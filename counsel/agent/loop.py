"""
COUNSEL Agent Loop - Claude Haiku 4.5 + MCP tools + corroboration engine.

State machine: INIT -> TRIAGE -> [PROPOSE -> VERIFY -> GAP? GATHER : RULE] -> SYNTHESIZE -> SIGN

Design notes:
  - Claude Haiku 4.5 with extended thinking (budget_tokens=10000)
  - Streaming for long responses (prevents timeout on multi-iteration analysis)
  - MAX_ITERATIONS enforced here (architectural bound, not prompt-based)
  - Graceful degradation: on tool failure, mark signal unavailable and continue
  - Ledger writes are NOT done here — MCP server subprocess writes tool_call entries;
    the Launcher writes genesis/claim_state/halt before and after this loop.
    Keeping a second Ledger instance here would corrupt the hash chain via
    duplicate seq numbers across the two independent in-memory counters.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import sys
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import anthropic
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ..engine.confidence import compute_confidence, prioritize_gaps
from ..engine.dsl import RuleRegistry
from ..engine.model import CLAIM_TYPE_ATTACK, Claim, ClaimGraph, ClaimState, ClaimType, EvidenceRef
from .prompts import SYSTEM_PROMPT, TRAINING_MODE_ADDENDUM

logger = logging.getLogger("counsel.agent")

MAX_ITERATIONS = 25
MAX_TOKENS_PER_TURN = 8192
MODEL = "claude-haiku-4-5-20251001"

# ─── Client-side rate limiting ──────────────────────────────────────────────
# The free / tier-1 Anthropic limit is 50,000 input tokens per minute. The agent
# conversation grows every iteration (each tool result is re-sent), so by iter ~7
# three requests in a 60s window breach the cap and the run 429s. We avoid this
# proactively (not just via SDK retry/backoff) with two levers:
#   1. INPUT_TPM_BUDGET: pace requests so the rolling 60s input-token sum stays
#      under this budget (headroom below 50K for the upcoming request's growth).
#   2. MAX_RECORDS_IN_CONTEXT: cap how many raw records each tool result re-sends
#      to the model. The engine already computed claims from the FULL record set
#      and the ledger retains all records, so this only bounds the agent's working
#      context — never the forensic result.
INPUT_TPM_BUDGET = 38000
MAX_RECORDS_IN_CONTEXT = 10
# Extra SDK-level retries as a second line of defense if pacing still grazes the cap.
CLIENT_MAX_RETRIES = 6

# How many times to nudge the agent to keep investigating if it tries to
# end_turn while open_gaps is non-empty. Bounded so a model that ignores
# the nudge entirely can't loop forever (MAX_ITERATIONS still applies too).
MAX_END_TURN_NUDGES = 3

# Known credential-dumping tool executables (SANS FOR508 / MITRE ATT&CK T1003 toolset).
_CRED_DUMP_TOOLS = {
    "mimikatz.exe", "procdump.exe", "procdump64.exe", "pwdump.exe",
    "pwdump7.exe", "gsecdump.exe", "wce.exe", "fgdump.exe",
    "secretsdump.exe", "lazagne.exe", "nanodump.exe",
}

# Path fragments indicating access to a credential-bearing registry hive or AD database.
_HIVE_PATH_MARKERS = ("\\config\\sam", "\\config\\system", "\\config\\security", "ntds.dit")

# Object names whose access indicates credential-store inspection (MITRE T1003).
_CRED_OBJECT_MARKERS = ("lsass", "\\sam", "\\security", "\\system32\\config", "ntds.dit")

# RFC1918 + loopback - mirrors the local-net filter in mcp_server/tools/{memory,network}.py.
_LOCAL_NETS = re.compile(
    r"^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|::1|fe80:)"
)

# Filenames embedded in path/value_data/executable fields - used to build a
# human-readable Claim.subject (e.g. "wupd.exe") that the benchmark harness
# can match against answer_key subject_hint strings.
_SUBJECT_FILE_RE = re.compile(
    r"([\w.\-]+\.(?:exe|dll|sys|bat|cmd|ps1|vbs|scr|docx?|xlsx?|pdf|zip|rar|7z))",
    re.IGNORECASE,
)

# Legitimate Windows system processes that constantly appear as ParentProcessName/
# ProcessName in EVTX records. They are pure noise as a Claim.subject. Matched on
# EXACT basename (case-insensitive) so the malware "svchost32.exe" is NOT excluded
# by the legitimate "svchost.exe".
_SYSTEM_PROCESS_DENYLIST = frozenset({
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsm.exe", "svchost.exe", "explorer.exe", "taskhost.exe", "taskhostw.exe",
    "dwm.exe", "spoolsv.exe", "searchindexer.exe", "system",
})


def _subject_candidates(tool: str, records: list[dict]) -> list[str]:
    """
    Extract human-readable identifiers (filenames, external IPs) from a tool's
    records, for use as Claim.subject. Without this, subject defaults to the
    fixture/evidence artifact path, which never matches answer_key subject_hint
    values like "wupd" or "185.220.101.47" - silently zeroing out precision/recall.

    Legitimate system processes are filtered out and matching is case-insensitive
    so the subject reads as a clean list of suspicious artifacts (malware binaries,
    external C2 IPs) rather than a soup of every executable mentioned in the logs.
    """
    seen: list[str] = []
    seen_lower: set[str] = set()
    _exec_exts = (".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".scr")

    def add(value: str) -> None:
        if not value:
            return
        low = value.lower()
        if low in _SYSTEM_PROCESS_DENYLIST or low in seen_lower:
            return
        # Windows binary names are case-insensitive; normalize executables to
        # lowercase so "WUPD.EXE" and "wupd.exe" never render as two casings.
        # Document/archive names keep their original case (it carries meaning).
        display = low if low.endswith(_exec_exts) else value
        seen.append(display)
        seen_lower.add(low)

    for r in records:
        for val in r.values():
            if isinstance(val, dict):
                for v in val.values():
                    if isinstance(v, str):
                        for m in _SUBJECT_FILE_RE.findall(v):
                            add(m)
            elif isinstance(val, str):
                for m in _SUBJECT_FILE_RE.findall(val):
                    add(m)
        if tool in ("mem.netscan", "net.flows"):
            for addr_key in ("raddr", "daddr", "dst"):  # net.flows uses 'dst'
                addr = str(r.get(addr_key, ""))
                if addr and not _LOCAL_NETS.match(addr):
                    add(addr)

    return seen[:8]


def _merge_subject(existing_subject: str, new_candidates: list[str]) -> str:
    """Append newly-discovered subject candidates to a claim's existing subject."""
    if not new_candidates:
        return existing_subject
    current = [s.strip() for s in existing_subject.split(",") if s.strip()]
    lowered = {s.lower() for s in current}
    for cand in new_candidates:
        if cand.lower() not in lowered:
            current.append(cand)
            lowered.add(cand.lower())
    return ", ".join(current[:8])


def _build_predicate_record(tool: str, records: list[dict]) -> dict:
    """
    Collapse a tool's record list into one dict for `evaluate_predicate`.

    Multi-record artifacts merge boolean fields with existential-OR (True if ANY
    record has the field set) - correct for "is there at least one external/linked/
    signed record" style requires: predicates used throughout counsel/rules/*.yaml.
    Single-record artifacts (e.g. fs.stat_hash) pass their fields through directly.

    Also computes derived indicators (credential-dumping tooling, LSASS/SAM object
    access, log clearing, external memory connections) that the simple field==value
    DSL cannot express on its own, since they require scanning across all records.
    """
    merged: dict = {"record_count": len(records)}

    if not records:
        merged["exists"] = False
        return merged

    if len(records) == 1:
        merged.update(records[0])
        merged.setdefault("exists", True)
    else:
        merged["exists"] = True
        all_keys: set[str] = set()
        for r in records:
            all_keys.update(r.keys())
        for key in all_keys:
            values = [r.get(key) for r in records if key in r]
            if any(v is True for v in values):
                merged[key] = True
            elif all(v is False for v in values):
                merged[key] = False
            else:
                merged[key] = values[0]

    if tool == "evtx.query":
        merged["log_cleared"] = any(r.get("eid") == 1102 for r in records)
        merged["lsass_or_hive_access"] = any(
            r.get("eid") in (4663, 4656)
            and any(m in str(r.get("fields", {}).get("ObjectName", "")).lower() for m in _CRED_OBJECT_MARKERS)
            for r in records
        )
    elif tool == "mem.malfind":
        merged["lsass_injection"] = any(str(r.get("name", "")).lower() == "lsass.exe" for r in records)
    elif tool == "prefetch.run_record":
        merged["cred_dump_tool"] = any(str(r.get("executable", "")).lower() in _CRED_DUMP_TOOLS for r in records)
    elif tool == "mem.pslist":
        merged["cred_dump_tool"] = any(str(r.get("name", "")).lower() in _CRED_DUMP_TOOLS for r in records)
    elif tool == "fs.stat_hash":
        path = str(merged.get("path", "")).lower()
        merged["cred_dump_artifact"] = bool(merged.get("exists")) and any(
            m in path for m in _HIVE_PATH_MARKERS + ("lsass.dmp",)
        )
    elif tool == "mft.timeline":
        merged["hive_file_referenced"] = any(
            any(m in str(r.get("path", "")).lower() for m in _HIVE_PATH_MARKERS)
            for r in records
        )
    elif tool == "registry.run_keys":
        markers = ("\\sam", "lsa\\secrets", "\\security")
        fields_to_check = ("key", "value_name", "value_data")
        merged["sam_related_key"] = any(
            m in str(r.get(f, "")).lower()
            for r in records
            for f in fields_to_check
            for m in markers
        )
    elif tool == "mem.netscan":
        merged["is_external"] = any(
            not _LOCAL_NETS.match(str(r.get("raddr", "")))
            for r in records if r.get("raddr")
        )

    return merged


@dataclass
class LoopConfig:
    run_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    evidence_root: Path = Path("/mnt/evidence")
    ledger_path: Path = Path("/tmp/counsel-ledger.jsonl")
    rules_dir: Path = Path("rules/")
    mcp_server_cmd: list[str] = field(default_factory=lambda: [sys.executable, "-m", "counsel.mcp_server.server"])
    max_iterations: int = MAX_ITERATIONS
    training_mode: bool = False
    anthropic_api_key: str = ""
    evidence_sha256: str = ""


@dataclass
class IterationLog:
    iteration: int
    phase: str
    action: str
    rationale: str
    tool_called: Optional[str]
    claim_state_changes: list[dict]
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class CounselLoop:
    """
    The main COUNSEL investigation loop.

    The agent drives tool selection; the corroboration engine drives state.
    Self-correction emerges from the gap-detection mechanism: after every tool
    call, open_gaps lists the highest-weight unchecked signals still needed to
    reach CORROBORATED, ordered by weight. The agent reads these and chooses
    the next tool accordingly — this is architectural self-correction, not scripted.
    """

    def __init__(self, config: LoopConfig) -> None:
        self.config = config
        self.claim_graph = ClaimGraph(run_id=config.run_id)
        self.rule_registry = RuleRegistry()
        self._iteration_logs: list[IterationLog] = []
        self._start_time = 0.0
        self._last_iteration = 0
        self._client: Optional[anthropic.Anthropic] = None
        # artifact (dotted tool name) -> (EvidenceRef, predicate record), accumulated
        # across the whole run. This is the evidence_map passed to compute_confidence.
        self._artifact_records: dict[str, tuple[EvidenceRef, dict]] = {}
        self._end_turn_nudges = 0
        # Thinking blocks collected during the run; written to ledger by Launcher post-run
        # to avoid hash-chain corruption from a concurrent Ledger instance.
        self._thinking_records: list[dict] = []
        # Set when the loop terminates abnormally (e.g. API rate limit exhausted).
        # The Launcher surfaces this as the halt reason so a degraded run still
        # produces a signed ledger + case file instead of crashing.
        self._halt_reason: Optional[str] = None
        # Rolling window of (monotonic_ts, input_tokens) for client-side pacing.
        self._token_window: deque[tuple[float, int]] = deque()
        self._last_input_tokens = 0

    def _get_client(self) -> anthropic.Anthropic:
        if self._client is None:
            import os
            api_key = self.config.anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY", "")
            self._client = anthropic.Anthropic(api_key=api_key, max_retries=CLIENT_MAX_RETRIES)
        return self._client

    async def _pace_for_token_budget(self, est_tokens: int) -> None:
        """
        Sleep until sending a request of ~est_tokens input tokens keeps the rolling
        60-second input-token total under INPUT_TPM_BUDGET. This keeps us below the
        organisation's tokens-per-minute limit by design, so the run completes
        instead of relying on 429 backoff. No effect on what the agent sees.
        """
        while True:
            now = time.monotonic()
            while self._token_window and now - self._token_window[0][0] > 60.0:
                self._token_window.popleft()
            used = sum(t for _, t in self._token_window)
            if not self._token_window or used + est_tokens <= INPUT_TPM_BUDGET:
                return
            sleep_for = 60.0 - (now - self._token_window[0][0]) + 0.5
            logger.info(
                "Rate-limit pacing: %d input tok in last 60s + est %d > budget %d - sleeping %.1fs",
                used, est_tokens, INPUT_TPM_BUDGET, sleep_for,
            )
            await asyncio.sleep(max(sleep_for, 1.0))

    def _record_token_usage(self, response) -> None:
        """Record a completed request's input-token cost for the pacing window."""
        usage = getattr(response, "usage", None)
        n = getattr(usage, "input_tokens", 0) or 0
        if n:
            self._token_window.append((time.monotonic(), n))
            self._last_input_tokens = n

    def _compact_result_for_context(self, result_dict: dict) -> dict:
        """
        Cap the raw records re-sent to the model so the conversation stops growing
        without bound. The engine has already consumed the FULL result to update
        claims, and the signed ledger retains every record — this trims only the
        agent's working context, never the forensic record.
        """
        records = result_dict.get("records")
        if not isinstance(records, list) or len(records) <= MAX_RECORDS_IN_CONTEXT:
            return result_dict
        compact = dict(result_dict)
        compact["records"] = records[:MAX_RECORDS_IN_CONTEXT]
        compact["records_truncated"] = {
            "shown": MAX_RECORDS_IN_CONTEXT,
            "total": len(records),
            "note": "Full records are in the signed ledger; claims already computed from all records.",
        }
        return compact

    def _load_rules(self) -> None:
        loaded = self.rule_registry.load_directory(self.config.rules_dir)
        logger.info("Loaded %d corroboration rules", len(loaded))

    def _system_prompt(self) -> str:
        base = SYSTEM_PROMPT
        if self.config.training_mode:
            base += "\n" + TRAINING_MODE_ADDENDUM
        return base

    def _build_mcp_tools_for_api(self, mcp_tools: list) -> list[dict]:
        tools = []
        for tool in mcp_tools:
            tools.append({
                "name": tool.name,
                "description": tool.description or "",
                "input_schema": tool.inputSchema if hasattr(tool, "inputSchema") else {"type": "object", "properties": {}},
            })
        return tools

    def _evidence_context(self) -> str:
        mem_img = os.environ.get("COUNSEL_MEMORY_IMAGE", "")
        mem_line = f"Memory image: {mem_img}\n" if mem_img else ""
        return (
            f"Evidence root: {self.config.evidence_root}\n"
            f"Run ID: {self.config.run_id}\n"
            f"Evidence SHA256: {self.config.evidence_sha256 or 'not yet computed'}\n"
            f"Max iterations: {self.config.max_iterations}\n"
            f"Rules loaded: {len(self.rule_registry.all_rules())}\n"
            f"{mem_line}"
        )

    def _claims_summary(self) -> str:
        if not self.claim_graph.claims:
            return "No claims yet."
        lines = []
        for c in self.claim_graph.claims:
            lines.append(
                f"  [{c.id}] {c.claim_type.value} - {c.subject} "
                f"STATE={c.state.value} support={c.support_score:.2f}"
            )
        return "\n".join(lines)

    def _collect_all_gaps(self) -> list[dict]:
        """
        Collect high-value unchecked signals across all open (OBSERVED/INFERENCE) claims.
        Returned to the agent as open_gaps in every tool result — this is what drives
        gap-detection self-correction: agent sees "amcache_lookup weight=0.65 needed for
        payload_executed (currently INFERENCE)" and knows which tool to call next.
        """
        seen: dict[str, dict] = {}

        for claim in self.claim_graph.claims:
            if not claim.needs_investigation:
                continue

            rule = self.rule_registry.get(claim.rule_id)
            if rule is None:
                continue

            conf = compute_confidence(rule, claim.claim_type.value, self._artifact_records)
            for gap in prioritize_gaps(conf):
                tool = gap.signal.artifact
                if tool not in seen or seen[tool]["weight"] < gap.signal.weight:
                    seen[tool] = {
                        "tool": tool,
                        "weight": round(gap.signal.weight, 2),
                        "for_claim": claim.claim_type.value,
                        "claim_state": claim.state.value,
                        "note": (
                            f"Unchecked independent signal — calling this tool moves "
                            f"{claim.claim_type.value} from {claim.state.value} toward CORROBORATED"
                        ),
                    }

        return sorted(seen.values(), key=lambda g: g["weight"], reverse=True)[:6]

    def _update_claim_from_tool_result(
        self,
        result: dict,
        iteration: int,
    ) -> list[dict]:
        """
        After a tool call, refresh the persistent evidence_map (self._artifact_records)
        with this artifact's real record data, then re-run the confidence model on
        every rule that has this artifact as a signal and update claim states.
        Returns list of state change dicts. State transitions are recorded in
        claim.history (not the ledger — the Launcher writes claim_state ledger
        entries post-run from claim.history).
        """
        state_changes = []
        tool_name = result.get("tool", "")
        if not tool_name or result.get("error"):
            return state_changes

        records = result.get("records") or []
        predicate_record = _build_predicate_record(tool_name, records)
        ev_ref = EvidenceRef(
            ledger_seq=result.get("seq", 0),
            tool=tool_name,
            artifact_path=result.get("evidence", {}).get("path", ""),
            offset=result.get("evidence", {}).get("offset", 0),
            raw_sha256=result.get("evidence", {}).get("raw_output_sha256", ""),
            weight=1.0,
            independent_group=tool_name,
            parse_quality=result.get("parse_quality", 1.0),
        )
        self._artifact_records[tool_name] = (ev_ref, predicate_record)

        subject_candidates = _subject_candidates(tool_name, records)
        _artifact_path = result.get("evidence", {}).get("path", "")
        subject = ", ".join(subject_candidates) or (Path(_artifact_path).stem if _artifact_path else "investigation_subject")

        for rule in self.rule_registry.all_rules():
            if not any(s.artifact == tool_name for s in rule.signals):
                continue

            for claim_type_str in rule.emits:
                conf = compute_confidence(rule, claim_type_str, self._artifact_records)

                existing = next(
                    (c for c in self.claim_graph.claims
                     if c.rule_id == rule.rule_id and c.claim_type.value == claim_type_str),
                    None,
                )

                if existing is None:
                    try:
                        ct = ClaimType(claim_type_str)
                    except ValueError:
                        continue
                    attack_technique, attack_tactic = CLAIM_TYPE_ATTACK.get(ct, (None, ""))
                    new_claim = Claim(
                        claim_type=ct,
                        subject=subject,
                        state=conf.state,
                        support_score=conf.support,
                        contradiction_score=conf.contradiction,
                        rule_id=rule.rule_id,
                        attack_technique=attack_technique,
                        attack_tactic=attack_tactic,
                    )
                    for sr in conf.active_signals:
                        if sr.evidence_ref:
                            new_claim.evidence.append(sr.evidence_ref)
                    self.claim_graph.add_claim(new_claim)
                    continue

                for sr in conf.active_signals:
                    if sr.evidence_ref and sr.evidence_ref not in existing.evidence:
                        existing.evidence.append(sr.evidence_ref)

                existing.subject = _merge_subject(existing.subject, subject_candidates)

                if conf.state != existing.state:
                    old_state = existing.state
                    existing.record_state_change(
                        new_state=conf.state,
                        trigger=f"{tool_name} result",
                        iteration=iteration,
                        new_support=conf.support,
                    )
                    existing.contradiction_score = conf.contradiction
                    state_changes.append({
                        "claim_id": existing.id,
                        "from": old_state.value,
                        "to": conf.state.value,
                        "trigger": tool_name,
                    })
                    logger.info(
                        "RULING CHANGE: %s [%s] %s -> %s (support=%.2f)",
                        claim_type_str, existing.id, old_state.value, conf.state.value, conf.support,
                    )
                elif (abs(conf.support - existing.support_score) > 1e-9
                      or abs(conf.contradiction - existing.contradiction_score) > 1e-9):
                    existing.support_score = conf.support
                    existing.contradiction_score = conf.contradiction
                    existing.last_updated = datetime.now(timezone.utc)

        return state_changes

    async def run(self) -> ClaimGraph:
        """Main async investigation loop. Returns the final ClaimGraph."""
        self._start_time = time.monotonic()

        self._load_rules()

        server_params = StdioServerParameters(
            command=self.config.mcp_server_cmd[0],
            args=self.config.mcp_server_cmd[1:],
            env={
                **os.environ,  # inherit PATH, PYTHONPATH, Anaconda paths, etc.
                "COUNSEL_EVIDENCE_ROOT": str(self.config.evidence_root.resolve()),
                "COUNSEL_RUN_ID": self.config.run_id,
                "COUNSEL_LEDGER_PATH": str(self.config.ledger_path.resolve()),
                "COUNSEL_RULES_DIR": str(self.config.rules_dir.resolve()),
            },
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                mcp_tools_raw = await session.list_tools()
                mcp_tools = self._build_mcp_tools_for_api(mcp_tools_raw.tools)

                logger.info(
                    "COUNSEL starting - run_id=%s tools=%d rules=%d",
                    self.config.run_id, len(mcp_tools), len(self.rule_registry.all_rules()),
                )

                messages: list[dict] = [
                    {
                        "role": "user",
                        "content": (
                            f"Begin investigation.\n\n"
                            f"{self._evidence_context()}\n"
                            f"Run your TRIAGE phase and report initial hypotheses."
                        ),
                    }
                ]

                client = self._get_client()
                iteration = 0

                while iteration < self.config.max_iterations:
                    iteration += 1
                    logger.info("=== ITERATION %d ===", iteration)
                    if iteration > 1:
                        await asyncio.sleep(2)

                    # Triage (iter 1) needs full reasoning; gap-fill iterations
                    # just pick the next highest-weight tool — minimal budget.
                    thinking_budget = 5000 if iteration == 1 else 1024
                    # Proactively pace so the rolling 60s input-token total stays
                    # under the org's per-minute limit (avoids 429 by design).
                    await self._pace_for_token_budget(self._last_input_tokens)
                    try:
                        with client.messages.stream(
                            model=MODEL,
                            max_tokens=MAX_TOKENS_PER_TURN,
                            system=self._system_prompt(),
                            messages=messages,
                            tools=mcp_tools,
                            thinking={"type": "enabled", "budget_tokens": thinking_budget},
                        ) as stream:
                            response = stream.get_final_message()
                        self._record_token_usage(response)
                    except anthropic.APIStatusError as e:
                        # The SDK already retried with backoff and still failed (most
                        # commonly a 429 rate-limit once the conversation grows). Rather
                        # than crash and lose the entire case, halt gracefully: every
                        # claim resolved so far is preserved and the Launcher still
                        # writes a signed ledger + HTML case file. A partial,
                        # evidence-backed verdict beats no verdict.
                        iteration -= 1  # this iteration did not complete
                        self._halt_reason = (
                            "rate_limit_halt" if isinstance(e, anthropic.RateLimitError)
                            else "api_error_halt"
                        )
                        logger.warning(
                            "API call failed at iteration %d (%s: %s) - halting gracefully "
                            "with %d claims resolved so far",
                            iteration + 1, type(e).__name__, e,
                            len(self.claim_graph.claims),
                        )
                        break

                    # Extract extended-thinking blocks and store for ledger (written post-run
                    # by Launcher to avoid dual-process hash chain corruption).
                    next_tool = next(
                        (b.name for b in response.content if getattr(b, "type", "") == "tool_use"),
                        None,
                    )
                    next_tool_use_id = next(
                        (b.id for b in response.content if getattr(b, "type", "") == "tool_use"),
                        None,
                    )
                    for block in response.content:
                        if getattr(block, "type", "") == "thinking":
                            text = getattr(block, "thinking", "") or ""
                            sha = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
                            self._thinking_records.append({
                                "iteration": iteration,
                                "thinking_sha256": sha,
                                "thinking_len": len(text),
                                "tool_use_id": next_tool_use_id,
                                "next_tool": next_tool,
                            })
                            logger.debug(
                                "Thinking block logged iter=%d sha=%s…  len=%d next_tool=%s",
                                iteration, sha[:16], len(text), next_tool,
                            )

                    messages.append({"role": "assistant", "content": response.content})

                    if response.stop_reason == "end_turn":
                        gaps = self._collect_all_gaps()
                        if gaps and self._end_turn_nudges < MAX_END_TURN_NUDGES:
                            self._end_turn_nudges += 1
                            logger.info(
                                "Agent signaled end_turn at iteration %d but %d open_gaps remain "
                                "- nudging to continue (%d/%d)",
                                iteration, len(gaps), self._end_turn_nudges, MAX_END_TURN_NUDGES,
                            )
                            messages.append({
                                "role": "user",
                                "content": (
                                    "You ended your turn, but open_gaps is non-empty:\n"
                                    f"{json.dumps(gaps)}\n\n"
                                    "Per the investigation loop, call the highest-weight gap tool "
                                    "now. If a gap is moot (its claim already reached CORROBORATED "
                                    "or CONTRADICTED via another independent signal), say so "
                                    "explicitly and move to the next gap. Only produce your final "
                                    "COUNSEL VERDICT once open_gaps is empty or every remaining "
                                    "gap has been explained as moot."
                                ),
                            })
                            continue
                        logger.info("Agent signaled end_turn at iteration %d", iteration)
                        break

                    if response.stop_reason != "tool_use":
                        logger.warning("Unexpected stop_reason: %s", response.stop_reason)
                        break

                    tool_results = []
                    for block in response.content:
                        if block.type != "tool_use":
                            continue

                        tool_name = block.name
                        tool_input = block.input if isinstance(block.input, dict) else {}

                        logger.info("Agent calling tool: %s(%s)", tool_name, json.dumps(tool_input)[:100])

                        try:
                            mcp_result = await session.call_tool(tool_name, tool_input)
                            raw_result = mcp_result.content[0].text if mcp_result.content else "{}"
                            result_dict = json.loads(raw_result)
                        except Exception as e:
                            logger.error("Tool call failed: %s - %s", tool_name, e)
                            result_dict = {"error": str(e), "tool": tool_name, "records": [], "seq": 0}

                        state_changes = self._update_claim_from_tool_result(result_dict, iteration)
                        open_gaps = self._collect_all_gaps()

                        self._iteration_logs.append(IterationLog(
                            iteration=iteration,
                            phase="GATHER",
                            action=f"tool:{tool_name}",
                            rationale=str(tool_input),
                            tool_called=tool_name,
                            claim_state_changes=state_changes,
                        ))

                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": json.dumps({
                                **self._compact_result_for_context(result_dict),
                                "claim_state_changes": state_changes,
                                "current_claims": self._claims_summary(),
                                "open_gaps": open_gaps,
                            }),
                        })

                    if tool_results:
                        messages.append({"role": "user", "content": tool_results})

                    open_claims = [c for c in self.claim_graph.claims if c.needs_investigation]
                    if not open_claims and self.claim_graph.claims:
                        logger.info("All claims settled - terminating at iteration %d", iteration)
                        break

        self._last_iteration = iteration
        elapsed = time.monotonic() - self._start_time
        logger.info(
            "COUNSEL complete - elapsed=%.1fs iterations=%d corroborated=%d unresolved=%d",
            elapsed,
            iteration,
            len(self.claim_graph.corroborated_claims()),
            len(self.claim_graph.unresolved_claims()),
        )

        return self.claim_graph


def run_investigation(config: LoopConfig) -> ClaimGraph:
    """Synchronous entry point for the launcher."""
    loop = CounselLoop(config)
    return asyncio.run(loop.run())
