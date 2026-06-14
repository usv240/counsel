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
MAX_TOKENS_PER_TURN = 16384
MODEL = "claude-haiku-4-5-20251001"

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


def _subject_candidates(tool: str, records: list[dict]) -> list[str]:
    """
    Extract human-readable identifiers (filenames, external IPs) from a tool's
    records, for use as Claim.subject. Without this, subject defaults to the
    fixture/evidence artifact path, which never matches answer_key subject_hint
    values like "wupd" or "185.220.101.47" - silently zeroing out precision/recall.
    """
    seen: list[str] = []

    def add(value: str) -> None:
        if value and value not in seen:
            seen.append(value)

    for r in records:
        for val in r.values():
            if not isinstance(val, str):
                continue
            for m in _SUBJECT_FILE_RE.findall(val):
                add(m)
        if tool in ("mem.netscan", "net.flows"):
            for addr_key in ("raddr", "daddr"):
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

    def _get_client(self) -> anthropic.Anthropic:
        if self._client is None:
            import os
            api_key = self.config.anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY", "")
            self._client = anthropic.Anthropic(api_key=api_key)
        return self._client

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
        subject = ", ".join(subject_candidates) or result.get("evidence", {}).get("path", "investigation_subject")

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

                    with client.messages.stream(
                        model=MODEL,
                        max_tokens=MAX_TOKENS_PER_TURN,
                        system=self._system_prompt(),
                        messages=messages,
                        tools=mcp_tools,
                        thinking={"type": "enabled", "budget_tokens": 10000},
                    ) as stream:
                        response = stream.get_final_message()

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
                                **result_dict,
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
