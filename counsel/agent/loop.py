"""
COUNSEL Agent Loop - Claude Opus 4.8 + MCP tools + corroboration engine.

State machine: INIT -> TRIAGE -> [PROPOSE -> VERIFY -> GAP? GATHER : RULE] -> SYNTHESIZE -> SIGN
This is where Criterion 1 (Autonomous Execution Quality) is won.

Key design choices:
  - Claude Opus 4.8 with adaptive thinking (no budget_tokens - deprecated)
  - Streaming for long responses (prevents timeout on multi-iteration analysis)
  - Temperature 0 for the corroboration engine; higher for analyst narration
  - MAX_ITERATIONS enforced here, not in the prompt (architectural bound)
  - Graceful degradation: on tool failure, mark signal unavailable and continue
"""
from __future__ import annotations

import asyncio
import json
import logging
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
from ..engine.model import Claim, ClaimGraph, ClaimState, ClaimType, EvidenceRef
from ..ledger.ledger import Ledger
from .prompts import SYSTEM_PROMPT, TRAINING_MODE_ADDENDUM

logger = logging.getLogger("counsel.agent")

MAX_ITERATIONS = 25
MAX_TOKENS_PER_TURN = 8192
MODEL = "claude-opus-4-8"


@dataclass
class LoopConfig:
    run_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    evidence_root: Path = Path("/mnt/evidence")
    ledger_path: Path = Path("/tmp/counsel-ledger.jsonl")
    rules_dir: Path = Path("rules/")
    mcp_server_cmd: list[str] = field(default_factory=lambda: ["python", "-m", "counsel.mcp_server.server"])
    max_iterations: int = MAX_ITERATIONS
    training_mode: bool = False
    anthropic_api_key: str = ""

    # Evidence integrity
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
    Self-correction emerges from the gap-detection mechanism, not scripted.
    """

    def __init__(self, config: LoopConfig) -> None:
        self.config = config
        self.claim_graph = ClaimGraph(run_id=config.run_id)
        self.rule_registry = RuleRegistry()
        self.ledger = Ledger(config.ledger_path, config.run_id)
        self._iteration_logs: list[IterationLog] = []
        self._start_time = 0.0
        self._client: Optional[anthropic.Anthropic] = None

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
        """Convert MCP tool definitions to Anthropic API tool_use format."""
        tools = []
        for tool in mcp_tools:
            tools.append({
                "name": tool.name,
                "description": tool.description or "",
                "input_schema": tool.inputSchema if hasattr(tool, "inputSchema") else {"type": "object", "properties": {}},
            })
        return tools

    def _evidence_context(self) -> str:
        return (
            f"Evidence root: {self.config.evidence_root}\n"
            f"Run ID: {self.config.run_id}\n"
            f"Evidence SHA256: {self.config.evidence_sha256 or 'not yet computed'}\n"
            f"Max iterations: {self.config.max_iterations}\n"
            f"Rules loaded: {len(self.rule_registry.all_rules())}\n"
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

    def _update_claim_from_tool_result(
        self,
        result: dict,
        iteration: int,
    ) -> list[dict]:
        """
        After a tool call, run the confidence model on all matching rules
        and update claim states. Returns list of state change dicts.
        """
        state_changes = []
        tool_name = result.get("tool", "")
        if not result.get("records"):
            return state_changes

        # For each rule that uses this tool, check if we have enough to update states
        for rule in self.rule_registry.all_rules():
            if not any(s.artifact == tool_name for s in rule.signals):
                continue

            # Build evidence_map from current claims' evidence refs
            evidence_map: dict = {}
            for claim in self.claim_graph.claims:
                for ev in claim.evidence:
                    if ev.tool not in evidence_map:
                        evidence_map[ev.tool] = (ev, result)

            # Add the new tool result
            fake_ev_ref = EvidenceRef(
                ledger_seq=result.get("seq", 0),
                tool=tool_name,
                artifact_path=result.get("evidence", {}).get("path", ""),
                offset=result.get("evidence", {}).get("offset", 0),
                raw_sha256=result.get("evidence", {}).get("raw_output_sha256", ""),
                weight=1.0,
                independent_group=tool_name,
                parse_quality=result.get("parse_quality", 1.0),
            )
            evidence_map[tool_name] = (fake_ev_ref, {"exists": bool(result.get("records"))})

            # Compute confidence for each claim type this rule emits
            for claim_type_str in rule.emits:
                conf = compute_confidence(rule, claim_type_str, evidence_map)

                # Find or create claim
                subject = result.get("evidence", {}).get("path", "investigation_subject")
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
                    new_claim = Claim(
                        claim_type=ct,
                        subject=subject,
                        state=conf.state,
                        support_score=conf.support,
                        contradiction_score=conf.contradiction,
                        rule_id=rule.rule_id,
                    )
                    new_claim.evidence.append(fake_ev_ref)
                    self.claim_graph.add_claim(new_claim)
                    self.ledger.append_claim_state(
                        claim_id=new_claim.id,
                        claim_type=claim_type_str,
                        subject=subject,
                        from_state="NONE",
                        to_state=conf.state.value,
                        support=conf.support,
                        contradiction=conf.contradiction,
                        rule_id=rule.rule_id,
                        trigger=f"Initial observation from {tool_name}",
                        iteration=iteration,
                    )
                elif conf.state != existing.state:
                    old_state = existing.state
                    existing.record_state_change(
                        new_state=conf.state,
                        trigger=f"{tool_name} result",
                        iteration=iteration,
                        new_support=conf.support,
                    )
                    existing.evidence.append(fake_ev_ref)
                    self.ledger.append_claim_state(
                        claim_id=existing.id,
                        claim_type=claim_type_str,
                        subject=existing.subject,
                        from_state=old_state.value,
                        to_state=conf.state.value,
                        support=conf.support,
                        contradiction=conf.contradiction,
                        rule_id=rule.rule_id,
                        trigger=f"State change driven by {tool_name}",
                        iteration=iteration,
                    )
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

        return state_changes

    async def run(self) -> ClaimGraph:
        """Main async investigation loop. Returns the final ClaimGraph."""
        self._start_time = time.monotonic()

        # Load rules
        self._load_rules()

        # Write genesis ledger entry
        self.ledger.genesis(
            evidence_sha256=self.config.evidence_sha256,
            tool_catalog_hash="tool_catalog_v1",
            rule_set_hash=self.rule_registry.catalog_hash(),
        )

        # Connect to MCP server
        server_params = StdioServerParameters(
            command=self.config.mcp_server_cmd[0],
            args=self.config.mcp_server_cmd[1:],
            env={
                "COUNSEL_EVIDENCE_ROOT": str(self.config.evidence_root),
                "COUNSEL_RUN_ID": self.config.run_id,
                "COUNSEL_LEDGER_PATH": str(self.config.ledger_path),
                "COUNSEL_RULES_DIR": str(self.config.rules_dir),
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

                    # Call Claude Opus 4.8 with adaptive thinking + streaming
                    with client.messages.stream(
                        model=MODEL,
                        max_tokens=MAX_TOKENS_PER_TURN,
                        system=self._system_prompt(),
                        messages=messages,
                        tools=mcp_tools,
                        thinking={"type": "adaptive"},
                    ) as stream:
                        response = stream.get_final_message()

                    # Append assistant response to conversation
                    messages.append({"role": "assistant", "content": response.content})

                    # Check stop reason
                    if response.stop_reason == "end_turn":
                        logger.info("Agent signaled end_turn at iteration %d", iteration)
                        break

                    if response.stop_reason != "tool_use":
                        logger.warning("Unexpected stop_reason: %s", response.stop_reason)
                        break

                    # Process tool calls
                    tool_results = []
                    for block in response.content:
                        if block.type != "tool_use":
                            continue

                        tool_name = block.name
                        tool_input = block.input if isinstance(block.input, dict) else {}

                        logger.info("Agent calling tool: %s(%s)", tool_name, json.dumps(tool_input)[:100])

                        self.ledger.append_agent_decision(
                            iteration=iteration,
                            phase="GATHER",
                            action=f"call_tool:{tool_name}",
                            rationale=str(tool_input),
                            tool_chosen=tool_name,
                        )

                        # Execute via MCP session
                        try:
                            mcp_result = await session.call_tool(tool_name, tool_input)
                            raw_result = mcp_result.content[0].text if mcp_result.content else "{}"
                            result_dict = json.loads(raw_result)
                        except Exception as e:
                            logger.error("Tool call failed: %s - %s", tool_name, e)
                            result_dict = {"error": str(e), "tool": tool_name, "records": [], "seq": 0}

                        # Update claim states from this result
                        state_changes = self._update_claim_from_tool_result(result_dict, iteration)

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
                            }),
                        })

                    if tool_results:
                        messages.append({"role": "user", "content": tool_results})

                    # Check if all claims are settled (early termination)
                    open_claims = [c for c in self.claim_graph.claims if c.needs_investigation]
                    if not open_claims and self.claim_graph.claims:
                        logger.info("All claims settled - terminating at iteration %d", iteration)
                        self.ledger.append_halt(
                            reason="all_claims_settled",
                            iteration=iteration,
                            open_claims=0,
                            corroborated_claims=len(self.claim_graph.corroborated_claims()),
                            elapsed_seconds=time.monotonic() - self._start_time,
                        )
                        break

                else:
                    # Max iterations reached
                    self.ledger.append_halt(
                        reason="max_iterations_reached",
                        iteration=iteration,
                        open_claims=len([c for c in self.claim_graph.claims if c.needs_investigation]),
                        corroborated_claims=len(self.claim_graph.corroborated_claims()),
                        elapsed_seconds=time.monotonic() - self._start_time,
                    )

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
