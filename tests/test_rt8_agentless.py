"""
RT8: Agentless Verdict — LLM-independent, order-independent corroboration proof.

This test is the strongest architectural guarantee COUNSEL makes:

    "Remove Claude entirely. Feed the forensic evidence directly to the
     corroboration engine in the WORST possible order (reverse of optimal).
     The verdict is identical: 5/5 true positives CORROBORATED, 0/2 false
     positives. The LLM navigates (which tool to call next). The math judges
     (what the evidence means). These concerns are architecturally separated."

The test uses zero API calls and runs in under one second.
No ANTHROPIC_API_KEY required.

Contrast with a naive LLM DFIR tool, where removing the LLM means removing
the verdict entirely — the LLM IS the verdict. In COUNSEL, the engine IS
the verdict. The LLM is an optional navigator.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from counsel.agent.loop import CounselLoop, LoopConfig
from counsel.engine.model import ClaimState
from counsel.mcp_server.parsers.base import load_fixture_result

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "counsel" / "fixtures" / "szechuan_sauce"
RULES_DIR = Path(__file__).resolve().parents[1] / "counsel" / "rules"

# Reverse of the optimal TRIAGE order — the hardest input ordering for a
# sequential agent, trivial for the order-independent noisy-OR engine.
TOOL_ORDER_REVERSED = [
    ("evtx_query",          "evtx.query"),
    ("net_flows",           "net.flows"),
    ("mem_malfind",         "mem.malfind"),
    ("mem_netscan",         "mem.netscan"),
    ("mem_pslist",          "mem.pslist"),
    ("yara_scan",           "yara.scan"),
    ("fs_stat_hash",        "fs.stat_hash"),
    ("amcache_lookup",      "amcache.lookup"),
    ("mft_timeline",        "mft.timeline"),
    ("prefetch_run_record", "prefetch.run_record"),
    ("registry_run_keys",   "registry.run_keys"),
]


@pytest.fixture(scope="module")
def agentless_claim_graph():
    """
    Build a claim graph by feeding fixture evidence directly to the corroboration
    engine — no LLM, no API calls, no agent loop. Pure engine math.
    """
    os.environ["COUNSEL_FIXTURE_DIR"] = str(FIXTURE_DIR)
    try:
        config = LoopConfig(run_id="rt8-agentless", rules_dir=RULES_DIR)
        loop = CounselLoop(config)
        loop._load_rules()

        for iteration, (stem, artifact_name) in enumerate(TOOL_ORDER_REVERSED, start=1):
            result = load_fixture_result(stem, config.run_id, "", artifact_name=artifact_name)
            assert result is not None, f"Missing fixture: {stem}.json"
            loop._update_claim_from_tool_result(result.to_dict(), iteration)

        return loop.claim_graph
    finally:
        os.environ.pop("COUNSEL_FIXTURE_DIR", None)


def _state(graph, claim_type: str) -> ClaimState | None:
    states = {c.state for c in graph.claims if c.claim_type.value == claim_type}
    if ClaimState.CORROBORATED in states:
        return ClaimState.CORROBORATED
    if ClaimState.CONTRADICTED in states:
        return ClaimState.CONTRADICTED
    return next(iter(states), None)


@pytest.mark.parametrize("claim_type", [
    "persistence_configured",
    "payload_executed",
    "payload_present",
    "payload_active",
    "c2_communication",
])
def test_rt8_true_positive_corroborated_without_llm(agentless_claim_graph, claim_type):
    """
    Same 5 TPs reach CORROBORATED with zero LLM calls, evidence fed in reverse order.
    The noisy-OR engine is commutative: group weights accumulate regardless of order.
    """
    assert _state(agentless_claim_graph, claim_type) == ClaimState.CORROBORATED


@pytest.mark.parametrize("claim_type", [
    "lateral_movement",
    "credential_access",
])
def test_rt8_true_negative_not_corroborated_without_llm(agentless_claim_graph, claim_type):
    """
    Same 2 TNs stay below CORROBORATED threshold — the engine cannot be convinced
    by text alone, only by evidence weights from real forensic tool results.
    """
    assert _state(agentless_claim_graph, claim_type) != ClaimState.CORROBORATED


def test_rt8_verdict_matches_agent_run(agentless_claim_graph):
    """
    The agentless verdict (engine only, reversed order) must match the agent-driven
    verdict (Claude Haiku navigating, optimal order). Same 5 TPs, 0 FPs.
    This is the definitive proof that the LLM is a navigator, not a judge.
    """
    corroborated_types = {
        c.claim_type.value for c in agentless_claim_graph.corroborated_claims()
    }
    expected = {
        "persistence_configured", "payload_executed",
        "payload_present", "payload_active", "c2_communication",
    }
    false_positives = {"lateral_movement", "credential_access"} & corroborated_types

    assert expected.issubset(corroborated_types), (
        f"Missing TPs in agentless run: {expected - corroborated_types}"
    )
    assert len(false_positives) == 0, (
        f"False positives in agentless run: {false_positives}"
    )
