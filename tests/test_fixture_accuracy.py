"""
End-to-end accuracy test against the 'Stolen Szechuan Sauce' fixture set -
no Anthropic API key required.

Feeds every fixture tool result through CounselLoop._update_claim_from_tool_result
(the same code path the live agent loop uses after each MCP tool call) in a
TRIAGE-first order, then checks the resulting claim graph against
counsel/fixtures/szechuan_sauce/answer_key.json via the bench harness.

This is the regression test for the evidence_map / rule-grouping / subject
fixes: it proves the engine reaches CORROBORATED on the 5 true positives and
withholds CORROBORATED on the 2 true negatives using real fixture data, with
no LLM involved.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from counsel.agent.loop import CounselLoop, LoopConfig
from counsel.bench.harness import AnswerKey, evaluate
from counsel.engine.model import ClaimState
from counsel.mcp_server.parsers.base import load_fixture_result

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "counsel" / "fixtures" / "szechuan_sauce"
RULES_DIR = Path(__file__).resolve().parents[1] / "counsel" / "rules"

# (fixture file stem, dotted artifact name) - TRIAGE tools first, matching
# the agent's prescribed investigation order, then the remaining tools.
TOOL_ORDER = [
    ("registry_run_keys", "registry.run_keys"),
    ("prefetch_run_record", "prefetch.run_record"),
    ("mft_timeline", "mft.timeline"),
    ("amcache_lookup", "amcache.lookup"),
    ("fs_stat_hash", "fs.stat_hash"),
    ("yara_scan", "yara.scan"),
    ("mem_pslist", "mem.pslist"),
    ("mem_netscan", "mem.netscan"),
    ("mem_malfind", "mem.malfind"),
    ("net_flows", "net.flows"),
    ("evtx_query", "evtx.query"),
]


@pytest.fixture(scope="module")
def claim_graph():
    os.environ["COUNSEL_FIXTURE_DIR"] = str(FIXTURE_DIR)
    try:
        config = LoopConfig(run_id="fixture-eval", rules_dir=RULES_DIR)
        loop = CounselLoop(config)
        loop._load_rules()

        for iteration, (fixture_stem, artifact_name) in enumerate(TOOL_ORDER, start=1):
            result = load_fixture_result(fixture_stem, config.run_id, "", artifact_name=artifact_name)
            assert result is not None, f"missing fixture: {fixture_stem}.json"
            loop._update_claim_from_tool_result(result.to_dict(), iteration)

        return loop.claim_graph
    finally:
        os.environ.pop("COUNSEL_FIXTURE_DIR", None)


def _claim_state(claim_graph, claim_type: str) -> ClaimState | None:
    states = {c.state for c in claim_graph.claims if c.claim_type.value == claim_type}
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
def test_true_positive_corroborated(claim_graph, claim_type):
    assert _claim_state(claim_graph, claim_type) == ClaimState.CORROBORATED


@pytest.mark.parametrize("claim_type", [
    "lateral_movement",
    "credential_access",
])
def test_true_negative_not_corroborated(claim_graph, claim_type):
    assert _claim_state(claim_graph, claim_type) != ClaimState.CORROBORATED


def test_c2_subject_matches_answer_key(claim_graph):
    c2_claims = [c for c in claim_graph.claims if c.claim_type.value == "c2_communication"]
    assert any("185.220.101.47" in c.subject for c in c2_claims)


def test_payload_subject_matches_answer_key(claim_graph):
    payload_claims = [c for c in claim_graph.claims if c.claim_type.value == "payload_executed"]
    assert any("wupd" in c.subject.lower() for c in payload_claims)


def test_accuracy_report(claim_graph):
    answer_key = AnswerKey.load(FIXTURE_DIR / "answer_key.json")
    metrics = evaluate(claim_graph, answer_key)
    # Recall: every true positive in the key should be matched by a CORROBORATED claim.
    assert metrics.recall == 1.0, metrics.to_dict()
    # Precision: every graded CORROBORATED claim should match a true positive.
    assert metrics.precision == 1.0, metrics.to_dict()
    # FPR: neither true negative should be hallucinated as CORROBORATED.
    assert metrics.fpr == 0.0, metrics.to_dict()
