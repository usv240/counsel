"""
No-API demo runner tests (D1-D3).

The `counsel demo` command is the judge's zero-friction entry point: it must
produce the same corroboration verdict as the agent, with a valid signed ledger
and a case file, using no ANTHROPIC_API_KEY. These tests guard that path.
"""
from __future__ import annotations

from counsel.launcher.demo import run_demo


def test_d1_demo_verdict_matches_benchmark(tmp_path):
    """The no-API demo reproduces the documented Szechuan Sauce verdict."""
    result = run_demo("szechuan_sauce", tmp_path)
    corroborated = {c.claim_type.value for c in result["corroborated"]}
    withheld = {c.claim_type.value for c in result["withheld"]}

    # The 5 graded true positives must all be corroborated.
    for tp in ("persistence_configured", "payload_executed", "payload_present",
               "payload_active", "c2_communication"):
        assert tp in corroborated, f"{tp} should be CORROBORATED, got {corroborated}"

    # The 2 true negatives must be withheld (never corroborated).
    assert "lateral_movement" not in corroborated
    assert "credential_access" not in corroborated
    assert "lateral_movement" in withheld
    assert "credential_access" in withheld


def test_d2_demo_ledger_chain_valid(tmp_path):
    """The demo writes a hash-chained ledger that verifies, and a case file."""
    result = run_demo("szechuan_sauce", tmp_path)
    assert result["chain_valid"] is True
    assert result["report_path"].exists()
    assert result["ledger_path"].exists()
    assert result["tool_calls"] >= 10  # all artifact families replayed


def test_d3_demo_runs_adversarial_case(tmp_path):
    """The same runner generalizes to the adversarial-injection case and still
    withholds credential_access (architectural, not lexical, guardrail)."""
    result = run_demo("adversarial_injection", tmp_path)
    corroborated = {c.claim_type.value for c in result["corroborated"]}
    assert "credential_access" not in corroborated, (
        f"injection text must not force credential_access CORROBORATED, got {corroborated}"
    )
    assert result["chain_valid"] is True
