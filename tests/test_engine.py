"""
Unit tests for the corroboration engine - no forensic tools required.
Tests the DSL compiler, confidence model, and state resolution logic.
"""
import pytest
from pathlib import Path

from counsel.engine.dsl import RuleRegistry, DSLCompileError, compile_rule, evaluate_predicate
from counsel.engine.model import ClaimState, ClaimType, Claim, EvidenceRef
from counsel.engine.confidence import compute_confidence, TAU_CORROBORATED


# ─── DSL compiler tests ──────────────────────────────────────────────────────

def test_compile_valid_rule():
    raw = {
        "rule": "test_rule",
        "emits": ["persistence_configured"],
        "signals": [
            {"artifact": "registry.run_keys", "supports": "persistence_configured", "weight": 0.9},
            {"artifact": "prefetch.run_record", "supports": "persistence_configured", "weight": 0.8,
             "independent_of": "registry.run_keys"},
        ],
        "provenance": "Test provenance",
    }
    rule = compile_rule(raw)
    assert rule.rule_id == "test_rule"
    assert "persistence_configured" in rule.emits
    assert len(rule.signals) == 2


def test_compile_missing_provenance():
    raw = {
        "rule": "bad_rule",
        "emits": ["persistence_configured"],
        "signals": [
            {"artifact": "registry.run_keys", "supports": "persistence_configured", "weight": 0.9}
        ],
    }
    with pytest.raises(DSLCompileError, match="provenance"):
        compile_rule(raw)


def test_compile_unknown_tool():
    raw = {
        "rule": "bad_rule",
        "emits": ["persistence_configured"],
        "signals": [
            {"artifact": "execute_shell", "supports": "persistence_configured", "weight": 0.9}
        ],
        "provenance": "Test",
    }
    with pytest.raises(DSLCompileError, match="unknown tool"):
        compile_rule(raw)


def test_compile_weight_out_of_range():
    raw = {
        "rule": "bad_rule",
        "emits": ["persistence_configured"],
        "signals": [
            {"artifact": "registry.run_keys", "supports": "persistence_configured", "weight": 1.5}
        ],
        "provenance": "Test",
    }
    with pytest.raises(DSLCompileError, match="weight"):
        compile_rule(raw)


def test_load_rules_directory(tmp_path):
    import yaml
    rule = {
        "rule": "dir_test_rule",
        "emits": ["payload_executed"],
        "signals": [
            {"artifact": "prefetch.run_record", "supports": "payload_executed", "weight": 0.9},
        ],
        "provenance": "Test",
    }
    (tmp_path / "test_rule.yaml").write_text(yaml.dump(rule))
    registry = RuleRegistry()
    loaded = registry.load_directory(tmp_path)
    assert "dir_test_rule" in loaded


# ─── Predicate evaluator tests ───────────────────────────────────────────────

def test_predicate_exists_true():
    assert evaluate_predicate("exists == true", {"exists": True}) is True
    assert evaluate_predicate("exists == true", {"exists": False}) is False

def test_predicate_exists_false():
    assert evaluate_predicate("exists == false", {"exists": False}) is True

def test_predicate_is_external():
    assert evaluate_predicate("is_external == true", {"is_external": True}) is True

def test_predicate_missing_field():
    assert evaluate_predicate("nonexistent == true", {"exists": True}) is False

def test_predicate_empty_is_true():
    assert evaluate_predicate("", {"any": "field"}) is True

def test_predicate_none_is_true():
    assert evaluate_predicate(None, {}) is True


# ─── Confidence model tests ──────────────────────────────────────────────────

def _make_rule():
    raw = {
        "rule": "conf_test",
        "emits": ["persistence_configured"],
        "signals": [
            {"artifact": "registry.run_keys", "supports": "persistence_configured", "weight": 0.95,
             "independent_of": "registry_sources"},
            {"artifact": "prefetch.run_record", "supports": "persistence_configured", "weight": 0.90,
             "independent_of": "execution_sources"},  # different group = genuinely independent
        ],
        "provenance": "Test",
    }
    return compile_rule(raw)


def _make_ev(tool: str, quality: float = 1.0) -> EvidenceRef:
    return EvidenceRef(
        ledger_seq=0, tool=tool, artifact_path="/test", offset=0,
        raw_sha256="abc", weight=0.9, independent_group=tool, parse_quality=quality,
    )


def test_no_evidence_is_observed():
    rule = _make_rule()
    result = compute_confidence(rule, "persistence_configured", {})
    assert result.state == ClaimState.OBSERVED
    assert result.support == 0.0
    assert len(result.gap_signals) == 2


def test_one_signal_is_inference():
    rule = _make_rule()
    ev_ref = _make_ev("registry.run_keys")
    evidence_map = {"registry.run_keys": (ev_ref, {"exists": True})}
    result = compute_confidence(rule, "persistence_configured", evidence_map)
    # One independent group active: state is INFERENCE regardless of support score,
    # because MIN_INDEPENDENT_GROUPS=2 is not yet satisfied.
    assert result.state == ClaimState.INFERENCE
    assert result.support > 0
    assert result.independent_groups_active == 1


def test_two_independent_signals_corroborated():
    rule = _make_rule()
    ev1 = _make_ev("registry.run_keys")
    ev2 = _make_ev("prefetch.run_record")
    evidence_map = {
        "registry.run_keys": (ev1, {}),
        "prefetch.run_record": (ev2, {}),
    }
    result = compute_confidence(rule, "persistence_configured", evidence_map)
    assert result.state == ClaimState.CORROBORATED
    assert result.support >= TAU_CORROBORATED
    assert result.independent_groups_active >= 2


def test_contradiction_overrides_support():
    raw = {
        "rule": "contra_test",
        "emits": ["payload_present"],
        "signals": [
            {"artifact": "registry.run_keys", "supports": "payload_present", "weight": 0.95},
        ],
        "contradictions": [
            {"artifact": "fs.stat_hash", "weight": 0.80, "requires": "exists == false"},
        ],
        "provenance": "Test",
    }
    rule = compile_rule(raw)
    ev_reg = _make_ev("registry.run_keys")
    ev_fs = _make_ev("fs.stat_hash")
    evidence_map = {
        "registry.run_keys": (ev_reg, {}),
        "fs.stat_hash": (ev_fs, {"exists": False}),
    }
    result = compute_confidence(rule, "payload_present", evidence_map)
    assert result.state == ClaimState.CONTRADICTED


# ─── Ledger tests ────────────────────────────────────────────────────────────

def test_ledger_chain(tmp_path):
    from counsel.ledger.ledger import Ledger, GENESIS_HASH
    ledger_path = tmp_path / "test.jsonl"
    ledger = Ledger(ledger_path, run_id="test-run")
    ledger.genesis("abc123", "catalog_hash", "rule_hash")
    ledger.append_agent_decision(1, "TRIAGE", "start", "beginning investigation")
    valid, errors = ledger.verify_chain()
    assert valid, f"Chain errors: {errors}"
    assert errors == []


def test_ledger_tamper_detected(tmp_path):
    import json
    from counsel.ledger.ledger import Ledger
    ledger_path = tmp_path / "test.jsonl"
    ledger = Ledger(ledger_path, run_id="test-run")
    ledger.genesis("abc123", "cat", "rules")
    ledger.append_agent_decision(1, "TRIAGE", "action", "rationale")

    # Tamper with entry 0
    lines = ledger_path.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["payload"]["evidence_sha256_in"] = "TAMPERED"
    lines[0] = json.dumps(entry)
    ledger_path.write_text("\n".join(lines) + "\n")

    tampered_ledger = Ledger(ledger_path, run_id="test-run")
    valid, errors = tampered_ledger.verify_chain()
    assert not valid
    assert len(errors) > 0
