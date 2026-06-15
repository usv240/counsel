"""
No-API demonstration runner.

Replays recorded case fixtures through the real corroboration engine to produce
the same verdict the live agent reaches - a signed, hash-chained ledger and an
HTML case file - with NO ANTHROPIC_API_KEY required.

This exists so a judge or practitioner can see the full pipeline (tool outputs ->
corroboration math -> 5-state verdict -> signed ledger -> case file) in two seconds,
offline, before ever wiring up an API key or the SIFT toolchain. The agent loop and
the engine are identical to a live run; only the tool *outputs* are pre-recorded.
"""
from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

from ..agent.loop import CounselLoop, LoopConfig
from ..engine.dsl import RuleRegistry
from ..engine.model import ClaimState
from ..ledger.ledger import Ledger
from ..mcp_server.parsers.base import load_fixture_result
from ..report import html_report

# Canonical investigation order: persistence -> payload -> memory -> network -> logs.
# (fixture_stem, dotted_artifact_name). Only tools whose fixture file exists are run,
# so the same runner works for any case fixture directory.
_TOOL_ORDER = [
    ("registry_run_keys",   "registry.run_keys"),
    ("prefetch_run_record", "prefetch.run_record"),
    ("mft_timeline",        "mft.timeline"),
    ("fs_stat_hash",        "fs.stat_hash"),
    ("yara_scan",           "yara.scan"),
    ("amcache_lookup",      "amcache.lookup"),
    ("mem_pslist",          "mem.pslist"),
    ("mem_netscan",         "mem.netscan"),
    ("mem_malfind",         "mem.malfind"),
    ("net_flows",           "net.flows"),
    ("evtx_query",          "evtx.query"),
]

_FIXTURES_BASE = Path(__file__).resolve().parent.parent / "fixtures"
_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def _evidence_sha(fixture_dir: Path) -> str:
    h = hashlib.sha256()
    for f in sorted(fixture_dir.glob("*.json")):
        if f.name == "answer_key.json":
            continue
        h.update(f.read_bytes())
    return h.hexdigest()


def run_demo(case: str, output_dir: Path) -> dict:
    """
    Run the deterministic no-API demonstration for a fixture case.

    Returns a dict with the claim graph, report path, ledger path, chain validity,
    elapsed time, run id, and the distinct-finding verdict counts.
    """
    fixture_dir = _FIXTURES_BASE / case
    if not fixture_dir.is_dir():
        available = sorted(p.name for p in _FIXTURES_BASE.iterdir() if p.is_dir())
        raise FileNotFoundError(
            f"Fixture case '{case}' not found under {_FIXTURES_BASE}. Available: {available}"
        )

    run_id = f"demo-{case[:16]}"
    case_out = output_dir / run_id
    case_out.mkdir(parents=True, exist_ok=True)
    ledger_path = case_out / "counsel-ledger.jsonl"
    if ledger_path.exists():
        ledger_path.unlink()  # fresh chain each run

    rule_registry = RuleRegistry()
    rule_registry.load_directory(_RULES_DIR)
    evidence_sha = _evidence_sha(fixture_dir)

    ledger = Ledger(ledger_path, run_id)
    ledger.genesis(
        evidence_sha256=evidence_sha,
        tool_catalog_hash="tool_catalog_v1",
        rule_set_hash=rule_registry.catalog_hash(),
    )

    config = LoopConfig(run_id=run_id, rules_dir=_RULES_DIR, evidence_sha256=evidence_sha)
    loop = CounselLoop(config)
    loop._load_rules()

    os.environ["COUNSEL_FIXTURE_DIR"] = str(fixture_dir)  # activate fixture replay
    start = time.monotonic()
    try:
        iteration = 0
        for stem, artifact in _TOOL_ORDER:
            if not (fixture_dir / f"{stem}.json").exists():
                continue  # case may not include every artifact family
            iteration += 1
            result = load_fixture_result(stem, run_id, "", artifact_name=artifact)
            if result is None:
                continue
            seq = ledger.append_tool_call(result)  # mirror server.py: pin seq on result
            result.seq = seq
            loop._update_claim_from_tool_result(result.to_dict(), iteration)
    finally:
        os.environ.pop("COUNSEL_FIXTURE_DIR", None)
    elapsed = time.monotonic() - start

    # Persist claim-state transitions (mirrors the launcher's post-loop ledger pass).
    for claim in loop.claim_graph.claims:
        for sc in claim.history:
            ledger.append_claim_state(
                claim_id=claim.id,
                claim_type=claim.claim_type.value,
                subject=claim.subject,
                from_state=sc.from_state.value,
                to_state=sc.to_state.value,
                support=sc.support_after,
                contradiction=claim.contradiction_score,
                rule_id=claim.rule_id,
                trigger=sc.trigger,
                iteration=sc.iteration,
            )
    open_claims = len([c for c in loop.claim_graph.claims if c.needs_investigation])
    ledger.append_halt(
        reason="all_claims_settled" if open_claims == 0 else "bounded_search_complete",
        iteration=iteration,
        open_claims=open_claims,
        corroborated_claims=len(loop.claim_graph.distinct_corroborated()),
        elapsed_seconds=elapsed,
    )

    chain_valid, _errors = ledger.verify_chain()

    report_path = case_out / f"counsel_case_{run_id}.html"
    html_report.generate(
        claim_graph=loop.claim_graph,
        ledger=ledger,
        output_path=report_path,
        run_id=run_id,
        elapsed_seconds=elapsed,
        evidence_sha_in=evidence_sha,
        evidence_sha_out=evidence_sha,   # fixtures unchanged -> integrity VERIFIED
        chain_valid=chain_valid,
    )

    distinct = loop.claim_graph.distinct_findings()
    return {
        "run_id": run_id,
        "claim_graph": loop.claim_graph,
        "report_path": report_path,
        "ledger_path": ledger_path,
        "chain_valid": chain_valid,
        "elapsed": elapsed,
        "corroborated": [c for c in distinct if c.state == ClaimState.CORROBORATED],
        "contradicted": [c for c in distinct if c.state == ClaimState.CONTRADICTED],
        "withheld": [c for c in distinct if c.state != ClaimState.CORROBORATED],
        "tool_calls": iteration,
    }
