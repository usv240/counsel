"""
COUNSEL Web API - FastAPI backend for the live dashboard.

Endpoints:
  GET  /api/stats                    - live system stats (rule count, tool count, etc.)
  GET  /api/cases                    - list completed investigations
  GET  /api/cases/{run_id}/claims    - claim graph for a completed run
  GET  /api/cases/{run_id}/ledger    - ledger entries for a completed run
  POST /api/cases/{run_id}/attack    - generate ATT&CK Navigator layer for a run
  GET  /api/cases/{run_id}/stream    - SSE stream of agent events for a run in progress
  GET  /                             - serve the live dashboard HTML
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, AsyncGenerator, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from sse_starlette.sse import EventSourceResponse

app = FastAPI(
    title="COUNSEL API",
    description="Corroboration-First Autonomous DFIR Agent - Live API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Resolve paths relative to this file
_PACKAGE_ROOT = Path(__file__).parent.parent
_RULES_DIR = _PACKAGE_ROOT / "rules"
_TOOLS_DIR = _PACKAGE_ROOT / "mcp_server" / "tools"
_OUTPUT_DIR = Path(os.environ.get("COUNSEL_OUTPUT_DIR", "./counsel-output"))
_DASHBOARD_HTML = Path(__file__).parent / "dashboard.html"

# Tool names: static list derived from the 10 MCP tool files (excludes __init__.py)
_TOOL_NAMES = [
    "registry.run_keys",
    "prefetch.run_record",
    "amcache.lookup",
    "fs.stat_hash",
    "mft.timeline",
    "yara.scan",
    "mem.pslist",
    "mem.netscan",
    "mem.malfind",
    "net.flows",
    "evtx.query",
]


# ─── Stats ────────────────────────────────────────────────────────────────────

def _count_rules() -> int:
    if not _RULES_DIR.exists():
        return 0
    total = 0
    for yaml_file in _RULES_DIR.glob("*.yaml"):
        try:
            text = yaml_file.read_text(encoding="utf-8")
            total += text.count("\nrule:") + (1 if text.startswith("rule:") else 0)
        except Exception:
            pass
    return total


def _count_completed_runs() -> int:
    if not _OUTPUT_DIR.exists():
        return 0
    return sum(1 for d in _OUTPUT_DIR.iterdir() if d.is_dir() and (d / "counsel-ledger.jsonl").exists())


@app.get("/api/stats")
def get_stats() -> JSONResponse:
    """Return live system statistics for the landing page and dashboard."""
    rule_count = _count_rules()
    tool_count = len(_TOOL_NAMES)
    completed_runs = _count_completed_runs()

    fixture_dir = os.environ.get("COUNSEL_FIXTURE_DIR", "")
    fixture_active = bool(fixture_dir and Path(fixture_dir).exists())

    rules_dir_exists = _RULES_DIR.exists()
    tools_dir_exists = _TOOLS_DIR.exists()

    return JSONResponse({
        "rule_count": rule_count,
        "tool_count": tool_count,
        "completed_runs": completed_runs,
        "artifact_types": tool_count,
        "state_model": 5,
        "independence_groups_minimum": 2,
        "tau_corroborated": 0.80,
        "fixture_mode_active": fixture_active,
        "fixture_dir": fixture_dir if fixture_active else "",
        "rules_loaded": rules_dir_exists,
        "tools_online": tools_dir_exists,
        "version": "1.0.0",
        "timestamp": time.time(),
    })


# ─── Cases ────────────────────────────────────────────────────────────────────

def _load_ledger_entries(run_dir: Path) -> list[dict]:
    ledger_path = run_dir / "counsel-ledger.jsonl"
    if not ledger_path.exists():
        return []
    entries = []
    for line in ledger_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return entries


def _extract_claims_from_ledger(entries: list[dict]) -> list[dict]:
    """Extract claim state entries from the ledger."""
    claims = {}
    for entry in entries:
        data = entry.get("data", {})
        if entry.get("type") in ("claim_update", "claim_final", "claim_state"):
            claim_id = data.get("claim_id") or data.get("id")
            if claim_id:
                claims[claim_id] = {
                    "id": claim_id,
                    "state": data.get("state", "UNRESOLVED"),
                    "support": data.get("support", 0.0),
                    "independent_groups": data.get("independent_groups_active", 0),
                    "signals": data.get("signals_fired", []),
                    "ts": entry.get("ts", ""),
                }
    return list(claims.values())


def _get_run_summary(run_dir: Path) -> dict:
    run_id = run_dir.name
    entries = _load_ledger_entries(run_dir)
    claims = _extract_claims_from_ledger(entries)

    started_at = ""
    ended_at = ""
    if entries:
        started_at = entries[0].get("ts", "")
        ended_at = entries[-1].get("ts", "")

    corroborated = sum(1 for c in claims if c["state"] == "CORROBORATED")
    contradicted = sum(1 for c in claims if c["state"] == "CONTRADICTED")
    unresolved = sum(1 for c in claims if c["state"] == "UNRESOLVED")

    report_path = run_dir / f"counsel_case_{run_id}.html"
    has_report = report_path.exists()

    manifest_path = run_dir / f"manifest_{run_id}.json"
    has_manifest = manifest_path.exists()

    return {
        "run_id": run_id,
        "started_at": started_at,
        "ended_at": ended_at,
        "ledger_entries": len(entries),
        "claims_total": len(claims),
        "claims_corroborated": corroborated,
        "claims_contradicted": contradicted,
        "claims_unresolved": unresolved,
        "has_report": has_report,
        "has_manifest": has_manifest,
    }


@app.get("/api/cases")
def list_cases() -> JSONResponse:
    """List all completed investigations."""
    if not _OUTPUT_DIR.exists():
        return JSONResponse({"cases": []})
    cases = []
    for run_dir in sorted(_OUTPUT_DIR.iterdir(), key=lambda d: d.stat().st_mtime, reverse=True):
        if run_dir.is_dir() and (run_dir / "counsel-ledger.jsonl").exists():
            try:
                cases.append(_get_run_summary(run_dir))
            except Exception:
                pass
    return JSONResponse({"cases": cases})


@app.get("/api/cases/{run_id}/claims")
def get_claims(run_id: str) -> JSONResponse:
    """Get claim graph for a specific run."""
    run_dir = _OUTPUT_DIR / run_id
    if not run_dir.exists():
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    entries = _load_ledger_entries(run_dir)
    claims = _extract_claims_from_ledger(entries)
    return JSONResponse({"run_id": run_id, "claims": claims})


@app.get("/api/cases/{run_id}/ledger")
def get_ledger(run_id: str, limit: int = 100, offset: int = 0) -> JSONResponse:
    """Get ledger entries for a specific run."""
    run_dir = _OUTPUT_DIR / run_id
    if not run_dir.exists():
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    entries = _load_ledger_entries(run_dir)
    total = len(entries)
    page = entries[offset: offset + limit]
    return JSONResponse({"run_id": run_id, "total": total, "offset": offset, "entries": page})


# ─── SSE Stream ───────────────────────────────────────────────────────────────

# In-memory event bus: run_id -> list of pending events
_event_queues: dict[str, list[dict]] = {}


def push_event(run_id: str, event: dict) -> None:
    """Push an agent event onto the SSE queue for a run. Called by the agent loop."""
    if run_id not in _event_queues:
        _event_queues[run_id] = []
    _event_queues[run_id].append(event)


async def _stream_events(run_id: str) -> AsyncGenerator[dict, None]:
    import asyncio
    seen = 0
    timeout = 300  # 5 min max stream duration
    start = time.monotonic()

    while time.monotonic() - start < timeout:
        queue = _event_queues.get(run_id, [])
        while seen < len(queue):
            evt = queue[seen]
            seen += 1
            yield {"data": json.dumps(evt)}

        # Check if run is done (ledger file exists and last event was "done")
        if queue and queue[-1].get("type") == "done":
            break

        await asyncio.sleep(0.25)

    yield {"data": json.dumps({"type": "stream_end", "run_id": run_id})}


@app.get("/api/cases/{run_id}/stream")
async def stream_events(run_id: str):
    """SSE stream of agent events for a live or recently completed run."""
    return EventSourceResponse(_stream_events(run_id))


# ─── ATT&CK Navigator Export ──────────────────────────────────────────────────

_ATTACK_MAP = {
    "persistence_configured": ["T1547.001"],
    "payload_executed": ["T1059.001", "T1204.002"],
    "payload_present": ["T1105"],
    "payload_active": ["T1055"],
    "C2_communication": ["T1071.001", "T1041"],
    "credential_access": ["T1003"],
    "lateral_movement": ["T1021"],
    "discovery": ["T1083", "T1057"],
    "defense_evasion": ["T1036", "T1027"],
}


@app.post("/api/cases/{run_id}/attack")
def export_attack_layer(run_id: str) -> JSONResponse:
    """Generate a MITRE ATT&CK Navigator layer from corroborated claims."""
    run_dir = _OUTPUT_DIR / run_id
    if not run_dir.exists():
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")

    entries = _load_ledger_entries(run_dir)
    claims = _extract_claims_from_ledger(entries)

    techniques: list[dict] = []
    seen_ids: set[str] = set()

    for claim in claims:
        if claim["state"] == "CORROBORATED":
            for technique_id in _ATTACK_MAP.get(claim["id"], []):
                if technique_id not in seen_ids:
                    seen_ids.add(technique_id)
                    techniques.append({
                        "techniqueID": technique_id,
                        "score": int(claim["support"] * 100),
                        "color": "#ff6666",
                        "comment": f"CORROBORATED by COUNSEL run {run_id} (support={claim['support']:.2f})",
                        "enabled": True,
                    })

    layer = {
        "name": f"COUNSEL Investigation {run_id}",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Auto-generated by COUNSEL corroboration engine for run {run_id}",
        "filters": {"platforms": ["Windows"]},
        "sorting": 0,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#ff6666", "#ff0000"], "minValue": 0, "maxValue": 100},
        "legendItems": [{"label": "CORROBORATED claim", "color": "#ff6666"}],
        "metadata": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
    }

    return JSONResponse(layer)


# ─── Dashboard ────────────────────────────────────────────────────────────────

@app.get("/")
def serve_dashboard() -> HTMLResponse:
    """Serve the live web dashboard."""
    if _DASHBOARD_HTML.exists():
        return HTMLResponse(_DASHBOARD_HTML.read_text(encoding="utf-8"))
    return HTMLResponse(
        "<h1>COUNSEL Dashboard</h1>"
        "<p>Dashboard HTML not found. Run: counsel serve</p>"
        "<p><a href='/api/stats'>/api/stats</a> | "
        "<a href='/api/cases'>/api/cases</a></p>"
    )
