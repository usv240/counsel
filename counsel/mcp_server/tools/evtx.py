"""
T10: evtx.query(filter)
Evidentiary meaning: logon/service/exec events (corroboration from Windows Event Logs)

Wraps evtx_dump (python-evtx) or wevtutil on SIFT.
Never dumps raw XML/binary event logs into context.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from ..parsers.base import (
    ParseResult,
    hash_raw,
    load_fixture_result,
    run_tool_subprocess,
    sanitize_string,
    tool_error_result,
    truncate_records,
)

# Common event log channels
EVTX_CANDIDATES = {
    "Security": [
        "Windows/System32/winevt/Logs/Security.evtx",
        "Windows/System32/winevt/logs/Security.evtx",
        "WINDOWS/system32/winevt/Logs/Security.evtx",
    ],
    "System": [
        "Windows/System32/winevt/Logs/System.evtx",
    ],
    "Application": [
        "Windows/System32/winevt/Logs/Application.evtx",
    ],
    "PowerShell": [
        "Windows/System32/winevt/Logs/Windows PowerShell.evtx",
        "Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx",
    ],
    "TaskScheduler": [
        "Windows/System32/winevt/Logs/Microsoft-Windows-TaskScheduler%4Operational.evtx",
    ],
    "WMI": [
        "Windows/System32/winevt/Logs/Microsoft-Windows-WMI-Activity%4Operational.evtx",
    ],
}

# Event IDs of forensic interest
INTERESTING_EIDS = {
    4624: "Logon Success",
    4625: "Logon Failure",
    4648: "Explicit Credentials Logon",
    4672: "Special Privileges",
    4688: "Process Creation",
    4698: "Scheduled Task Created",
    4702: "Scheduled Task Updated",
    4720: "User Account Created",
    4728: "Member Added to Global Group",
    7045: "New Service Installed",
    1102: "Audit Log Cleared",
    4663: "Object Access",
    4657: "Registry Value Modified",
}


def _find_evtx(evidence_root: Path, channel: str, evtx_path: Optional[str]) -> Optional[Path]:
    if evtx_path:
        p = evidence_root / evtx_path.lstrip("/\\")
        return p if p.exists() else None
    for rel in EVTX_CANDIDATES.get(channel, []):
        p = evidence_root / rel
        if p.exists():
            return p
    return None


def _parse_evtx_dump_json(raw: bytes, eid_filter: Optional[int], start_time: str, end_time: str, max_str: int) -> tuple[list[dict], list[str]]:
    """Parse evtx_dump JSON-lines output."""
    records: list[dict] = []
    warnings: list[str] = []
    text = raw.decode("utf-8", errors="replace")

    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            evt = json.loads(line)
            system = evt.get("System", {})
            eid = int(system.get("EventID", {}).get("#text", system.get("EventID", 0)) or 0)

            if eid_filter is not None and eid != eid_filter:
                continue

            ts = sanitize_string(system.get("TimeCreated", {}).get("@SystemTime", ""), 64)
            if start_time and ts and ts < start_time:
                continue
            if end_time and ts and ts > end_time:
                continue

            data = evt.get("EventData", {})
            if isinstance(data, dict):
                fields = {
                    sanitize_string(k, 64): sanitize_string(v, max_str)
                    for k, v in data.items()
                    if not k.startswith("@")
                }
            else:
                fields = {}

            records.append({
                "channel": sanitize_string(system.get("Channel", ""), 64),
                "eid": eid,
                "ts": ts,
                "description": INTERESTING_EIDS.get(eid, ""),
                "computer": sanitize_string(system.get("Computer", ""), max_str),
                "fields": fields,
            })
        except (json.JSONDecodeError, ValueError, KeyError):
            continue

    return records, warnings


def _parse_evtx_xml(raw: bytes, eid_filter: Optional[int], start_time: str, end_time: str, max_str: int) -> tuple[list[dict], list[str]]:
    """Parse raw XML event log output (fallback)."""
    records: list[dict] = []
    warnings: list[str] = []
    text = raw.decode("utf-8", errors="replace")

    ns = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}
    # Handle multiple events concatenated
    for evt_xml in re.split(r"(?=<Event xmlns)", text):
        if not evt_xml.strip():
            continue
        try:
            root = ET.fromstring(evt_xml)
            system = root.find("evt:System", ns)
            if system is None:
                continue

            eid_el = system.find("evt:EventID", ns)
            eid = int(eid_el.text or 0) if eid_el is not None else 0

            if eid_filter is not None and eid != eid_filter:
                continue

            ts_el = system.find("evt:TimeCreated", ns)
            ts = sanitize_string(ts_el.get("SystemTime", "") if ts_el is not None else "", 64)

            data_el = root.find("evt:EventData", ns)
            fields = {}
            if data_el is not None:
                for named in data_el.findall("evt:Data", ns):
                    name = named.get("Name", "")
                    fields[sanitize_string(name, 64)] = sanitize_string(named.text or "", max_str)

            records.append({
                "channel": sanitize_string(
                    (system.find("evt:Channel", ns) or ET.Element("")).text or "", 64
                ),
                "eid": eid,
                "ts": ts,
                "description": INTERESTING_EIDS.get(eid, ""),
                "computer": sanitize_string(
                    (system.find("evt:Computer", ns) or ET.Element("")).text or "", max_str
                ),
                "fields": fields,
            })
        except ET.ParseError:
            continue

    return records, warnings


def query(
    run_id: str,
    evidence_root: Path,
    channel: str = "Security",
    eid: Optional[int] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    evtx_path: Optional[str] = None,
    keyword: Optional[str] = None,
    evtx_dump_bin: str = "",
    max_records: int = 200,
    max_str_len: int = 512,
    timeout: int = 120,
    ledger_seq: int = 0,
) -> ParseResult:
    """
    T10: Query Windows Event Logs.

    channel:    Security | System | Application | PowerShell | TaskScheduler | WMI
    eid:        optional Event ID filter (e.g. 4688 for process creation)
    start_time: optional ISO timestamp lower bound
    end_time:   optional ISO timestamp upper bound
    keyword:    optional substring to match in event fields

    Typed output per record:
        channel, eid, ts, description, computer, fields (dict of event data)
    """
    fixture = load_fixture_result("evtx_query", run_id, str(evidence_root), artifact_name="evtx.query")
    if fixture is not None:
        return fixture

    evtx_file = _find_evtx(evidence_root, channel, evtx_path)
    if not evtx_file:
        return tool_error_result("evtx.query", run_id, str(evidence_root),
                                 f"Event log not found for channel '{channel}'")

    if not evtx_dump_bin:
        return tool_error_result("evtx.query", run_id, str(evtx_file),
                                 "evtx_dump binary not configured. "
                                 "Install: pip install python-evtx  # provides evtx_dump")

    st = start_time or ""
    et = end_time or ""
    warnings: list[str] = []

    stdout, stderr, rc = run_tool_subprocess(
        [evtx_dump_bin, "--format", "json", str(evtx_file)],
        evidence_root, timeout,
    )

    if rc != 0 or not stdout:
        # Try XML format
        stdout, stderr, rc = run_tool_subprocess(
            [evtx_dump_bin, str(evtx_file)],
            evidence_root, timeout,
        )
        if rc == 0 and stdout:
            records, warns = _parse_evtx_xml(stdout, eid, st, et, max_str_len)
        else:
            return tool_error_result("evtx.query", run_id, str(evtx_file),
                                     f"evtx_dump failed rc={rc}", stderr)
    else:
        records, warns = _parse_evtx_dump_json(stdout, eid, st, et, max_str_len)

    warnings.extend(warns)

    # Keyword filter post-parse
    if keyword:
        kw = keyword.lower()
        records = [
            r for r in records
            if kw in json.dumps(r).lower()
        ]

    final_records, truncated = truncate_records(records, max_records, warnings)
    return ParseResult(
        tool="evtx.query", run_id=run_id, seq=ledger_seq,
        records=final_records, artifact_path=str(evtx_file), offset=0,
        raw_output_sha256=hash_raw(stdout) if stdout else hash_raw(b"empty"),
        parse_quality=0.95, warnings=warnings, truncated=truncated,
    )
