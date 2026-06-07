"""
T1: registry.run_keys()
Evidentiary meaning: persistence_configured

Wraps Eric Zimmerman's RECmd (rla.exe) on SIFT Workstation.
Falls back to python-registry (regipy) if RECmd is unavailable.
Parse-before-return: typed records only, never raw hive dumps.
"""
from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path
from typing import Optional

from ..parsers.base import (
    ParseResult,
    hash_raw,
    run_tool_subprocess,
    sanitize_string,
    tool_error_result,
    truncate_records,
)

# Run key paths (checked in both NTUSER and SOFTWARE hives)
RUN_KEY_PATHS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"SYSTEM\CurrentControlSet\Services",
]

# Suspicion heuristics (evidence for analyst, not blocking)
_SUSPICIOUS_RE = [
    re.compile(r"\b(cmd|powershell|wscript|cscript|mshta|regsvr32|rundll32)\.exe\b", re.I),
    re.compile(r"%temp%|%appdata%|%localappdata%|%tmp%", re.I),
    re.compile(r"\\users\\[^\\]+\\appdata\\(local|roaming)\\temp\\", re.I),
    re.compile(r"\.(vbs|ps1|bat|cmd|hta|js|jse|wsf)\b", re.I),
    re.compile(r"-enc\b|-encodedcommand|-nop\b|-noprofile|-w\s+hidden|-windowstyle\s+hidden", re.I),
    re.compile(r"https?://|ftp://", re.I),
    re.compile(r"\\(temp|tmp)\\[a-z0-9]{6,}\.(exe|dll|bat|ps1)", re.I),
]

def _suspicion_score(command: str) -> float:
    hits = sum(1 for p in _SUSPICIOUS_RE if p.search(command))
    return round(min(1.0, hits / 3.0), 3)


def _parse_recmd_csv(raw: bytes, max_str: int) -> tuple[list[dict], list[str]]:
    records: list[dict] = []
    warnings: list[str] = []
    text = raw.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        cmd = sanitize_string(row.get("ValueData") or row.get("ValueData2") or "", max_str)
        records.append({
            "hive": sanitize_string(row.get("HiveType", ""), max_str),
            "key": sanitize_string(row.get("KeyPath", ""), max_str),
            "value_name": sanitize_string(row.get("ValueName", ""), max_str),
            "command": cmd,
            "last_write": sanitize_string(row.get("LastWriteTimestamp", ""), 64),
            "suspicion_score": _suspicion_score(cmd),
        })
    return records, warnings


def _parse_recmd_json(raw: bytes, max_str: int) -> tuple[list[dict], list[str]]:
    records: list[dict] = []
    warnings: list[str] = []
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        entries = data if isinstance(data, list) else data.get("entries", [data])
        for entry in entries:
            cmd = sanitize_string(entry.get("ValueData", "") or "", max_str)
            records.append({
                "hive": sanitize_string(entry.get("HiveType", ""), max_str),
                "key": sanitize_string(entry.get("KeyPath", ""), max_str),
                "value_name": sanitize_string(entry.get("ValueName", ""), max_str),
                "command": cmd,
                "last_write": sanitize_string(entry.get("LastWriteTimestamp", ""), 64),
                "suspicion_score": _suspicion_score(cmd),
            })
    except json.JSONDecodeError as e:
        warnings.append(f"JSON parse error: {e}")
    return records, warnings


def _parse_regipy(raw: bytes, max_str: int) -> tuple[list[dict], list[str]]:
    """Parse regipy JSON output (SIFT fallback when RECmd is unavailable)."""
    records: list[dict] = []
    warnings: list[str] = []
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        for entry in (data if isinstance(data, list) else [data]):
            cmd = sanitize_string(entry.get("value", "") or "", max_str)
            records.append({
                "hive": sanitize_string(entry.get("hive_type", "UNKNOWN"), max_str),
                "key": sanitize_string(entry.get("key_path", ""), max_str),
                "value_name": sanitize_string(entry.get("name", ""), max_str),
                "command": cmd,
                "last_write": sanitize_string(entry.get("timestamp", ""), 64),
                "suspicion_score": _suspicion_score(cmd),
            })
    except json.JSONDecodeError as e:
        warnings.append(f"regipy JSON error: {e}")
    return records, warnings


def run_keys(
    run_id: str,
    evidence_root: Path,
    hive_paths: list[str],
    recmd_bin: str = "",
    regipy_bin: str = "",
    max_records: int = 200,
    max_str_len: int = 512,
    timeout: int = 120,
    ledger_seq: int = 0,
) -> ParseResult:
    """
    T1: Extract Run/RunOnce/RunServices persistence keys.

    hive_paths: list of paths relative to evidence_root
                e.g. ["Windows/System32/config/SOFTWARE",
                      "Users/Rick/NTUSER.DAT"]

    Typed output per record:
        hive, key, value_name, command, last_write, suspicion_score
    """
    if not hive_paths:
        return tool_error_result(
            "registry.run_keys", run_id, str(evidence_root),
            "hive_paths is required — provide paths to registry hive files"
        )

    all_records: list[dict] = []
    all_raw = b""
    warnings: list[str] = []
    quality = 1.0

    for hive_rel in hive_paths:
        hive_abs = evidence_root / hive_rel.lstrip("/\\")
        if not hive_abs.exists():
            warnings.append(f"Hive not found: {hive_rel}")
            quality -= 0.15
            continue

        parsed = False

        # Try RECmd (Zimmerman tools — preferred on SIFT)
        if recmd_bin:
            for key_path in RUN_KEY_PATHS:
                stdout, stderr, rc = run_tool_subprocess(
                    [recmd_bin, "-f", str(hive_abs), "--kf", key_path,
                     "--csv", "--csvf", "/dev/stdout", "-q"],
                    evidence_root, timeout,
                )
                if rc == 0 and stdout:
                    recs, warns = _parse_recmd_csv(stdout, max_str_len)
                    all_records.extend(recs)
                    warnings.extend(warns)
                    all_raw += stdout
                    parsed = True
                elif rc != 0:
                    warnings.append(
                        f"RECmd on {hive_rel}/{key_path}: rc={rc} "
                        f"stderr={sanitize_string(stderr.decode('utf-8', errors='replace')[:100])}"
                    )

        # Fallback: regipy
        if not parsed and regipy_bin:
            stdout, stderr, rc = run_tool_subprocess(
                [regipy_bin, str(hive_abs), "--registry-path", RUN_KEY_PATHS[0],
                 "--json"],
                evidence_root, timeout,
            )
            if rc == 0 and stdout:
                recs, warns = _parse_regipy(stdout, max_str_len)
                all_records.extend(recs)
                warnings.extend(warns)
                all_raw += stdout
                parsed = True

        if not parsed:
            warnings.append(
                f"No parser available for {hive_rel}. "
                "Install RECmd or regipy: pip install regipy"
            )
            quality -= 0.2

    if not all_records and not warnings:
        warnings.append("No run key records found — hive may be clean or parsers unavailable")

    records, truncated = truncate_records(all_records, max_records, warnings)

    return ParseResult(
        tool="registry.run_keys",
        run_id=run_id,
        seq=ledger_seq,
        records=records,
        artifact_path=str(evidence_root),
        offset=0,
        raw_output_sha256=hash_raw(all_raw) if all_raw else hash_raw(b"empty"),
        parse_quality=max(0.0, quality),
        warnings=warnings,
        truncated=truncated,
    )
