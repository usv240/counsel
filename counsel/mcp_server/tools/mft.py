"""
T5: mft.timeline(filter)
Evidentiary meaning: timeline backbone (MACB timestamps for all activity)

Wraps MFTECmd.exe (Zimmerman) or analyzeMFT (Python fallback) on SIFT.
Returns unified MACB timeline entries - filtered to avoid context explosion.
"""
from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from datetime import datetime, timezone
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

MFT_CANDIDATES = [
    "$MFT",
    "Windows/$MFT",
    "WINDOWS/$MFT",
]


def _find_mft(evidence_root: Path, mft_path: Optional[str]) -> Optional[Path]:
    if mft_path:
        p = evidence_root / mft_path.lstrip("/\\")
        return p if p.exists() else None
    for c in MFT_CANDIDATES:
        p = evidence_root / c
        if p.exists():
            return p
    return None


def _parse_mftecmd_csv(
    raw: bytes,
    path_filter: str,
    start_time: str,
    end_time: str,
    max_str: int,
) -> tuple[list[dict], list[str]]:
    records: list[dict] = []
    warnings: list[str] = []
    text = raw.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))

    for row in reader:
        entry_path = sanitize_string(row.get("ParentPath", "") + "\\" + row.get("FileName", ""), max_str)
        ts_si = sanitize_string(row.get("SiCreated0x10", "") or row.get("Created0x10", ""), 64)

        # Path filter
        if path_filter and path_filter.lower() not in entry_path.lower():
            continue

        # Time filter
        if start_time and ts_si and ts_si < start_time:
            continue
        if end_time and ts_si and ts_si > end_time:
            continue

        records.append({
            "ts": ts_si,
            "path": entry_path,
            "action": _infer_action(row),
            "MACB": _macb_flags(row),
            "source": "MFT",
            "entry_num": sanitize_string(row.get("EntryNumber", ""), 16),
            "is_deleted": row.get("IsDeleted", "").lower() in ("true", "1", "yes"),
            "file_size": _safe_int(row.get("FileSize", 0)),
        })

    return records, warnings


def _infer_action(row: dict) -> str:
    is_dir = row.get("IsDirectory", "").lower() in ("true", "1")
    is_del = row.get("IsDeleted", "").lower() in ("true", "1", "yes")
    if is_del:
        return "delete"
    if is_dir:
        return "create_dir"
    return "create_file"


def _macb_flags(row: dict) -> str:
    """Produce MACB string from MFT row: M=modified, A=accessed, C=changed, B=born."""
    parts = []
    if row.get("SiModified0x10") or row.get("LastModified0x10"):
        parts.append("M")
    if row.get("SiAccessed0x10") or row.get("LastAccessed0x10"):
        parts.append("A")
    if row.get("SiChanged0x10") or row.get("EntryModified0x10"):
        parts.append("C")
    if row.get("SiCreated0x10") or row.get("Created0x10"):
        parts.append("B")
    return "".join(parts) or "????"


def _safe_int(v: object) -> int:
    try:
        return int(str(v).strip())
    except (ValueError, TypeError):
        return 0


_FALLBACK_SCAN_ROOTS = [
    "Windows/Temp",
    "Windows/System32/Tasks",
    "Users",
    "ProgramData",
    "$Recycle.Bin",
    "Temp",
]


def _filesystem_timeline_fallback(
    run_id: str,
    evidence_root: Path,
    mft: Path,
    path_filter: str,
    start_time: str,
    end_time: str,
    max_records: int,
    max_str_len: int,
    ledger_seq: int,
) -> ParseResult:
    """Filesystem timestamp scan fallback when MFTECmd is unavailable.

    Walks high-value directories on the mounted evidence volume and returns
    file modification timestamps as timeline entries. parse_quality=0.5
    reflects reduced fidelity vs full MFT parsing (no deleted files, no MACB
    distinction), but is sufficient for corroboration group counting.
    """
    records: list[dict] = []
    warnings = [
        "MFTECmd not available; falling back to filesystem timestamp scan "
        "(parse_quality=0.5). Install MFTECmd for full MFT analysis."
    ]

    roots = [evidence_root / r for r in _FALLBACK_SCAN_ROOTS]
    if not any(r.exists() for r in roots):
        roots = [evidence_root]

    for scan_root in roots:
        if not scan_root.exists():
            continue
        try:
            for child in scan_root.rglob("*"):
                if len(records) >= max_records:
                    break
                if not child.is_file():
                    continue
                try:
                    stat = child.stat()
                except OSError:
                    continue
                try:
                    rel_str = str(child.relative_to(evidence_root))
                except ValueError:
                    rel_str = str(child)
                if path_filter and path_filter.lower() not in rel_str.lower():
                    continue
                ts = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                if start_time and ts < start_time:
                    continue
                if end_time and ts > end_time:
                    continue
                records.append({
                    "ts": ts,
                    "path": sanitize_string(rel_str, max_str_len),
                    "action": "modify",
                    "MACB": "MAC.",
                    "source": "FILESYSTEM",
                    "entry_num": "",
                    "is_deleted": False,
                    "file_size": stat.st_size,
                })
        except (OSError, PermissionError):
            continue
        if len(records) >= max_records:
            break

    final_records, truncated = truncate_records(records, max_records, warnings)
    return ParseResult(
        tool="mft.timeline",
        run_id=run_id,
        seq=ledger_seq,
        records=final_records,
        artifact_path=str(mft),
        offset=0,
        raw_output_sha256=hash_raw(b"filesystem_scan_fallback"),
        parse_quality=0.5,
        warnings=warnings,
        truncated=truncated,
    )


def timeline(
    run_id: str,
    evidence_root: Path,
    path_filter: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    mft_path: Optional[str] = None,
    mft_ecmd_bin: str = "",
    max_records: int = 200,
    max_str_len: int = 512,
    timeout: int = 300,
    ledger_seq: int = 0,
) -> ParseResult:
    """
    T5: Extract MFT timeline entries.

    path_filter: optional path substring (e.g. "Temp", "AppData\\Local")
    start_time:  optional ISO timestamp lower bound
    end_time:    optional ISO timestamp upper bound
    mft_path:    path to $MFT relative to evidence_root (auto-detected if None)

    Typed output per record:
        ts, path, action, MACB, source, entry_num, is_deleted, file_size
    """
    fixture = load_fixture_result("mft_timeline", run_id, str(evidence_root), artifact_name="mft.timeline")
    if fixture is not None:
        return fixture

    mft = _find_mft(evidence_root, mft_path)

    pf = path_filter or ""
    st = start_time or ""
    et = end_time or ""

    if not mft_ecmd_bin:
        # Fallback: filesystem timestamp scan works even without an accessible $MFT
        return _filesystem_timeline_fallback(
            run_id, evidence_root, mft or evidence_root, pf, st, et,
            max_records, max_str_len, ledger_seq
        )

    if not mft:
        return tool_error_result(
            "mft.timeline", run_id, str(evidence_root),
            "$MFT not found. Provide mft_path or ensure evidence root contains $MFT"
        )

    warnings: list[str] = []
    all_raw = b""

    stdout, stderr, rc = run_tool_subprocess(
        [mft_ecmd_bin, "-f", str(mft), "--csv", "--csvf", "/dev/stdout", "-q"],
        evidence_root, timeout,
    )
    all_raw = stdout

    if rc != 0 or not stdout:
        return tool_error_result(
            "mft.timeline", run_id, str(mft),
            f"MFTECmd failed rc={rc}",
            stderr,
        )

    records, warns = _parse_mftecmd_csv(stdout, pf, st, et, max_str_len)
    warnings.extend(warns)

    if path_filter and not records:
        warnings.append(f"No MFT entries matching path_filter='{path_filter}' in time window")

    final_records, truncated = truncate_records(records, max_records, warnings)

    return ParseResult(
        tool="mft.timeline",
        run_id=run_id,
        seq=ledger_seq,
        records=final_records,
        artifact_path=str(mft),
        offset=0,
        raw_output_sha256=hash_raw(all_raw),
        parse_quality=0.95,
        warnings=warnings,
        truncated=truncated,
    )
