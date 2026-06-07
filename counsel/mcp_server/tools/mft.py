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
    mft = _find_mft(evidence_root, mft_path)
    if not mft:
        return tool_error_result(
            "mft.timeline", run_id, str(evidence_root),
            "$MFT not found. Provide mft_path or ensure evidence root contains $MFT"
        )

    if not mft_ecmd_bin:
        return tool_error_result(
            "mft.timeline", run_id, str(mft),
            "MFTECmd binary not configured. "
            "Set COUNSEL_MFTECMD_BIN or install: https://github.com/EricZimmerman/MFTECmd"
        )

    warnings: list[str] = []
    all_raw = b""
    pf = path_filter or ""
    st = start_time or ""
    et = end_time or ""

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
