"""
T2: prefetch.run_record(name)
Evidentiary meaning: payload_executed (strong - direct execution evidence)

Wraps Eric Zimmerman's PECmd.exe on SIFT Workstation.
Parse-before-return: returns structured execution records, not raw PECmd output.
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
    load_fixture_result,
    run_tool_subprocess,
    sanitize_string,
    tool_error_result,
    truncate_records,
)

# Windows Prefetch directory (relative to Windows volume root)
PREFETCH_DIR_CANDIDATES = [
    "Windows/Prefetch",
    "WINDOWS/Prefetch",
    "Windows/prefetch",
]


def _find_prefetch_files(evidence_root: Path, name_filter: Optional[str]) -> list[Path]:
    """Locate .pf files matching optional name filter."""
    pf_files: list[Path] = []
    for candidate in PREFETCH_DIR_CANDIDATES:
        pf_dir = evidence_root / candidate
        if pf_dir.exists():
            pattern = f"{name_filter.upper()}*.pf" if name_filter else "*.pf"
            pf_files.extend(pf_dir.glob(pattern))
            break
    return pf_files


def _parse_pecmd_csv(raw: bytes, max_str: int) -> tuple[list[dict], list[str]]:
    """Parse PECmd CSV output into typed run records."""
    records: list[dict] = []
    warnings: list[str] = []
    text = raw.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        # PECmd CSV columns: SourceFilename, SourceCreated, SourceModified,
        #   SourceAccessed, ExecutableName, Hash, Size, Version,
        #   RunCount, LastRun, PreviousRun0..PreviousRun6, Volume0Name, ...
        last_runs = [sanitize_string(row.get("LastRun", ""), 64)]
        for i in range(7):
            v = row.get(f"PreviousRun{i}", "")
            if v:
                last_runs.append(sanitize_string(v, 64))
        last_runs = [lr for lr in last_runs if lr]

        records.append({
            "exe": sanitize_string(row.get("ExecutableName", ""), max_str),
            "hash": sanitize_string(row.get("Hash", ""), 32),
            "run_count": _safe_int(row.get("RunCount", "0")),
            "last_run": last_runs[0] if last_runs else "",
            "all_runs": last_runs,
            "volume": sanitize_string(row.get("Volume0Name", ""), max_str),
            "pf_path": sanitize_string(row.get("SourceFilename", ""), max_str),
            "pf_created": sanitize_string(row.get("SourceCreated", ""), 64),
        })
    return records, warnings


def _parse_pecmd_json(raw: bytes, max_str: int) -> tuple[list[dict], list[str]]:
    """Parse PECmd JSON output (--json flag)."""
    records: list[dict] = []
    warnings: list[str] = []
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        entries = data if isinstance(data, list) else [data]
        for entry in entries:
            runs = entry.get("Timestamps", {})
            last_run = sanitize_string(runs.get("LastRun", ""), 64)
            prev_runs = [sanitize_string(r, 64) for r in runs.get("PreviousRuns", []) if r]
            records.append({
                "exe": sanitize_string(entry.get("ExecutableName", ""), max_str),
                "hash": sanitize_string(entry.get("Hash", ""), 32),
                "run_count": _safe_int(entry.get("RunCount", 0)),
                "last_run": last_run,
                "all_runs": [last_run] + prev_runs if last_run else prev_runs,
                "volume": sanitize_string(
                    (entry.get("VolumesInformation") or [{}])[0].get("VolumeLabel", ""), max_str
                ),
                "pf_path": sanitize_string(entry.get("SourceFilename", ""), max_str),
                "pf_created": sanitize_string(entry.get("SourceCreated", ""), 64),
            })
    except json.JSONDecodeError as e:
        warnings.append(f"PECmd JSON parse error: {e}")
    return records, warnings


def _safe_int(v: object) -> int:
    try:
        return int(str(v).strip())
    except (ValueError, TypeError):
        return 0


def run_record(
    run_id: str,
    evidence_root: Path,
    name: Optional[str] = None,
    pecmd_bin: str = "",
    max_records: int = 200,
    max_str_len: int = 512,
    timeout: int = 120,
    ledger_seq: int = 0,
) -> ParseResult:
    """
    T2: Parse Windows Prefetch files to recover execution evidence.

    name: optional executable name filter (e.g. "svchost.exe")
          If None, parses all .pf files in the Prefetch directory.

    Typed output per record:
        exe, hash, run_count, last_run, all_runs, volume, pf_path, pf_created
    """
    fixture = load_fixture_result("prefetch_run_record", run_id, str(evidence_root), artifact_name="prefetch.run_record")
    if fixture is not None:
        return fixture

    pf_files = _find_prefetch_files(evidence_root, name)

    if not pf_files:
        msg = (
            f"No prefetch files found for '{name}'" if name
            else "Prefetch directory not found or empty"
        )
        return tool_error_result("prefetch.run_record", run_id, str(evidence_root), msg)

    all_records: list[dict] = []
    all_raw = b""
    warnings: list[str] = []
    quality = 1.0

    if not pecmd_bin:
        warnings.append(
            "PECmd binary not configured. "
            "Set COUNSEL_PECMD_BIN or install PECmd on SIFT: "
            "https://github.com/EricZimmerman/PECmd"
        )
        return ParseResult(
            tool="prefetch.run_record", run_id=run_id, seq=ledger_seq,
            records=[], artifact_path=str(evidence_root), offset=0,
            raw_output_sha256=hash_raw(b""),
            parse_quality=0.0, warnings=warnings,
        )

    for pf_path in pf_files:
        stdout, stderr, rc = run_tool_subprocess(
            [pecmd_bin, "-f", str(pf_path), "--csv", "--csvf", "/dev/stdout", "-q"],
            evidence_root, timeout,
        )
        if rc == 0 and stdout:
            recs, warns = _parse_pecmd_csv(stdout, max_str_len)
            all_records.extend(recs)
            warnings.extend(warns)
            all_raw += stdout
        else:
            # Try JSON format
            stdout_j, stderr_j, rc_j = run_tool_subprocess(
                [pecmd_bin, "-f", str(pf_path), "--json", "/dev/stdout"],
                evidence_root, timeout,
            )
            if rc_j == 0 and stdout_j:
                recs, warns = _parse_pecmd_json(stdout_j, max_str_len)
                all_records.extend(recs)
                warnings.extend(warns)
                all_raw += stdout_j
            else:
                warnings.append(
                    f"PECmd failed on {pf_path.name}: rc={rc} "
                    f"stderr={sanitize_string(stderr.decode('utf-8', errors='replace')[:100])}"
                )
                quality -= 0.15

    records, truncated = truncate_records(all_records, max_records, warnings)

    return ParseResult(
        tool="prefetch.run_record",
        run_id=run_id,
        seq=ledger_seq,
        records=records,
        artifact_path=str(evidence_root / "Windows/Prefetch"),
        offset=0,
        raw_output_sha256=hash_raw(all_raw) if all_raw else hash_raw(b"empty"),
        parse_quality=max(0.0, quality),
        warnings=warnings,
        truncated=truncated,
    )
