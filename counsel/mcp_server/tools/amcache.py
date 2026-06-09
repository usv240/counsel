"""
T3: amcache.lookup(name|sha1)
Evidentiary meaning: payload_executed (medium, independent of Prefetch)

Wraps Eric Zimmerman's AmcacheParser.exe on SIFT Workstation.
Independence note: Amcache is written by the Windows OS kernel loader, completely
independent of the Prefetch subsystem - a corroborating signal with a different
code path means a single compromised artifact cannot fake both.
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

AMCACHE_CANDIDATES = [
    "Windows/AppCompat/Programs/Amcache.hve",
    "WINDOWS/AppCompat/Programs/Amcache.hve",
    "Windows/AppCompat/Programs/amcache.hve",
]


def _find_amcache(evidence_root: Path) -> Optional[Path]:
    for rel in AMCACHE_CANDIDATES:
        p = evidence_root / rel
        if p.exists():
            return p
    return None


def _parse_amcache_csv(raw: bytes, name_filter: str, sha1_filter: str, max_str: int) -> tuple[list[dict], list[str]]:
    records: list[dict] = []
    warnings: list[str] = []
    text = raw.decode("utf-8", errors="replace")

    # AmcacheParser produces multiple CSV files; we parse the InventoryApplicationFile
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        path = sanitize_string(row.get("FullPath", "") or row.get("FilePath", ""), max_str)
        sha1 = sanitize_string(row.get("SHA1", "") or row.get("Sha1", ""), 64).lower()
        name = sanitize_string(row.get("Name", "") or row.get("FileName", ""), max_str)
        first_seen = sanitize_string(row.get("FileKeyLastWriteTimestamp", "") or row.get("FirstSeen", ""), 64)

        # Apply filters
        name_match = not name_filter or name_filter.lower() in name.lower() or name_filter.lower() in path.lower()
        sha1_match = not sha1_filter or sha1_filter.lower() == sha1

        if not (name_match and sha1_match):
            continue

        records.append({
            "path": path,
            "sha1": sha1,
            "name": name,
            "first_seen": first_seen,
            "company": sanitize_string(row.get("Publisher", "") or row.get("CompanyName", ""), max_str),
            "description": sanitize_string(row.get("Description", ""), max_str),
            "product_version": sanitize_string(row.get("ProductVersion", ""), 64),
            "file_size": _safe_int(row.get("FileSize", 0) or row.get("Size", 0)),
            "linked_pe": bool(sha1),   # Amcache records SHA1 only for actual PE execution
        })
    return records, warnings


def _parse_amcache_json(raw: bytes, name_filter: str, sha1_filter: str, max_str: int) -> tuple[list[dict], list[str]]:
    records: list[dict] = []
    warnings: list[str] = []
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        entries = data if isinstance(data, list) else data.get("entries", [data])
        for entry in entries:
            path = sanitize_string(entry.get("FullPath", "") or entry.get("FilePath", ""), max_str)
            sha1 = sanitize_string(entry.get("SHA1", ""), 64).lower()
            name = sanitize_string(entry.get("Name", ""), max_str)

            name_match = not name_filter or name_filter.lower() in name.lower()
            sha1_match = not sha1_filter or sha1_filter.lower() == sha1

            if not (name_match and sha1_match):
                continue

            records.append({
                "path": path,
                "sha1": sha1,
                "name": name,
                "first_seen": sanitize_string(entry.get("FileKeyLastWriteTimestamp", ""), 64),
                "company": sanitize_string(entry.get("Publisher", ""), max_str),
                "description": sanitize_string(entry.get("Description", ""), max_str),
                "product_version": sanitize_string(entry.get("ProductVersion", ""), 64),
                "file_size": _safe_int(entry.get("FileSize", 0)),
                "linked_pe": bool(sha1),
            })
    except json.JSONDecodeError as e:
        warnings.append(f"AmcacheParser JSON error: {e}")
    return records, warnings


def _safe_int(v: object) -> int:
    try:
        return int(str(v).strip())
    except (ValueError, TypeError):
        return 0


def lookup(
    run_id: str,
    evidence_root: Path,
    name: Optional[str] = None,
    sha1: Optional[str] = None,
    amcache_parser_bin: str = "",
    max_records: int = 200,
    max_str_len: int = 512,
    timeout: int = 120,
    ledger_seq: int = 0,
) -> ParseResult:
    """
    T3: Look up executables in Amcache.hve - independent of Prefetch.

    name: optional executable name filter (e.g. "svchost.exe")
    sha1: optional SHA1 hash filter

    Typed output per record:
        path, sha1, name, first_seen, company, description,
        product_version, file_size, linked_pe
    """
    fixture = load_fixture_result("amcache_lookup", run_id, str(evidence_root))
    if fixture is not None:
        return fixture

    amcache_path = _find_amcache(evidence_root)
    if not amcache_path:
        return tool_error_result(
            "amcache.lookup", run_id, str(evidence_root),
            "Amcache.hve not found. Expected at Windows/AppCompat/Programs/Amcache.hve"
        )

    if not amcache_parser_bin:
        return tool_error_result(
            "amcache.lookup", run_id, str(amcache_path),
            "AmcacheParser binary not configured. "
            "Set COUNSEL_AMCACHE_BIN or install: https://github.com/EricZimmerman/AmcacheParser"
        )

    warnings: list[str] = []
    all_raw = b""
    quality = 1.0
    name_filter = name or ""
    sha1_filter = sha1 or ""

    # Run AmcacheParser with CSV output
    stdout, stderr, rc = run_tool_subprocess(
        [amcache_parser_bin, "-f", str(amcache_path),
         "--csv", "--csvf", "/tmp/counsel_amcache", "-q"],
        evidence_root, timeout,
    )
    all_raw += stdout + stderr

    records: list[dict] = []

    if rc == 0:
        # AmcacheParser writes multiple CSV files; read the InventoryApplicationFile one
        csv_files = list(Path("/tmp").glob("counsel_amcache*InventoryApplicationFile*.csv"))
        if not csv_files:
            # Try reading stdout directly
            recs, warns = _parse_amcache_csv(stdout, name_filter, sha1_filter, max_str_len)
            records.extend(recs)
            warnings.extend(warns)
        else:
            for csv_file in csv_files:
                raw = csv_file.read_bytes()
                recs, warns = _parse_amcache_csv(raw, name_filter, sha1_filter, max_str_len)
                records.extend(recs)
                warnings.extend(warns)
                all_raw += raw
    else:
        # Try JSON format
        stdout_j, stderr_j, rc_j = run_tool_subprocess(
            [amcache_parser_bin, "-f", str(amcache_path), "--json", "/dev/stdout"],
            evidence_root, timeout,
        )
        if rc_j == 0 and stdout_j:
            recs, warns = _parse_amcache_json(stdout_j, name_filter, sha1_filter, max_str_len)
            records.extend(recs)
            warnings.extend(warns)
            all_raw += stdout_j
        else:
            warnings.append(
                f"AmcacheParser failed: rc={rc} "
                f"stderr={sanitize_string(stderr.decode('utf-8', errors='replace')[:150])}"
            )
            quality = 0.0

    final_records, truncated = truncate_records(records, max_records, warnings)

    return ParseResult(
        tool="amcache.lookup",
        run_id=run_id,
        seq=ledger_seq,
        records=final_records,
        artifact_path=str(amcache_path),
        offset=0,
        raw_output_sha256=hash_raw(all_raw) if all_raw else hash_raw(b"empty"),
        parse_quality=max(0.0, quality),
        warnings=warnings,
        truncated=truncated,
    )
