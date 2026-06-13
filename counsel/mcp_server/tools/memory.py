"""
T7: mem.pslist()     - payload_active (strong)
T7: mem.netscan()    - C2/exfil corroboration
T8: mem.malfind()    - injected code detection

All three wrap Volatility 3 on SIFT Workstation.
Memory artifacts are independent of disk artifacts - corroboration across
disk+memory is the strongest possible evidence chain.
"""
from __future__ import annotations

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

# Private/RFC1918 + loopback (non-suspicious by default)
_LOCAL_NETS = re.compile(
    r"^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|::1|fe80:)"
)


def _run_vol(
    vol_bin: str,
    memory_image: Path,
    plugin: str,
    extra_args: list[str],
    evidence_root: Path,
    timeout: int,
) -> tuple[bytes, bytes, int]:
    return run_tool_subprocess(
        [vol_bin, "-f", str(memory_image), plugin, "--output=json"] + extra_args,
        evidence_root,
        timeout,
    )


def _find_memory_image(evidence_root: Path, image_path: Optional[str]) -> Optional[Path]:
    if image_path:
        p = Path(image_path)
        if p.is_absolute():
            return p if p.exists() else None
        p = evidence_root / image_path.lstrip("/\\")
        return p if p.exists() else None
    for ext in ("*.raw", "*.img", "*.vmem", "*.mem", "*.dmp"):
        candidates = list(evidence_root.glob(ext))
        if candidates:
            return candidates[0]
    return None


def _parse_vol_json(raw: bytes, max_str: int) -> tuple[list[dict], list[str]]:
    """Parse Volatility 3 JSON output into normalized records."""
    records: list[dict] = []
    warnings: list[str] = []
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        rows = data.get("rows", []) if isinstance(data, dict) else data
        columns = data.get("columns", []) if isinstance(data, dict) else []
        for row in rows:
            if isinstance(row, dict):
                records.append({k: sanitize_string(v, max_str) for k, v in row.items()})
            elif isinstance(row, list) and columns:
                records.append({
                    col: sanitize_string(val, max_str)
                    for col, val in zip(columns, row)
                })
    except json.JSONDecodeError as e:
        warnings.append(f"Volatility JSON parse error: {e}")
    return records, warnings


# ─── T7a: pslist ─────────────────────────────────────────────────────────────

def pslist(
    run_id: str,
    evidence_root: Path,
    image_path: Optional[str] = None,
    name_filter: Optional[str] = None,
    vol_bin: str = "",
    max_records: int = 200,
    max_str_len: int = 512,
    timeout: int = 300,
    ledger_seq: int = 0,
) -> ParseResult:
    """
    T7a: List processes from memory image.

    Typed output per record:
        pid, ppid, name, path, create_time, exit_time, threads, handles
    """
    fixture = load_fixture_result("mem_pslist", run_id, str(evidence_root), artifact_name="mem.pslist")
    if fixture is not None:
        return fixture

    mem = _find_memory_image(evidence_root, image_path)
    if not mem:
        return tool_error_result("mem.pslist", run_id, str(evidence_root),
                                 "No memory image found. Provide image_path.")
    if not vol_bin:
        return tool_error_result("mem.pslist", run_id, str(mem),
                                 "Volatility binary not configured. Set COUNSEL_VOL_BIN.")

    stdout, stderr, rc = _run_vol(vol_bin, mem, "windows.pslist.PsList", [], evidence_root, timeout)
    if rc != 0 or not stdout:
        return tool_error_result("mem.pslist", run_id, str(mem),
                                 f"pslist failed rc={rc}", stderr)

    raw_records, warns = _parse_vol_json(stdout, max_str_len)

    # Normalize Volatility column names → typed fields
    records: list[dict] = []
    for r in raw_records:
        name = sanitize_string(r.get("ImageFileName", r.get("Name", "")), max_str_len)
        if name_filter and name_filter.lower() not in name.lower():
            continue
        records.append({
            "pid": sanitize_string(r.get("PID", r.get("pid", "")), 16),
            "ppid": sanitize_string(r.get("PPID", r.get("ppid", "")), 16),
            "name": name,
            "path": sanitize_string(r.get("ImagePathName", r.get("path", "")), max_str_len),
            "create_time": sanitize_string(r.get("CreateTime", ""), 64),
            "exit_time": sanitize_string(r.get("ExitTime", ""), 64),
            "threads": sanitize_string(r.get("Threads", ""), 16),
            "handles": sanitize_string(r.get("Handles", ""), 16),
        })

    final_records, truncated = truncate_records(records, max_records, warns)
    return ParseResult(
        tool="mem.pslist", run_id=run_id, seq=ledger_seq,
        records=final_records, artifact_path=str(mem), offset=0,
        raw_output_sha256=hash_raw(stdout), parse_quality=0.9,
        warnings=warns, truncated=truncated,
    )


# ─── T7b: netscan ────────────────────────────────────────────────────────────

def netscan(
    run_id: str,
    evidence_root: Path,
    image_path: Optional[str] = None,
    remote_filter: Optional[str] = None,
    exclude_local: bool = True,
    vol_bin: str = "",
    max_records: int = 200,
    max_str_len: int = 512,
    timeout: int = 300,
    ledger_seq: int = 0,
) -> ParseResult:
    """
    T7b: Scan memory for network connections.

    remote_filter: optional remote IP/domain substring filter
    exclude_local: if True, filter out loopback/RFC1918 connections

    Typed output per record:
        pid, name, laddr, lport, raddr, rport, state, proto, create_time
    """
    fixture = load_fixture_result("mem_netscan", run_id, str(evidence_root), artifact_name="mem.netscan")
    if fixture is not None:
        return fixture

    mem = _find_memory_image(evidence_root, image_path)
    if not mem:
        return tool_error_result("mem.netscan", run_id, str(evidence_root),
                                 "No memory image found. Provide image_path.")
    if not vol_bin:
        return tool_error_result("mem.netscan", run_id, str(mem),
                                 "Volatility binary not configured.")

    stdout, stderr, rc = _run_vol(vol_bin, mem, "windows.netstat.NetStat", [], evidence_root, timeout)
    if rc != 0 or not stdout:
        # Fallback to netscan plugin
        stdout, stderr, rc = _run_vol(vol_bin, mem, "windows.netscan.NetScan", [], evidence_root, timeout)

    if rc != 0 or not stdout:
        return tool_error_result("mem.netscan", run_id, str(mem),
                                 f"netscan/netstat failed rc={rc}", stderr)

    raw_records, warns = _parse_vol_json(stdout, max_str_len)

    records: list[dict] = []
    for r in raw_records:
        raddr = sanitize_string(r.get("ForeignAddr", r.get("raddr", "")), max_str_len)
        laddr = sanitize_string(r.get("LocalAddr", r.get("laddr", "")), max_str_len)

        if exclude_local and _LOCAL_NETS.match(raddr):
            continue
        if remote_filter and remote_filter not in raddr:
            continue

        records.append({
            "pid": sanitize_string(r.get("PID", ""), 16),
            "name": sanitize_string(r.get("Owner", r.get("name", "")), max_str_len),
            "laddr": laddr,
            "lport": sanitize_string(r.get("LocalPort", ""), 8),
            "raddr": raddr,
            "rport": sanitize_string(r.get("ForeignPort", ""), 8),
            "state": sanitize_string(r.get("State", ""), 32),
            "proto": sanitize_string(r.get("Proto", ""), 8),
            "create_time": sanitize_string(r.get("CreateTime", ""), 64),
        })

    final_records, truncated = truncate_records(records, max_records, warns)
    return ParseResult(
        tool="mem.netscan", run_id=run_id, seq=ledger_seq,
        records=final_records, artifact_path=str(mem), offset=0,
        raw_output_sha256=hash_raw(stdout), parse_quality=0.85,
        warnings=warns, truncated=truncated,
    )


# ─── T8: malfind ─────────────────────────────────────────────────────────────

def malfind(
    run_id: str,
    evidence_root: Path,
    image_path: Optional[str] = None,
    pid_filter: Optional[str] = None,
    vol_bin: str = "",
    max_records: int = 100,
    max_str_len: int = 512,
    timeout: int = 300,
    ledger_seq: int = 0,
) -> ParseResult:
    """
    T8: Find injected memory regions using malfind heuristics.

    Typed output per record:
        pid, name, address, size, protection, vad_tag, hexdump_preview
    """
    fixture = load_fixture_result("mem_malfind", run_id, str(evidence_root), artifact_name="mem.malfind")
    if fixture is not None:
        return fixture

    mem = _find_memory_image(evidence_root, image_path)
    if not mem:
        return tool_error_result("mem.malfind", run_id, str(evidence_root),
                                 "No memory image found.")
    if not vol_bin:
        return tool_error_result("mem.malfind", run_id, str(mem),
                                 "Volatility binary not configured.")

    extra = ["--pid", str(pid_filter)] if pid_filter else []
    stdout, stderr, rc = _run_vol(vol_bin, mem, "windows.malfind.Malfind", extra, evidence_root, timeout)

    if rc != 0 or not stdout:
        return tool_error_result("mem.malfind", run_id, str(mem),
                                 f"malfind failed rc={rc}", stderr)

    raw_records, warns = _parse_vol_json(stdout, max_str_len)

    records: list[dict] = []
    for r in raw_records:
        if pid_filter and str(r.get("PID", "")) != str(pid_filter):
            continue
        records.append({
            "pid": sanitize_string(r.get("PID", ""), 16),
            "name": sanitize_string(r.get("Process", r.get("name", "")), max_str_len),
            "address": sanitize_string(r.get("Start VPN", r.get("address", "")), 24),
            "size": sanitize_string(r.get("Size", ""), 16),
            "protection": sanitize_string(r.get("Protection", r.get("Tag", "")), 16),
            "vad_tag": sanitize_string(r.get("Tag", ""), 16),
            "hexdump_preview": sanitize_string(r.get("Hexdump", "")[:128], 256),
        })

    final_records, truncated = truncate_records(records, max_records, warns)
    return ParseResult(
        tool="mem.malfind", run_id=run_id, seq=ledger_seq,
        records=final_records, artifact_path=str(mem), offset=0,
        raw_output_sha256=hash_raw(stdout), parse_quality=0.8,
        warnings=warns, truncated=truncated,
    )
