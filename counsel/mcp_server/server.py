"""
COUNSEL MCP Server - the trust boundary between forensic tools and the agent.

Architecture guarantees (enforced here, not in prompts):
  B1: Agent reaches evidence ONLY through typed MCP functions (no shell, no file read)
  B2: Every call is logged to the ledger before returning to agent
  B3: Agent cannot write, execute, or sign - MCP server is read-only

Uses FastMCP for clean tool registration. All tools are typed functions.
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

from .config import ServerConfig
from .tools import amcache, evtx, filesystem, memory, mft, network, prefetch, registry
from .tools import yara_scan as yara_scan_tool

logger = logging.getLogger("counsel.mcp_server")

mcp = FastMCP(
    "counsel",
    instructions="COUNSEL - Corroboration-First DFIR MCP Server. "
    "All tools are read-only, parse-before-return, and append to the audit ledger.",
)

_config: ServerConfig = None  # type: ignore[assignment]
_ledger = None                # lazy import to avoid circular

# ─── Ledger integration ───────────────────────────────────────────────────────

def _get_ledger():
    global _ledger
    if _ledger is None:
        from ..ledger.ledger import Ledger
        _ledger = Ledger(
            ledger_path=_config.ledger_path,
            run_id=_config.run_id,
        )
    return _ledger


def _log_and_return(result) -> dict:
    """Append MCP result to the audit ledger and return it as a dict."""
    ledger = _get_ledger()
    seq = ledger.append_tool_call(result)
    result.seq = seq
    return result.to_dict()


# ─── T1: Registry Run Keys ───────────────────────────────────────────────────

@mcp.tool()
def registry_run_keys(
    hive_paths: list[str],
) -> dict:
    """
    T1 - registry.run_keys: Extract Run/RunOnce persistence registry keys.

    Args:
        hive_paths: List of registry hive paths relative to the evidence root.
                    Example: ["Windows/System32/config/SOFTWARE",
                              "Users/Rick/NTUSER.DAT"]

    Returns typed records:
        hive, key, value_name, command, last_write, suspicion_score
    Evidentiary claim: persistence_configured
    """
    result = registry.run_keys(
        run_id=_config.run_id,
        evidence_root=_config.evidence_root,
        hive_paths=hive_paths,
        recmd_bin=_config.tools.recmd,
        regipy_bin="regipy",
        max_records=_config.max_records_per_call,
        max_str_len=_config.max_string_length,
        timeout=_config.tool_timeout_seconds,
    )
    return _log_and_return(result)


# ─── T2: Prefetch ────────────────────────────────────────────────────────────

@mcp.tool()
def prefetch_run_record(
    name: Optional[str] = None,
) -> dict:
    """
    T2 - prefetch.run_record: Parse Windows Prefetch files for execution evidence.

    Args:
        name: Optional executable name filter (e.g., "svchost.exe").
              If omitted, parses all .pf files.

    Returns typed records:
        exe, hash, run_count, last_run, all_runs, volume, pf_path
    Evidentiary claim: payload_executed (strong - direct execution evidence)
    Independence: written by Prefetch subsystem, independent of Amcache
    """
    result = prefetch.run_record(
        run_id=_config.run_id,
        evidence_root=_config.evidence_root,
        name=name,
        pecmd_bin=_config.tools.pecmd,
        max_records=_config.max_records_per_call,
        max_str_len=_config.max_string_length,
        timeout=_config.tool_timeout_seconds,
    )
    return _log_and_return(result)


# ─── T3: Amcache ─────────────────────────────────────────────────────────────

@mcp.tool()
def amcache_lookup(
    name: Optional[str] = None,
    sha1: Optional[str] = None,
) -> dict:
    """
    T3 - amcache.lookup: Look up executables in Amcache.hve.

    Args:
        name: Optional executable name filter.
        sha1: Optional SHA1 hash to look up.

    Returns typed records:
        path, sha1, name, first_seen, company, description, file_size, linked_pe
    Evidentiary claim: payload_executed (medium)
    Independence: written by Windows kernel loader, independent of Prefetch
    """
    result = amcache.lookup(
        run_id=_config.run_id,
        evidence_root=_config.evidence_root,
        name=name,
        sha1=sha1,
        amcache_parser_bin=_config.tools.amcache_parser,
        max_records=_config.max_records_per_call,
        max_str_len=_config.max_string_length,
        timeout=_config.tool_timeout_seconds,
    )
    return _log_and_return(result)


# ─── T4: Filesystem stat + hash ──────────────────────────────────────────────

@mcp.tool()
def fs_stat_hash(
    file_path: str,
) -> dict:
    """
    T4 - fs.stat_hash: Stat and SHA256-hash a file in the evidence image.

    Args:
        file_path: Path relative to evidence root (e.g., "Users/Rick/AppData/Local/Temp/evil.exe")

    Returns one record:
        path, exists, size, sha256, mtime, atime, ctime, mode, signed, signer
    Evidentiary claim: payload_present (exists=True) or contradiction (exists=False)
    Note: signed=True is a modifier - LOLBin/signed-proxy abuse still possible
    """
    result = filesystem.stat_hash(
        run_id=_config.run_id,
        evidence_root=_config.evidence_root,
        file_path=file_path,
        max_str_len=_config.max_string_length,
        timeout=_config.tool_timeout_seconds,
    )
    return _log_and_return(result)


# ─── T5: MFT Timeline ────────────────────────────────────────────────────────

@mcp.tool()
def mft_timeline(
    path_filter: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    mft_path: Optional[str] = None,
) -> dict:
    """
    T5 - mft.timeline: Extract NTFS MFT timeline entries.

    Args:
        path_filter: Optional path substring filter (e.g., "Temp", "Users\\Rick").
        start_time:  Optional ISO 8601 lower bound (e.g., "2018-08-25T00:00:00Z").
        end_time:    Optional ISO 8601 upper bound.
        mft_path:    Path to $MFT relative to evidence root (auto-detected if None).

    Returns typed records:
        ts, path, action, MACB, source, entry_num, is_deleted, file_size
    Evidentiary claim: timeline backbone
    """
    result = mft.timeline(
        run_id=_config.run_id,
        evidence_root=_config.evidence_root,
        path_filter=path_filter,
        start_time=start_time,
        end_time=end_time,
        mft_path=mft_path,
        mft_ecmd_bin=_config.tools.mft_ecmd,
        max_records=_config.max_records_per_call,
        max_str_len=_config.max_string_length,
        timeout=_config.tool_timeout_seconds,
    )
    return _log_and_return(result)


# ─── T6: YARA Scan ───────────────────────────────────────────────────────────

@mcp.tool()
def yara_scan(
    target_path: str,
    rules_path: Optional[str] = None,
) -> dict:
    """
    T6 - yara.scan: Scan a file or directory with YARA rules.

    Args:
        target_path: Path relative to evidence root.
        rules_path:  Path to .yar rules file/directory. Uses COUNSEL built-in rules if omitted.

    Returns typed records:
        rule, target, strings (list of {offset, var, snippet})
    Evidentiary claim: malware identity
    """
    result = yara_scan_tool.scan(
        run_id=_config.run_id,
        evidence_root=_config.evidence_root,
        target_path=target_path,
        rules_path=rules_path,
        yara_bin=_config.tools.yara,
        max_records=_config.max_records_per_call,
        max_str_len=_config.max_string_length,
        timeout=_config.tool_timeout_seconds,
    )
    return _log_and_return(result)


# ─── T7a: Memory Process List ────────────────────────────────────────────────

@mcp.tool()
def mem_pslist(
    image_path: Optional[str] = None,
    name_filter: Optional[str] = None,
) -> dict:
    """
    T7a - mem.pslist: List processes from a memory image.

    Args:
        image_path:  Path to memory image relative to evidence root (auto-detected if None).
        name_filter: Optional process name substring filter.

    Returns typed records:
        pid, ppid, name, path, create_time, exit_time, threads, handles
    Evidentiary claim: payload_active (strong - live process in memory)
    Independence: memory artifacts are independent of disk artifacts
    """
    result = memory.pslist(
        run_id=_config.run_id,
        evidence_root=_config.evidence_root,
        image_path=image_path,
        name_filter=name_filter,
        vol_bin=_config.tools.volatility,
        max_records=_config.max_records_per_call,
        max_str_len=_config.max_string_length,
        timeout=_config.tool_timeout_seconds,
    )
    return _log_and_return(result)


# ─── T7b: Memory Network Scan ────────────────────────────────────────────────

@mcp.tool()
def mem_netscan(
    image_path: Optional[str] = None,
    remote_filter: Optional[str] = None,
    exclude_local: bool = True,
) -> dict:
    """
    T7b - mem.netscan: Scan memory for network connections.

    Args:
        image_path:    Path to memory image (auto-detected if None).
        remote_filter: Optional remote IP/domain substring filter.
        exclude_local: If True, filter out loopback and RFC1918 connections.

    Returns typed records:
        pid, name, laddr, lport, raddr, rport, state, proto, create_time
    Evidentiary claim: C2_communication, payload_active
    """
    result = memory.netscan(
        run_id=_config.run_id,
        evidence_root=_config.evidence_root,
        image_path=image_path,
        remote_filter=remote_filter,
        exclude_local=exclude_local,
        vol_bin=_config.tools.volatility,
        max_records=_config.max_records_per_call,
        max_str_len=_config.max_string_length,
        timeout=_config.tool_timeout_seconds,
    )
    return _log_and_return(result)


# ─── T8: Malfind ─────────────────────────────────────────────────────────────

@mcp.tool()
def mem_malfind(
    image_path: Optional[str] = None,
    pid_filter: Optional[str] = None,
) -> dict:
    """
    T8 - mem.malfind: Find injected memory regions using Volatility malfind.

    Args:
        image_path: Path to memory image (auto-detected if None).
        pid_filter: Optional PID to restrict scan to one process.

    Returns typed records:
        pid, name, address, size, protection, vad_tag, hexdump_preview
    Evidentiary claim: defense_evasion (process injection)
    """
    result = memory.malfind(
        run_id=_config.run_id,
        evidence_root=_config.evidence_root,
        image_path=image_path,
        pid_filter=pid_filter,
        vol_bin=_config.tools.volatility,
        max_records=_config.max_records_per_call,
        max_str_len=_config.max_string_length,
        timeout=_config.tool_timeout_seconds,
    )
    return _log_and_return(result)


# ─── T9: Network Flows ───────────────────────────────────────────────────────

@mcp.tool()
def net_flows(
    src_filter: Optional[str] = None,
    dst_filter: Optional[str] = None,
    port_filter: Optional[int] = None,
    exclude_local: bool = True,
    pcap_path: Optional[str] = None,
) -> dict:
    """
    T9 - net.flows: Extract network flows from PCAP evidence.

    Args:
        src_filter:   Optional source IP substring.
        dst_filter:   Optional destination IP/domain substring.
        port_filter:  Optional destination port (integer).
        exclude_local: Filter out RFC1918/loopback traffic.
        pcap_path:    Path to PCAP file (auto-detected if None).

    Returns typed records:
        ts, src, sport, dst, dport, proto, bytes, sni, http_host, dns_query, is_external
    Evidentiary claim: C2_communication, exfiltration
    """
    result = network.flows(
        run_id=_config.run_id,
        evidence_root=_config.evidence_root,
        src_filter=src_filter,
        dst_filter=dst_filter,
        port_filter=port_filter,
        exclude_local=exclude_local,
        pcap_path=pcap_path,
        tshark_bin=_config.tools.tshark,
        zeek_bin=_config.tools.zeek,
        max_records=_config.max_records_per_call,
        max_str_len=_config.max_string_length,
        timeout=_config.tool_timeout_seconds,
    )
    return _log_and_return(result)


# ─── T10: Event Log Query ────────────────────────────────────────────────────

@mcp.tool()
def evtx_query(
    channel: str = "Security",
    eid: Optional[int] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    keyword: Optional[str] = None,
    evtx_path: Optional[str] = None,
) -> dict:
    """
    T10 - evtx.query: Query Windows Event Logs.

    Args:
        channel:    Log channel: Security | System | Application | PowerShell | TaskScheduler | WMI
        eid:        Optional Event ID filter (e.g., 4688 for process creation).
        start_time: Optional ISO 8601 lower bound.
        end_time:   Optional ISO 8601 upper bound.
        keyword:    Optional substring to match in event fields.
        evtx_path:  Explicit path to .evtx file (auto-detected by channel if None).

    Returns typed records:
        channel, eid, ts, description, computer, fields (dict of event data)
    Evidentiary claim: logon/service/exec events
    """
    result = evtx.query(
        run_id=_config.run_id,
        evidence_root=_config.evidence_root,
        channel=channel,
        eid=eid,
        start_time=start_time,
        end_time=end_time,
        evtx_path=evtx_path,
        keyword=keyword,
        evtx_dump_bin=_config.tools.evtx_dump,
        max_records=_config.max_records_per_call,
        max_str_len=_config.max_string_length,
        timeout=_config.tool_timeout_seconds,
    )
    return _log_and_return(result)


# ─── Server entrypoint ───────────────────────────────────────────────────────

def init_server(config: ServerConfig) -> None:
    """Initialize the MCP server with a validated config. Call before run()."""
    global _config
    errors = config.validate()
    if errors:
        logger.critical("Config validation failed:\n%s", "\n".join(errors))
        sys.exit(1)
    _config = config
    logger.info(
        "COUNSEL MCP Server initialized - evidence_root=%s run_id=%s",
        config.evidence_root, config.run_id,
    )


def run(config: Optional[ServerConfig] = None) -> None:
    """Run the MCP server over stdio (called by the launcher)."""
    if config is None:
        config = ServerConfig.from_env()
    init_server(config)
    mcp.run()


if __name__ == "__main__":
    run()
