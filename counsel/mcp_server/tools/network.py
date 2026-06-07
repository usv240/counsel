"""
T9: net.flows(filter)
Evidentiary meaning: C2_communication, exfiltration (corroborates memory netscan)

Wraps tshark (Wireshark CLI) or Zeek log parser on SIFT.
Parses PCAP/PCAPNG files into flow-level records — never dumps raw packet bytes.
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

_LOCAL_NETS = re.compile(
    r"^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|::1|fe80:)"
)

PCAP_EXTENSIONS = ("*.pcap", "*.pcapng", "*.cap")


def _find_pcap(evidence_root: Path, pcap_path: Optional[str]) -> Optional[Path]:
    if pcap_path:
        p = evidence_root / pcap_path.lstrip("/\\")
        return p if p.exists() else None
    for ext in PCAP_EXTENSIONS:
        candidates = list(evidence_root.rglob(ext))
        if candidates:
            return candidates[0]
    return None


def _parse_tshark_json(raw: bytes, src_filter: str, dst_filter: str, max_str: int) -> tuple[list[dict], list[str]]:
    """Parse tshark -T json output into flow records."""
    records: list[dict] = []
    warnings: list[str] = []
    try:
        packets = json.loads(raw.decode("utf-8", errors="replace"))
        for pkt in packets:
            layers = pkt.get("_source", {}).get("layers", {})
            ip = layers.get("ip", {})
            tcp = layers.get("tcp", {})
            udp = layers.get("udp", {})
            dns = layers.get("dns", {})
            http = layers.get("http", {})
            tls = layers.get("tls", {})

            src = sanitize_string(ip.get("ip.src", ""), 48)
            dst = sanitize_string(ip.get("ip.dst", ""), 48)
            sport = sanitize_string(tcp.get("tcp.srcport", "") or udp.get("udp.srcport", ""), 8)
            dport = sanitize_string(tcp.get("tcp.dstport", "") or udp.get("udp.dstport", ""), 8)
            proto = "TCP" if tcp else ("UDP" if udp else "OTHER")
            ts = sanitize_string(layers.get("frame", {}).get("frame.time_epoch", ""), 32)

            # Apply filters
            if src_filter and src_filter not in src and src_filter not in dst:
                continue
            if dst_filter and dst_filter not in dst and dst_filter not in src:
                continue

            sni = sanitize_string(
                tls.get("tls.handshake.extensions_server_name", ""), max_str
            )
            http_host = sanitize_string(http.get("http.host", ""), max_str)
            dns_query = sanitize_string(dns.get("dns.qry.name", ""), max_str)

            records.append({
                "ts": ts,
                "src": src,
                "sport": sport,
                "dst": dst,
                "dport": dport,
                "proto": proto,
                "bytes": sanitize_string(layers.get("frame", {}).get("frame.len", ""), 16),
                "sni": sni,
                "http_host": http_host,
                "dns_query": dns_query,
                "is_external": not _LOCAL_NETS.match(dst) if dst else True,
            })
    except json.JSONDecodeError as e:
        warnings.append(f"tshark JSON parse error: {e}")
    return records, warnings


def _parse_zeek_conn_log(raw: bytes, src_filter: str, dst_filter: str, max_str: int) -> tuple[list[dict], list[str]]:
    """Parse Zeek conn.log TSV into flow records."""
    records: list[dict] = []
    warnings: list[str] = []
    text = raw.decode("utf-8", errors="replace")
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 9:
            continue
        ts, uid, src, sport, dst, dport, proto = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
        src = sanitize_string(src, 48)
        dst = sanitize_string(dst, 48)

        if src_filter and src_filter not in src and src_filter not in dst:
            continue
        if dst_filter and dst_filter not in dst:
            continue

        records.append({
            "ts": sanitize_string(ts, 32),
            "src": src,
            "sport": sanitize_string(sport, 8),
            "dst": dst,
            "dport": sanitize_string(dport, 8),
            "proto": sanitize_string(proto, 8).upper(),
            "bytes": sanitize_string(parts[9] if len(parts) > 9 else "", 16),
            "sni": "",
            "http_host": "",
            "dns_query": "",
            "is_external": not _LOCAL_NETS.match(dst) if dst else True,
        })
    return records, warnings


def flows(
    run_id: str,
    evidence_root: Path,
    src_filter: Optional[str] = None,
    dst_filter: Optional[str] = None,
    port_filter: Optional[int] = None,
    exclude_local: bool = True,
    pcap_path: Optional[str] = None,
    tshark_bin: str = "",
    zeek_bin: str = "",
    max_records: int = 200,
    max_str_len: int = 512,
    timeout: int = 120,
    ledger_seq: int = 0,
) -> ParseResult:
    """
    T9: Extract network flows from PCAP/PCAPNG evidence.

    src_filter: optional source IP substring
    dst_filter: optional destination IP/domain substring
    port_filter: optional destination port filter
    exclude_local: filter out RFC1918/loopback traffic

    Typed output per record:
        ts, src, sport, dst, dport, proto, bytes, sni, http_host, dns_query, is_external
    """
    pcap = _find_pcap(evidence_root, pcap_path)
    if not pcap:
        return tool_error_result("net.flows", run_id, str(evidence_root),
                                 "No PCAP file found. Provide pcap_path.")

    sf = src_filter or ""
    df = dst_filter or ""
    warnings: list[str] = []
    all_raw = b""
    records: list[dict] = []
    quality = 1.0

    if tshark_bin:
        display_filter = []
        if port_filter:
            display_filter = ["-Y", f"tcp.port == {port_filter} || udp.port == {port_filter}"]

        stdout, stderr, rc = run_tool_subprocess(
            [tshark_bin, "-r", str(pcap), "-T", "json",
             "-e", "ip.src", "-e", "ip.dst",
             "-e", "tcp.srcport", "-e", "tcp.dstport",
             "-e", "udp.srcport", "-e", "udp.dstport",
             "-e", "frame.time_epoch", "-e", "frame.len",
             "-e", "tls.handshake.extensions_server_name",
             "-e", "http.host", "-e", "dns.qry.name",
             ] + display_filter,
            evidence_root, timeout,
        )
        all_raw = stdout
        if rc == 0 and stdout:
            recs, warns = _parse_tshark_json(stdout, sf, df, max_str_len)
            records.extend(recs)
            warnings.extend(warns)
        else:
            warnings.append(f"tshark failed rc={rc}: {sanitize_string(stderr.decode('utf-8', errors='replace')[:100])}")
            quality -= 0.3

    elif zeek_bin:
        # Run Zeek and parse conn.log
        stdout, stderr, rc = run_tool_subprocess(
            [zeek_bin, "-r", str(pcap)],
            evidence_root, timeout,
        )
        conn_log = evidence_root / "conn.log"
        if conn_log.exists():
            all_raw = conn_log.read_bytes()
            recs, warns = _parse_zeek_conn_log(all_raw, sf, df, max_str_len)
            records.extend(recs)
            warnings.extend(warns)
        else:
            warnings.append("Zeek ran but conn.log not found")
            quality -= 0.2
    else:
        return tool_error_result("net.flows", run_id, str(pcap),
                                 "No network analysis tool configured. "
                                 "Set COUNSEL_TSHARK_BIN or COUNSEL_ZEEK_BIN.")

    # Apply exclusion filter post-parse
    if exclude_local:
        records = [r for r in records if r.get("is_external", True)]

    final_records, truncated = truncate_records(records, max_records, warnings)
    return ParseResult(
        tool="net.flows", run_id=run_id, seq=ledger_seq,
        records=final_records, artifact_path=str(pcap), offset=0,
        raw_output_sha256=hash_raw(all_raw) if all_raw else hash_raw(b"empty"),
        parse_quality=max(0.0, quality), warnings=warnings, truncated=truncated,
    )
