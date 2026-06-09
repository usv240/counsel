"""
T6: yara.scan(path|pid, rules)
Evidentiary meaning: malware identity confirmation

Wraps the YARA binary on SIFT Workstation.
Returns match records: rule name, matched strings, offsets.
Never returns full file contents or raw binary data.
"""
from __future__ import annotations

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

# Match line: rule_name(meta) /path/to/file
_YARA_MATCH_RE = re.compile(r"^(\S+)\s+(.+)$")
# Match detail: 0x1a2b3c:$var_name: hexdata or string
_YARA_STRING_RE = re.compile(r"0x([0-9a-fA-F]+):\$(\w+):\s*(.{0,80})")


def _parse_yara_output(raw: bytes, max_str: int) -> tuple[list[dict], list[str]]:
    """Parse yara CLI output into match records."""
    records: list[dict] = []
    warnings: list[str] = []
    current: Optional[dict] = None

    for line in raw.decode("utf-8", errors="replace").splitlines():
        line = line.rstrip()
        if not line:
            continue

        string_m = _YARA_STRING_RE.match(line.strip())
        if string_m and current is not None:
            offset_hex, var_name, snippet = string_m.groups()
            current["strings"].append({
                "offset": int(offset_hex, 16),
                "var": sanitize_string(var_name, 64),
                "snippet": sanitize_string(snippet, max_str),
            })
            continue

        match_m = _YARA_MATCH_RE.match(line)
        if match_m:
            if current is not None:
                records.append(current)
            rule_raw, target = match_m.groups()
            rule_name = rule_raw.split("(")[0]
            current = {
                "rule": sanitize_string(rule_name, 128),
                "target": sanitize_string(target, max_str),
                "strings": [],
            }

    if current is not None:
        records.append(current)

    return records, warnings


def scan(
    run_id: str,
    evidence_root: Path,
    target_path: Optional[str] = None,
    rules_path: Optional[str] = None,
    yara_bin: str = "",
    max_records: int = 100,
    max_str_len: int = 256,
    timeout: int = 120,
    ledger_seq: int = 0,
) -> ParseResult:
    """
    T6: Scan a file or directory with YARA rules.

    target_path: path relative to evidence_root (or absolute)
    rules_path:  path to .yar/.yara rules file/directory (absolute or relative to evidence_root)

    Typed output per record:
        rule, target, strings (list of {offset, var, snippet})
    """
    fixture = load_fixture_result("yara_scan", run_id, str(evidence_root))
    if fixture is not None:
        return fixture

    if not yara_bin:
        return tool_error_result("yara.scan", run_id, str(evidence_root),
                                 "YARA binary not configured. Set COUNSEL_YARA_BIN.")

    if not target_path:
        return tool_error_result("yara.scan", run_id, str(evidence_root),
                                 "target_path is required for yara.scan")

    target = evidence_root / target_path.lstrip("/\\")
    if not target.exists():
        return tool_error_result("yara.scan", run_id, str(target),
                                 f"Target not found: {target_path}")

    # Rules path
    if rules_path:
        rules = Path(rules_path) if Path(rules_path).is_absolute() else evidence_root / rules_path
    else:
        # Default to COUNSEL built-in rules directory
        rules = Path(__file__).parent.parent.parent / "rules" / "yara"

    if not rules.exists():
        return tool_error_result("yara.scan", run_id, str(target),
                                 f"YARA rules not found at: {rules}")

    warnings: list[str] = []

    stdout, stderr, rc = run_tool_subprocess(
        [yara_bin, "-r", "-s", str(rules), str(target)],
        evidence_root, timeout,
    )

    if rc not in (0, 1):   # 0=matches, 1=no matches, other=error
        return tool_error_result("yara.scan", run_id, str(target),
                                 f"YARA failed rc={rc}", stderr)

    records, warns = _parse_yara_output(stdout, max_str_len)
    warnings.extend(warns)

    if not records:
        warnings.append(f"No YARA matches on {target_path}")

    final_records, truncated = truncate_records(records, max_records, warnings)
    return ParseResult(
        tool="yara.scan", run_id=run_id, seq=ledger_seq,
        records=final_records, artifact_path=str(target), offset=0,
        raw_output_sha256=hash_raw(stdout) if stdout else hash_raw(b"no-match"),
        parse_quality=0.9, warnings=warnings, truncated=truncated,
    )
