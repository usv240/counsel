"""
Parse-before-return infrastructure.

Fixture mode: set COUNSEL_FIXTURE_DIR to a directory containing pre-recorded
tool output JSON files (e.g. counsel/fixtures/szechuan_sauce/). When set, each
tool loads its fixture file instead of calling the real binary. This enables
full end-to-end demonstration without SIFT Workstation installed.


Every MCP tool MUST parse raw forensic tool output into typed records before
returning to the LLM. Raw forensic output (multi-MB, attacker-controlled)
never enters the agent context.

Two guarantees:
1. Size budget: parsed output is bounded to MAX_RECORDS.
2. Injection resistance: raw strings from evidence are sanitized data fields,
   not freeform instructions. The predicate evaluator only reads named fields.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ParseResult:
    """Common return envelope for every MCP tool call."""
    tool: str
    run_id: str
    seq: int                    # ledger sequence (filled by server)
    records: list[dict]
    artifact_path: str
    offset: int
    raw_output_sha256: str
    parse_quality: float        # 0.0-1.0
    warnings: list[str] = field(default_factory=list)
    truncated: bool = False

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "run_id": self.run_id,
            "seq": self.seq,
            "records": self.records,
            "evidence": {
                "path": self.artifact_path,
                "offset": self.offset,
                "raw_output_sha256": self.raw_output_sha256,
            },
            "parse_quality": self.parse_quality,
            "warnings": self.warnings,
            "truncated": self.truncated,
            "record_count": len(self.records),
        }


def sanitize_string(s: object, max_len: int = 512) -> str:
    """
    Strip control characters and cap length.
    This is the injection barrier: attacker-controlled artifact content
    becomes a bounded, control-char-free string - never executable.
    """
    cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", str(s or ""))
    return cleaned[:max_len]


def hash_raw(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def run_tool_subprocess(
    cmd: list[str],
    cwd: Path,
    timeout: int = 120,
) -> tuple[bytes, bytes, int]:
    """
    Execute an external forensic tool. Returns (stdout, stderr, returncode).
    This is the only place in the MCP server that spawns a subprocess.
    The agent has no access to this - it calls typed MCP functions only.
    """
    actual_cmd = list(cmd)
    # On Linux, .NET .exe tools (Eric Zimmerman) require mono runtime
    if sys.platform != "win32" and actual_cmd and actual_cmd[0].endswith(".exe"):
        mono = shutil.which("mono") or shutil.which("mono-sgen")
        if mono:
            actual_cmd = [mono] + actual_cmd
    try:
        result = subprocess.run(
            actual_cmd,
            capture_output=True,
            timeout=timeout,
            cwd=str(cwd),
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return b"", b"TIMEOUT: tool exceeded time limit", 124
    except FileNotFoundError:
        return b"", f"TOOL_NOT_FOUND: {cmd[0]}".encode(), 127
    except PermissionError as e:
        return b"", str(e).encode(), 126


def truncate_records(
    records: list[dict],
    max_records: int,
    warnings: list[str],
) -> tuple[list[dict], bool]:
    if len(records) > max_records:
        warnings.append(
            f"Truncated to {max_records} records (total: {len(records)}). "
            "Use filters to narrow the query."
        )
        return records[:max_records], True
    return records, False


def load_fixture_result(
    tool_name: str, run_id: str, artifact_path: str, artifact_name: str | None = None
) -> "ParseResult | None":
    """
    Load pre-recorded tool output from COUNSEL_FIXTURE_DIR.

    Returns None when fixture mode is not active or the file is absent,
    so callers fall through to the real tool binary unchanged.

    File must be a JSON array of record dicts in the same schema the tool
    would produce after parse-before-return. See counsel/fixtures/README.md.

    tool_name selects the fixture file ({tool_name}.json, matches the MCP
    function name). artifact_name sets ParseResult.tool to the dotted
    artifact identifier (e.g. "registry.run_keys") that the corroboration
    rules match against - this must match the real (non-fixture) code path.
    """
    fixture_dir = os.environ.get("COUNSEL_FIXTURE_DIR", "")
    if not fixture_dir:
        return None
    fixture_path = Path(fixture_dir) / f"{tool_name}.json"
    if not fixture_path.exists():
        return None
    try:
        raw_bytes = fixture_path.read_bytes()
        records = json.loads(raw_bytes)
        if not isinstance(records, list):
            return None
        return ParseResult(
            tool=artifact_name or tool_name,
            run_id=run_id,
            seq=0,
            records=records,
            artifact_path=str(fixture_path),
            offset=0,
            raw_output_sha256=hash_raw(raw_bytes),
            parse_quality=1.0,
            warnings=["[FIXTURE] Pre-recorded output. Replace with a real SIFT run to get live results."],
        )
    except Exception:
        return None


def tool_error_result(
    tool_name: str,
    run_id: str,
    artifact_path: str,
    error: str,
    stderr: bytes = b"",
) -> ParseResult:
    """Return a well-formed error result when a tool fails."""
    msg = sanitize_string(error)
    stderr_msg = sanitize_string(stderr.decode("utf-8", errors="replace")[:200])
    return ParseResult(
        tool=tool_name,
        run_id=run_id,
        seq=0,
        records=[],
        artifact_path=artifact_path,
        offset=0,
        raw_output_sha256=hash_raw(b""),
        parse_quality=0.0,
        warnings=[f"Tool failed: {msg}", f"stderr: {stderr_msg}"],
    )
