"""
Parse-before-return infrastructure.

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
import re
import subprocess
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
    try:
        result = subprocess.run(
            cmd,
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
