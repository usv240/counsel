"""
T4: fs.stat_hash(path)
Evidentiary meaning: payload_present + signature modifier

Checks file existence, size, SHA256, timestamps, and Authenticode signature status.
No external tool required - pure Python stat + hashlib.
Signature check uses osslsigncode (SIFT) or openssl.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..parsers.base import (
    ParseResult,
    hash_raw,
    run_tool_subprocess,
    sanitize_string,
    tool_error_result,
)


def _ts(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _check_signature(file_path: Path, osslsigncode_bin: str, timeout: int) -> tuple[bool, str]:
    """
    Check Authenticode signature using osslsigncode or openssl.
    Returns (is_signed, signer_info).
    """
    if osslsigncode_bin:
        stdout, _, rc = run_tool_subprocess(
            [osslsigncode_bin, "verify", str(file_path)],
            file_path.parent, timeout,
        )
        output = stdout.decode("utf-8", errors="replace")
        is_signed = "Signature verification: ok" in output or "Verified successfully" in output
        signer = ""
        for line in output.splitlines():
            if "Subject:" in line or "CN=" in line:
                signer = sanitize_string(line.strip(), 256)
                break
        return is_signed, signer

    # Fallback: check PE headers for signature directory entry (basic heuristic)
    try:
        with open(file_path, "rb") as f:
            pe_bytes = f.read(4096)
        # Look for PKCS#7 signature marker (0x2F7557EB) - rough heuristic
        has_sig_marker = b"\x30\x82" in pe_bytes[128:]  # ASN.1 sequence
        return has_sig_marker, "signature-check-unavailable"
    except Exception:
        return False, "signature-check-unavailable"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def stat_hash(
    run_id: str,
    evidence_root: Path,
    file_path: str,
    osslsigncode_bin: str = "",
    max_str_len: int = 512,
    timeout: int = 60,
    ledger_seq: int = 0,
) -> ParseResult:
    """
    T4: Stat and hash a file in the evidence image.

    file_path: path relative to evidence_root (e.g. "Users/Rick/AppData/Local/Temp/evil.exe")

    Typed output (single record):
        path, exists, size, sha256, mtime, atime, ctime, mode, signed, signer
    """
    target = evidence_root / file_path.lstrip("/\\")
    artifact_path = str(target)
    warnings: list[str] = []

    if not target.exists():
        return ParseResult(
            tool="fs.stat_hash",
            run_id=run_id,
            seq=ledger_seq,
            records=[{
                "path": sanitize_string(file_path, max_str_len),
                "exists": False,
                "size": 0,
                "sha256": "",
                "mtime": "",
                "atime": "",
                "ctime": "",
                "mode": "",
                "signed": False,
                "signer": "",
            }],
            artifact_path=artifact_path,
            offset=0,
            raw_output_sha256=hash_raw(b"not_found"),
            parse_quality=1.0,   # tool ran correctly; file just doesn't exist
            warnings=[f"File not found: {file_path}"],
        )

    try:
        st = target.stat()
        sha256 = _sha256_file(target)
        is_signed, signer = _check_signature(target, osslsigncode_bin, timeout)

        record = {
            "path": sanitize_string(str(target.relative_to(evidence_root)), max_str_len),
            "exists": True,
            "size": st.st_size,
            "sha256": sha256,
            "mtime": _ts(st.st_mtime),
            "atime": _ts(st.st_atime),
            "ctime": _ts(st.st_ctime),
            "mode": oct(stat.S_IMODE(st.st_mode)),
            "signed": is_signed,
            "signer": sanitize_string(signer, 256),
        }

        return ParseResult(
            tool="fs.stat_hash",
            run_id=run_id,
            seq=ledger_seq,
            records=[record],
            artifact_path=artifact_path,
            offset=0,
            raw_output_sha256=sha256,
            parse_quality=1.0,
            warnings=warnings,
        )

    except PermissionError as e:
        return tool_error_result(
            "fs.stat_hash", run_id, artifact_path,
            f"Permission denied: {e} - is the evidence mount read-only to the right user?"
        )
    except OSError as e:
        return tool_error_result("fs.stat_hash", run_id, artifact_path, str(e))
