"""
COUNSEL Hash-Chained Audit Ledger.

Every tool call, claim state change, and agent decision is recorded as an
append-only JSONL entry. Each entry is hash-chained to its predecessor
(SHA256 of: prev_hash || canonical_json_of_entry).

The agent can APPEND but CANNOT SIGN. Signing is performed by the external
Verifier process after agent exit (see verifier/verify.py). This separation
ensures no compromised agent path can forge a valid signature.

Audit trail guarantee: trace any finding → ledger entry → exact MCP call →
raw output hash → artifact path + offset. The `replay()` method re-runs
the tool and verifies the raw output hash matches.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

GENESIS_HASH = "0" * 64   # sentinel for the first entry


class LedgerEntry:
    """Canonical ledger entry format. Never use __dict__ directly - use to_dict()."""

    def __init__(
        self,
        seq: int,
        entry_type: str,
        run_id: str,
        prev_hash: str,
        payload: dict,
        ts: Optional[str] = None,
    ) -> None:
        self.seq = seq
        self.entry_type = entry_type   # genesis | tool_call | claim_state | agent_decision | halt
        self.run_id = run_id
        self.ts = ts or datetime.now(timezone.utc).isoformat()
        self.prev_hash = prev_hash
        self.payload = payload
        self.entry_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        canonical = json.dumps(self._canonical_dict(), ensure_ascii=True, sort_keys=True)
        return hashlib.sha256(
            (self.prev_hash + canonical).encode("utf-8")
        ).hexdigest()

    def _canonical_dict(self) -> dict:
        return {
            "seq": self.seq,
            "entry_type": self.entry_type,
            "run_id": self.run_id,
            "ts": self.ts,
            "payload": self.payload,
        }

    def to_dict(self) -> dict:
        d = self._canonical_dict()
        d["prev_hash"] = self.prev_hash
        d["entry_hash"] = self.entry_hash
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=True, sort_keys=True)


class Ledger:
    """
    Append-only hash-chained ledger.

    Thread-safe: a single file lock guards all writes.
    Idempotent on re-open: loads last_hash from the most recent entry.
    """

    def __init__(self, ledger_path: Path, run_id: str) -> None:
        self.ledger_path = Path(ledger_path)
        self.run_id = run_id
        self._lock = threading.Lock()
        self._seq = 0
        self._last_hash = GENESIS_HASH

        # Resume from existing ledger (e.g., crash recovery)
        if self.ledger_path.exists():
            self._resume()

    def _resume(self) -> None:
        """Load last_hash and seq from an existing ledger file."""
        try:
            lines = self.ledger_path.read_text(encoding="utf-8").splitlines()
            for line in reversed(lines):
                line = line.strip()
                if line:
                    entry = json.loads(line)
                    self._last_hash = entry["entry_hash"]
                    self._seq = entry["seq"] + 1
                    break
        except (json.JSONDecodeError, KeyError, OSError):
            pass

    def _append(self, entry_type: str, payload: dict) -> LedgerEntry:
        with self._lock:
            entry = LedgerEntry(
                seq=self._seq,
                entry_type=entry_type,
                run_id=self.run_id,
                prev_hash=self._last_hash,
                payload=payload,
            )
            self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.ledger_path, "a", encoding="utf-8") as f:
                f.write(entry.to_json() + "\n")
            self._last_hash = entry.entry_hash
            self._seq += 1
            return entry

    # ─── Public API ─────────────────────────────────────────────────────────

    def genesis(
        self,
        evidence_sha256: str,
        tool_catalog_hash: str,
        rule_set_hash: str,
    ) -> LedgerEntry:
        """Write the genesis entry - pins evidence hash, catalog, and rule set."""
        return self._append("genesis", {
            "evidence_sha256_in": evidence_sha256,
            "tool_catalog_hash": tool_catalog_hash,
            "rule_set_hash": rule_set_hash,
        })

    def append_tool_call(self, result: Any) -> int:
        """Record an MCP tool call result. Returns the assigned seq number."""
        payload = {
            "tool": result.tool,
            "artifact_path": result.artifact_path,
            "raw_output_sha256": result.raw_output_sha256,
            "parse_quality": result.parse_quality,
            "record_count": len(result.records),
            "truncated": result.truncated,
            "warnings": result.warnings,
        }
        entry = self._append("tool_call", payload)
        return entry.seq

    def append_claim_state(
        self,
        claim_id: str,
        claim_type: str,
        subject: str,
        from_state: str,
        to_state: str,
        support: float,
        contradiction: float,
        rule_id: str,
        trigger: str,
        iteration: int,
    ) -> LedgerEntry:
        """Record a claim state transition (powers 'self-correction' demo)."""
        return self._append("claim_state", {
            "claim_id": claim_id,
            "claim_type": claim_type,
            "subject": subject,
            "from_state": from_state,
            "to_state": to_state,
            "support": round(support, 4),
            "contradiction": round(contradiction, 4),
            "rule_id": rule_id,
            "trigger": trigger,
            "iteration": iteration,
        })

    def append_agent_decision(
        self,
        iteration: int,
        phase: str,
        action: str,
        rationale: str,
        tool_chosen: Optional[str] = None,
        claim_id: Optional[str] = None,
    ) -> LedgerEntry:
        """Record an agent decision (WHY it chose each next tool - audit trail)."""
        return self._append("agent_decision", {
            "iteration": iteration,
            "phase": phase,
            "action": action,
            "rationale": rationale,
            "tool_chosen": tool_chosen,
            "claim_id": claim_id,
        })

    def append_halt(
        self,
        reason: str,
        iteration: int,
        open_claims: int,
        corroborated_claims: int,
        elapsed_seconds: float,
    ) -> LedgerEntry:
        """Record graceful halt - captures termination condition."""
        return self._append("halt", {
            "reason": reason,
            "iteration": iteration,
            "open_claims": open_claims,
            "corroborated_claims": corroborated_claims,
            "elapsed_seconds": round(elapsed_seconds, 2),
        })

    def head_hash(self) -> str:
        return self._last_hash

    def current_seq(self) -> int:
        return self._seq

    # ─── Verification & Replay ──────────────────────────────────────────────

    def read_entry(self, seq: int) -> Optional[dict]:
        """Read a specific entry by sequence number."""
        try:
            with open(self.ledger_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if entry["seq"] == seq:
                            return entry
                    except (json.JSONDecodeError, KeyError):
                        continue
        except OSError:
            pass
        return None

    def verify_chain(self) -> tuple[bool, list[str]]:
        """
        Recompute the full hash chain from genesis. Returns (valid, errors).
        Called by the Verifier process - not by the agent.
        """
        errors: list[str] = []
        prev_hash = GENESIS_HASH
        seq_expected = 0

        try:
            with open(self.ledger_path, "r", encoding="utf-8") as f:
                for lineno, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw = json.loads(line)
                    except json.JSONDecodeError as e:
                        errors.append(f"Line {lineno}: JSON parse error: {e}")
                        continue

                    # Reconstruct the entry and recompute its hash
                    try:
                        entry = LedgerEntry(
                            seq=raw["seq"],
                            entry_type=raw["entry_type"],
                            run_id=raw["run_id"],
                            prev_hash=raw["prev_hash"],
                            payload=raw["payload"],
                            ts=raw["ts"],
                        )
                    except KeyError as e:
                        errors.append(f"Line {lineno}: missing field {e}")
                        continue

                    if raw["seq"] != seq_expected:
                        errors.append(
                            f"Line {lineno}: seq gap - expected {seq_expected}, got {raw['seq']}"
                        )
                    if raw["prev_hash"] != prev_hash:
                        errors.append(
                            f"seq {raw['seq']}: prev_hash mismatch - "
                            f"expected {prev_hash[:16]}…, got {raw['prev_hash'][:16]}…"
                        )
                    if entry.entry_hash != raw.get("entry_hash", ""):
                        errors.append(
                            f"seq {raw['seq']}: hash mismatch - "
                            f"computed {entry.entry_hash[:16]}…, stored {raw.get('entry_hash', '')[:16]}…"
                        )

                    prev_hash = raw.get("entry_hash", entry.entry_hash)
                    seq_expected = raw["seq"] + 1

        except OSError as e:
            errors.append(f"Cannot read ledger: {e}")

        return len(errors) == 0, errors

    def replay(
        self,
        seq: int,
        config: Any,
    ) -> dict:
        """
        Re-execute the tool call at ledger seq and verify the raw output hash.

        Returns:
            {
                "seq": int,
                "tool": str,
                "original_sha256": str,
                "replayed_sha256": str,
                "match": bool,
                "verdict": "REPRODUCED" | "HASH_MISMATCH" | "TOOL_FAILED" | "NOT_A_TOOL_CALL"
            }
        """
        entry = self.read_entry(seq)
        if not entry:
            return {"seq": seq, "verdict": "NOT_FOUND", "match": False}

        if entry["entry_type"] != "tool_call":
            return {"seq": seq, "verdict": "NOT_A_TOOL_CALL", "match": False}

        payload = entry["payload"]
        tool = payload.get("tool", "")
        original_sha = payload.get("raw_output_sha256", "")

        # Import and re-invoke the tool
        try:
            replayed_result = _invoke_tool_for_replay(tool, config, payload)
            replayed_sha = replayed_result.raw_output_sha256
            match = replayed_sha == original_sha
            return {
                "seq": seq,
                "tool": tool,
                "original_sha256": original_sha,
                "replayed_sha256": replayed_sha,
                "match": match,
                "verdict": "REPRODUCED" if match else "HASH_MISMATCH",
            }
        except Exception as e:
            return {"seq": seq, "tool": tool, "verdict": "TOOL_FAILED", "match": False, "error": str(e)}


def _invoke_tool_for_replay(tool: str, config: Any, payload: dict) -> Any:
    """Re-invoke a forensic tool by name for replay verification."""
    from ..mcp_server.tools import registry, prefetch, amcache, filesystem, mft, memory, network, evtx
    kwargs = dict(
        run_id=config.run_id,
        evidence_root=config.evidence_root,
    )
    tool_map = {
        "registry.run_keys": lambda: registry.run_keys(**{**kwargs, "hive_paths": [payload.get("artifact_path", "")]}),
        "prefetch.run_record": lambda: prefetch.run_record(**kwargs),
        "amcache.lookup": lambda: amcache.lookup(**kwargs),
        "fs.stat_hash": lambda: filesystem.stat_hash(**{**kwargs, "file_path": payload.get("artifact_path", "")}),
        "mft.timeline": lambda: mft.timeline(**kwargs),
        "mem.pslist": lambda: memory.pslist(**kwargs),
        "mem.netscan": lambda: memory.netscan(**kwargs),
        "mem.malfind": lambda: memory.malfind(**kwargs),
        "net.flows": lambda: network.flows(**kwargs),
        "evtx.query": lambda: evtx.query(**kwargs),
    }
    fn = tool_map.get(tool)
    if fn is None:
        raise ValueError(f"Unknown tool for replay: {tool}")
    return fn()
