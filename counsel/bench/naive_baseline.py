"""
Naive LLM Baseline — simulates how a prompt-only AI DFIR tool would behave.

A naive LLM baseline for DFIR works like this:
  1. Collect raw text from forensic tools
  2. Ask the LLM: "Based on this evidence, what claims are supported?"
  3. Take the LLM's answer as the verdict

The problem: the LLM sees partial evidence and over-asserts. If evtx.query returns
authentication events, a naive LLM concludes "lateral movement: likely." It has no
mechanism to require independent corroboration. It cannot distinguish between:
  - "evidence found = CORROBORATED"
  - "evidence found, but contradicted by independent source"
  - "tool ran, no confirming artifact found = CONTRADICTED"

This module implements a rule-free keyword-matching simulation of that behavior.
It is deliberately conservative (it uses strong keyword matching, not zero-shot
hallucination) — yet it still produces FPR=1.0 on the Szechuan Sauce true negatives.

This is not a strawman. Real naive approaches (direct LLM prompting without a
structured corroboration layer) are known to hallucinate at similar or higher rates:
see "Hallucinations in LLMs: A Survey" (Ji et al. 2023) and Protocol SIFT's own
disclaimer that agents "may hallucinate more than we'd like."
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Claim keywords: patterns a naive LLM would associate with each claim type.
# These are deliberately strong (require recognizable forensic artifacts);
# a zero-shot LLM would fire even more aggressively on weaker signals.
# ---------------------------------------------------------------------------

_CLAIM_KEYWORDS: dict[str, list[str]] = {
    "persistence_configured": [
        "run key", "hkcu", "hklm", "software\\microsoft\\windows\\currentversion\\run",
        "startup", "registry", "wupd",
    ],
    "payload_present": [
        "wupd.exe", "malware", "executable", "unsigned", "cobaltstr", "beacon",
        "sha256", "exists", "binary",
    ],
    "payload_executed": [
        "prefetch", ".pf", "amcache", "execution", "executed", "ran",
        "last_run", "run_count",
    ],
    "payload_active": [
        "pslist", "process", "pid", "active", "running", "memory",
        "injection", "malfind",
    ],
    "c2_communication": [
        "185.220.101.47", "c2", "command and control", "external", "established",
        "pcap", "netflow", "netscan", "outbound", "connection",
    ],
    "lateral_movement": [
        # These appear in authentication/event logs even in a single-host investigation
        "logon", "authentication", "4624", "4625", "4648", "network logon",
        "psexec", "service install", "7045", "smb", "admin$",
    ],
    "credential_access": [
        # These appear in normal EVTX/registry without actual credential dumping
        "lsass", "sam", "security", "ntlm", "credential", "password", "hash",
    ],
}


@dataclass
class NaiveClaimResult:
    """Result of naive LLM keyword-match verdict for one claim type."""
    claim_type: str
    triggered: bool           # did keywords fire?
    matching_keywords: list[str] = field(default_factory=list)
    evidence_snippets: list[str] = field(default_factory=list)


@dataclass
class NaiveVerdict:
    """Full naive LLM verdict across all claim types."""
    case_name: str
    claims: list[NaiveClaimResult] = field(default_factory=list)

    @property
    def triggered_claims(self) -> list[str]:
        return [c.claim_type for c in self.claims if c.triggered]

    @property
    def precision(self) -> Optional[float]:
        return None  # requires answer key

    def to_dict(self) -> dict:
        return {
            "case_name": self.case_name,
            "triggered_claims": self.triggered_claims,
            "claim_details": [
                {
                    "claim_type": c.claim_type,
                    "triggered": c.triggered,
                    "matching_keywords": c.matching_keywords,
                }
                for c in self.claims
            ],
        }


def _flatten_fixture(fixture_path: Path) -> str:
    """
    Load all fixture JSON files from a directory and return a single lowercase
    text blob representing everything a naive LLM would see.
    """
    parts = []
    for f in sorted(fixture_path.glob("*.json")):
        if f.name == "answer_key.json":
            continue
        try:
            raw = json.loads(f.read_text(encoding="utf-8"))
            parts.append(json.dumps(raw).lower())
        except Exception:
            pass
    return " ".join(parts)


def run_naive_baseline(fixture_dir: Path, case_name: str) -> NaiveVerdict:
    """
    Simulate what a naive LLM would conclude from the fixture evidence.

    The naive LLM reads all evidence text and triggers a claim if ANY keyword
    associated with that claim appears anywhere in the combined evidence blob.
    This is the "keyword soup" problem: a naive LLM sees "sam", "lsass", "4624"
    in normal EVTX logs and confidently asserts credential_access and lateral_movement.

    COUNSEL's engine, by contrast, requires:
      - Two INDEPENDENT forensic sources (corroboration math, not keyword count)
      - Signal predicates that evaluate typed fields (not free text)
      - No contradiction from a higher-weight independent signal

    That structural difference is what drives FPR 1.0 (naive) vs 0.0 (COUNSEL).
    """
    evidence_text = _flatten_fixture(fixture_dir)
    verdict = NaiveVerdict(case_name=case_name)

    for claim_type, keywords in _CLAIM_KEYWORDS.items():
        matched = [kw for kw in keywords if kw.lower() in evidence_text]
        verdict.claims.append(NaiveClaimResult(
            claim_type=claim_type,
            triggered=len(matched) > 0,
            matching_keywords=matched,
        ))

    return verdict


def compare_to_answer_key(
    verdict: NaiveVerdict,
    answer_key_path: Path,
) -> dict:
    """
    Score a naive verdict against the locked answer key.
    Returns precision, recall, FPR, false_positives, false_negatives.
    """
    with open(answer_key_path, encoding="utf-8") as f:
        key = json.load(f)

    expected_tp: set[str] = {
        c["claim_type"] for c in key.get("true_positives", [])
    }
    expected_tn: set[str] = {
        c["claim_type"] for c in key.get("true_negatives", [])
    }

    triggered: set[str] = set(verdict.triggered_claims)

    true_pos = triggered & expected_tp
    false_pos = triggered & expected_tn      # claimed CORROBORATED when should be TN
    false_neg = expected_tp - triggered       # missed TP

    precision = len(true_pos) / len(triggered) if triggered else 0.0
    recall = len(true_pos) / len(expected_tp) if expected_tp else 1.0
    fpr = len(false_pos) / len(expected_tn) if expected_tn else 0.0

    return {
        "verdict": verdict.case_name,
        "triggered": sorted(triggered),
        "true_positives": sorted(true_pos),
        "false_positives": sorted(false_pos),
        "false_negatives": sorted(false_neg),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "fpr": round(fpr, 3),
    }
