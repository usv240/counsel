"""
COUNSEL Benchmark Harness - Ground-Truth Accuracy Evaluation.

Compares COUNSEL findings against a locked answer key for the
'Stolen Szechuan Sauce' case (Dfir.training / Dave Cowen, 2018).

Metrics:
  - Precision: of CORROBORATED findings, what fraction are true positives?
  - Recall:    of true positives in the answer key, what fraction did we find?
  - FPR:       false positive rate (hallucinated CORROBORATED claims)
  - Hallucination rate: INFERENCE claims that are unsupported by the key
  - ECE:       Expected Calibration Error (confidence calibration curve)

Baseline comparison: run Protocol SIFT (without COUNSEL) and compare.
'Hallucinations We Caught' gallery: claims the agent self-flagged.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..engine.model import Claim, ClaimGraph, ClaimState


@dataclass
class AnswerKey:
    """
    Ground-truth answer key for one case.
    Each entry is a (claim_type, subject_substring) tuple that should be CORROBORATED.
    """
    case_name: str
    true_positives: list[dict]   # {"claim_type": ..., "subject_hint": ..., "attack_technique": ...}
    true_negatives: list[dict]   # things that should NOT be corroborated (no evidence)

    @classmethod
    def load(cls, path: Path) -> "AnswerKey":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            case_name=data["case_name"],
            true_positives=data.get("true_positives", []),
            true_negatives=data.get("true_negatives", []),
        )


@dataclass
class AccuracyMetrics:
    precision: float = 0.0
    recall: float = 0.0
    fpr: float = 0.0
    hallucination_rate: float = 0.0
    ece: float = 0.0
    true_positive_count: int = 0
    false_positive_count: int = 0
    false_negative_count: int = 0
    corroborated_count: int = 0
    hallucinations_caught: list[str] = field(default_factory=list)
    calibration_bins: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "fpr": round(self.fpr, 4),
            "hallucination_rate": round(self.hallucination_rate, 4),
            "ece": round(self.ece, 4),
            "true_positives": self.true_positive_count,
            "false_positives": self.false_positive_count,
            "false_negatives": self.false_negative_count,
            "corroborated_total": self.corroborated_count,
            "hallucinations_caught": self.hallucinations_caught,
            "calibration_bins": self.calibration_bins,
        }


def _matches_key_entry(claim: Claim, entry: dict) -> bool:
    """Does a claim match a ground-truth key entry?"""
    if claim.claim_type.value != entry.get("claim_type", ""):
        return False
    hint = entry.get("subject_hint", "").lower()
    if hint and hint not in claim.subject.lower():
        return False
    return True


def evaluate(
    claim_graph: ClaimGraph,
    answer_key: AnswerKey,
) -> AccuracyMetrics:
    """
    Compute precision, recall, FPR, hallucination rate, and ECE.
    """
    metrics = AccuracyMetrics()
    corroborated = claim_graph.corroborated_claims()
    metrics.corroborated_count = len(corroborated)

    # True positives: corroborated claims that match the answer key
    matched_keys = set()
    tp_claims = []
    fp_claims = []

    for claim in corroborated:
        matched = False
        for i, tp_entry in enumerate(answer_key.true_positives):
            if i not in matched_keys and _matches_key_entry(claim, tp_entry):
                matched_keys.add(i)
                matched = True
                break
        if matched:
            tp_claims.append(claim)
        else:
            fp_claims.append(claim)

    # False negatives: key entries we didn't corroborate
    fn_entries = [
        entry for i, entry in enumerate(answer_key.true_positives)
        if i not in matched_keys
    ]

    metrics.true_positive_count = len(tp_claims)
    metrics.false_positive_count = len(fp_claims)
    metrics.false_negative_count = len(fn_entries)

    metrics.precision = (
        metrics.true_positive_count / metrics.corroborated_count
        if metrics.corroborated_count > 0 else 0.0
    )
    metrics.recall = (
        metrics.true_positive_count / len(answer_key.true_positives)
        if answer_key.true_positives else 0.0
    )

    # FPR: FP / (FP + TN opportunities)
    tn_count = len(answer_key.true_negatives)
    metrics.fpr = (
        metrics.false_positive_count / (metrics.false_positive_count + tn_count)
        if (metrics.false_positive_count + tn_count) > 0 else 0.0
    )

    # Hallucination rate: INFERENCE claims with no key support
    inference_claims = [c for c in claim_graph.claims if c.state == ClaimState.INFERENCE]
    unsupported_inference = [
        c for c in inference_claims
        if not any(_matches_key_entry(c, e) for e in answer_key.true_positives)
    ]
    metrics.hallucination_rate = (
        len(unsupported_inference) / len(inference_claims)
        if inference_claims else 0.0
    )
    metrics.hallucinations_caught = [
        f"{c.claim_type.value} - {c.subject[:60]} (support={c.support_score:.2f})"
        for c in unsupported_inference
    ]

    # ECE: Expected Calibration Error (confidence calibration)
    # Bin claims by support_score into 10 bins
    bins = _compute_calibration_bins(claim_graph.claims, answer_key)
    metrics.calibration_bins = bins
    metrics.ece = _compute_ece(bins)

    return metrics


def _compute_calibration_bins(claims: list[Claim], answer_key: AnswerKey) -> list[dict]:
    """
    Partition claims into 10 confidence bins and measure accuracy in each bin.
    ECE = weighted average of |confidence - accuracy| per bin.
    """
    bins_data: dict[int, dict] = {i: {"count": 0, "correct": 0, "confidence_sum": 0.0} for i in range(10)}

    for claim in claims:
        conf = claim.support_score
        bin_idx = min(int(conf * 10), 9)
        bins_data[bin_idx]["count"] += 1
        bins_data[bin_idx]["confidence_sum"] += conf

        # Is this claim correct?
        if claim.state == ClaimState.CORROBORATED:
            is_correct = any(_matches_key_entry(claim, e) for e in answer_key.true_positives)
            if is_correct:
                bins_data[bin_idx]["correct"] += 1

    result = []
    for i in range(10):
        b = bins_data[i]
        count = b["count"]
        if count == 0:
            continue
        avg_conf = b["confidence_sum"] / count
        accuracy = b["correct"] / count
        result.append({
            "bin": i,
            "confidence_lower": i * 0.1,
            "confidence_upper": (i + 1) * 0.1,
            "avg_confidence": round(avg_conf, 3),
            "accuracy": round(accuracy, 3),
            "count": count,
        })
    return result


def _compute_ece(bins: list[dict]) -> float:
    if not bins:
        return 0.0
    total = sum(b["count"] for b in bins)
    if total == 0:
        return 0.0
    ece = sum(
        (b["count"] / total) * abs(b["avg_confidence"] - b["accuracy"])
        for b in bins
    )
    return round(ece, 4)


def print_accuracy_report(metrics: AccuracyMetrics, case_name: str) -> None:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box as rbox

    c = Console()
    c.print(Panel(
        f"[bold cyan]COUNSEL Accuracy Report[/bold cyan]\n"
        f"[dim]Case: {case_name}[/dim]\n\n"
        f"[bold]Precision:[/bold]  [green]{metrics.precision:.1%}[/green]  "
        f"(of corroborated findings, fraction correct)\n"
        f"[bold]Recall:[/bold]     [green]{metrics.recall:.1%}[/green]  "
        f"(of true positives, fraction found)\n"
        f"[bold]FPR:[/bold]        [red]{metrics.fpr:.1%}[/red]  "
        f"(false positive rate)\n"
        f"[bold]Hallucination:[/bold] [yellow]{metrics.hallucination_rate:.1%}[/yellow]  "
        f"(INFERENCE claims unsupported by ground truth)\n"
        f"[bold]ECE:[/bold]        {metrics.ece:.4f}  "
        f"(Expected Calibration Error - lower is better)\n\n"
        f"TP={metrics.true_positive_count}  FP={metrics.false_positive_count}  "
        f"FN={metrics.false_negative_count}",
        title="[bold]Accuracy Metrics[/bold]",
        border_style="cyan",
    ))

    if metrics.hallucinations_caught:
        c.print("\n[bold yellow]Hallucinations We Caught:[/bold yellow]")
        c.print("[dim](Claims that seemed plausible but lacked corroboration)[/dim]")
        for h in metrics.hallucinations_caught:
            c.print(f"  [yellow]![/yellow] {h}")

    if metrics.calibration_bins:
        table = Table("Bin", "Confidence", "Accuracy", "N", title="Calibration", box=rbox.SIMPLE)
        for b in metrics.calibration_bins:
            diff = abs(b["avg_confidence"] - b["accuracy"])
            color = "green" if diff < 0.1 else ("yellow" if diff < 0.2 else "red")
            table.add_row(
                str(b["bin"]),
                f"{b['confidence_lower']:.1f}–{b['confidence_upper']:.1f}",
                f"[{color}]{b['accuracy']:.2f}[/{color}]",
                str(b["count"]),
            )
        c.print(table)
