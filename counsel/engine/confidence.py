"""
Noisy-OR confidence model with independence-group partitioning.

Core invariant: a finding only reaches CORROBORATED when >=2 independent
signal groups agree. One confident tool is never enough.
This is the anti-hallucination heart of COUNSEL.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .dsl import CompiledRule, ContradictionSpec, SignalSpec, evaluate_predicate
from .model import ClaimState, EvidenceRef

# Tunable thresholds — calibrated on the ground-truth case (see bench/)
TAU_CORROBORATED = 0.80   # minimum noisy-OR support to reach CORROBORATED
TAU_CONTRADICTED = 0.60   # minimum contradiction score to override
MIN_INDEPENDENT_GROUPS = 2  # must come from >=2 independent artifact families


@dataclass
class SignalResult:
    """Result of evaluating one signal against observed evidence."""
    signal: SignalSpec
    evidence_ref: Optional[EvidenceRef]
    active: bool            # False if evidence_ref is None (gap = not yet collected)
    predicate_satisfied: bool
    effective_weight: float


@dataclass
class ConfidenceResult:
    """Full confidence computation for one claim type under one rule."""
    claim_type: str
    rule_id: str
    support: float
    contradiction: float
    independent_groups_active: int
    state: ClaimState
    active_signals: list[SignalResult]
    gap_signals: list[SignalResult]   # unchecked high-value signals (drive GAP DETECTION)
    modifier_notes: list[str]


def compute_confidence(
    rule: CompiledRule,
    claim_type: str,
    evidence_map: dict[str, tuple[EvidenceRef, dict]],
    # evidence_map: tool -> (EvidenceRef, record_dict)
) -> ConfidenceResult:
    """
    Apply the noisy-OR model for one (rule, claim_type) pair.

    evidence_map contains only the tools that have been run so far.
    Unobserved tools contribute 0 to support (they become gap_signals).
    """
    relevant_signals = rule.tools_for_claim(claim_type)

    # Partition by independent_group
    groups: dict[str, list[SignalResult]] = {}
    active_signals: list[SignalResult] = []
    gap_signals: list[SignalResult] = []

    for sig in relevant_signals:
        if sig.artifact in evidence_map:
            ev_ref, record = evidence_map[sig.artifact]
            pred_ok = evaluate_predicate(sig.requires or "", record) if sig.requires else True
            eff_w = sig.weight * ev_ref.parse_quality if pred_ok else 0.0
            sr = SignalResult(
                signal=sig,
                evidence_ref=ev_ref,
                active=True,
                predicate_satisfied=pred_ok,
                effective_weight=eff_w,
            )
            active_signals.append(sr)
        else:
            # Not yet observed — potential gap
            sr = SignalResult(
                signal=sig,
                evidence_ref=None,
                active=False,
                predicate_satisfied=False,
                effective_weight=0.0,
            )
            gap_signals.append(sr)

        groups.setdefault(sig.independent_group, []).append(sr)

    # Noisy-OR over groups (co-dependent signals share max within their group)
    group_weights: list[float] = []
    independent_groups_active = 0

    for group_name, sigs in groups.items():
        max_eff_w = max((s.effective_weight for s in sigs), default=0.0)
        if max_eff_w > 0:
            independent_groups_active += 1
        group_weights.append(max_eff_w)

    # support = 1 - PRODUCT(1 - w_g) for all groups
    support = 1.0
    for gw in group_weights:
        support *= (1.0 - gw)
    support = 1.0 - support

    # Contradiction: max over conflicting signals
    contradiction = _compute_contradiction(rule, evidence_map)

    # Modifier notes (never changes state on their own)
    modifier_notes = _collect_modifier_notes(rule, evidence_map)

    # State resolution
    state = _resolve_state(support, contradiction, independent_groups_active, gap_signals)

    return ConfidenceResult(
        claim_type=claim_type,
        rule_id=rule.rule_id,
        support=support,
        contradiction=contradiction,
        independent_groups_active=independent_groups_active,
        state=state,
        active_signals=active_signals,
        gap_signals=gap_signals,
        modifier_notes=modifier_notes,
    )


def _compute_contradiction(
    rule: CompiledRule,
    evidence_map: dict[str, tuple[EvidenceRef, dict]],
) -> float:
    max_contradiction = 0.0
    for cs in rule.contradictions:
        if cs.artifact not in evidence_map:
            continue
        ev_ref, record = evidence_map[cs.artifact]
        pred_ok = evaluate_predicate(cs.requires or "", record) if cs.requires else True
        if pred_ok:
            eff_w = cs.weight * ev_ref.parse_quality
            max_contradiction = max(max_contradiction, eff_w)
    return max_contradiction


def _collect_modifier_notes(
    rule: CompiledRule,
    evidence_map: dict[str, tuple[EvidenceRef, dict]],
) -> list[str]:
    notes = []
    for mod in rule.modifiers:
        if mod.artifact not in evidence_map:
            continue
        _, record = evidence_map[mod.artifact]
        pred_ok = evaluate_predicate(mod.requires or "", record) if mod.requires else True
        if pred_ok and mod.note:
            notes.append(mod.note)
    return notes


def _resolve_state(
    support: float,
    contradiction: float,
    independent_groups_active: int,
    gap_signals: list[SignalResult],
) -> ClaimState:
    if contradiction >= TAU_CONTRADICTED:
        return ClaimState.CONTRADICTED
    if support >= TAU_CORROBORATED and independent_groups_active >= MIN_INDEPENDENT_GROUPS:
        return ClaimState.CORROBORATED
    if support > 0:
        return ClaimState.INFERENCE
    if not gap_signals:
        # No gaps left, still no support
        return ClaimState.UNRESOLVED
    # Gaps remain — stay OBSERVED (agent should gather more)
    return ClaimState.OBSERVED


def prioritize_gaps(result: ConfidenceResult) -> list[SignalResult]:
    """
    Return unchecked signals ranked by weight descending.
    These are the next tools the agent should call (gap-driven self-correction).
    """
    return sorted(
        (s for s in result.gap_signals if s.signal.weight >= 0.5),
        key=lambda s: s.signal.weight,
        reverse=True,
    )
