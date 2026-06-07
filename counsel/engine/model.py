"""
Core data model: Claim, EvidenceRef, ClaimState, StateChange, ClaimGraph.
The engine (not the LLM) owns all state transitions — this is the anti-hallucination core.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class ClaimType(str, Enum):
    PERSISTENCE_CONFIGURED = "persistence_configured"
    PAYLOAD_PRESENT = "payload_present"
    PAYLOAD_EXECUTED = "payload_executed"
    PAYLOAD_ACTIVE = "payload_active"
    LATERAL_MOVEMENT = "lateral_movement"
    CREDENTIAL_ACCESS = "credential_access"
    EXFILTRATION = "exfiltration"
    C2_COMMUNICATION = "c2_communication"
    DEFENSE_EVASION = "defense_evasion"
    DISCOVERY = "discovery"


class ClaimState(str, Enum):
    # Single artifact observed; no corroboration yet attempted
    OBSERVED = "OBSERVED"
    # Two+ independent sources agree; confidence >= TAU_CORROB
    CORROBORATED = "CORROBORATED"
    # Some support but below corroboration threshold
    INFERENCE = "INFERENCE"
    # Conflicting evidence — a source actively contradicts this claim
    CONTRADICTED = "CONTRADICTED"
    # Bounded search exhausted; insufficient evidence to decide
    UNRESOLVED = "UNRESOLVED"


# MITRE ATT&CK technique mapping
class AttackTechnique(str, Enum):
    T1547_001 = "T1547.001"   # Registry Run Keys / Startup Folder
    T1059 = "T1059"           # Command and Scripting Interpreter
    T1055 = "T1055"           # Process Injection
    T1003 = "T1003"           # OS Credential Dumping
    T1071 = "T1071"           # Application Layer Protocol
    T1041 = "T1041"           # Exfiltration Over C2 Channel
    T1083 = "T1083"           # File and Directory Discovery
    T1070 = "T1070"           # Indicator Removal
    T1036 = "T1036"           # Masquerading
    T1105 = "T1105"           # Ingress Tool Transfer


@dataclass
class EvidenceRef:
    """Pointer from a claim to its exact forensic artifact — traceable to byte level."""
    ledger_seq: int
    tool: str
    artifact_path: str
    offset: int
    raw_sha256: str
    weight: float
    independent_group: str   # signals in the same group are co-dependent
    parse_quality: float = 1.0

    @property
    def effective_weight(self) -> float:
        return self.weight * self.parse_quality


@dataclass
class StateChange:
    """Records every ruling revision — powers the 'self-correction' demo moment."""
    ts: datetime
    from_state: ClaimState
    to_state: ClaimState
    trigger: str          # e.g. "prefetch.run_record confirmed execution"
    iteration: int
    support_before: float
    support_after: float


@dataclass
class Claim:
    """
    A single forensic assertion about a subject (file, process, key, IP).
    Only the engine mutates state; the agent reads and requests tool execution.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    claim_type: ClaimType = ClaimType.PAYLOAD_PRESENT
    subject: str = ""
    time: Optional[datetime] = None
    state: ClaimState = ClaimState.OBSERVED
    support_score: float = 0.0
    contradiction_score: float = 0.0
    confidence: float = 0.0

    # Evidence attached so far
    evidence: list[EvidenceRef] = field(default_factory=list)
    contradictions: list[EvidenceRef] = field(default_factory=list)

    # Rule and history
    rule_id: str = ""
    history: list[StateChange] = field(default_factory=list)

    # MITRE mapping
    attack_technique: Optional[AttackTechnique] = None
    attack_tactic: str = ""

    # Agent reasoning (Training Mode narration)
    analyst_notes: list[str] = field(default_factory=list)

    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def record_state_change(
        self,
        new_state: ClaimState,
        trigger: str,
        iteration: int,
        new_support: float,
    ) -> None:
        change = StateChange(
            ts=datetime.now(timezone.utc),
            from_state=self.state,
            to_state=new_state,
            trigger=trigger,
            iteration=iteration,
            support_before=self.support_score,
            support_after=new_support,
        )
        self.history.append(change)
        self.state = new_state
        self.support_score = new_support
        self.last_updated = change.ts

    @property
    def is_settled(self) -> bool:
        return self.state in (ClaimState.CORROBORATED, ClaimState.CONTRADICTED)

    @property
    def needs_investigation(self) -> bool:
        return self.state in (ClaimState.OBSERVED, ClaimState.INFERENCE)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "claim_type": self.claim_type.value,
            "subject": self.subject,
            "state": self.state.value,
            "support_score": round(self.support_score, 4),
            "contradiction_score": round(self.contradiction_score, 4),
            "confidence": round(self.confidence, 4),
            "rule_id": self.rule_id,
            "attack_technique": self.attack_technique.value if self.attack_technique else None,
            "attack_tactic": self.attack_tactic,
            "evidence_count": len(self.evidence),
            "history_length": len(self.history),
            "analyst_notes": self.analyst_notes,
        }


@dataclass
class Entity:
    """A forensic entity referenced by claims — file, process, IP, registry key."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    entity_type: str = "file"   # file | process | registry_key | ip | domain
    name: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class ClaimEdge:
    source_id: str
    target_id: str
    edge_type: str   # supports | contradicts | configures | executed | active | exfils_to


@dataclass
class ClaimGraph:
    """
    The full investigation graph: claims, entities, and relationships.
    Rendered as the corroboration-graph UI view.
    """
    run_id: str = ""
    claims: list[Claim] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    edges: list[ClaimEdge] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)

    def add_claim(self, claim: Claim) -> None:
        self.claims.append(claim)

    def get_claim(self, claim_id: str) -> Optional[Claim]:
        return next((c for c in self.claims if c.id == claim_id), None)

    def corroborated_claims(self) -> list[Claim]:
        return [c for c in self.claims if c.state == ClaimState.CORROBORATED]

    def unresolved_claims(self) -> list[Claim]:
        return [c for c in self.claims if c.state == ClaimState.UNRESOLVED]

    def investigation_summary(self) -> dict:
        state_counts = {}
        for s in ClaimState:
            state_counts[s.value] = sum(1 for c in self.claims if c.state == s)
        return {
            "total_claims": len(self.claims),
            "state_distribution": state_counts,
            "attack_techniques": list({
                c.attack_technique.value
                for c in self.claims
                if c.attack_technique and c.state == ClaimState.CORROBORATED
            }),
        }
