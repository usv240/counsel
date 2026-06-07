"""
Corroboration Rule DSL — YAML loader, compiler, and validator.

The DSL is a declarative YAML language that encodes DFIR corroboration knowledge.
Bad rules fail at load time (fail-closed). Good rules produce an evaluator the
confidence model can run against live signal sets.
"""
from __future__ import annotations

import operator
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

from .model import ClaimType

# ---------------------------------------------------------------------------
# Schema types produced by the compiler
# ---------------------------------------------------------------------------

KNOWN_TOOLS = {
    "registry.run_keys", "prefetch.run_record", "amcache.lookup",
    "fs.stat_hash", "mft.timeline", "yara.scan", "mem.pslist",
    "mem.netscan", "mem.malfind", "net.flows", "evtx.query",
}

KNOWN_CLAIM_TYPES = {ct.value for ct in ClaimType}


@dataclass
class SignalSpec:
    artifact: str           # e.g. "prefetch.run_record"
    supports: str           # ClaimType value
    weight: float
    independent_group: str  # signals with the same group share one pool
    requires: Optional[str] = None  # predicate expression, or None


@dataclass
class ModifierSpec:
    artifact: str
    effect: str             # "benign_indicator" | "suspicion"
    requires: Optional[str] = None
    note: str = ""


@dataclass
class ContradictionSpec:
    artifact: str
    weight: float
    requires: Optional[str] = None


@dataclass
class CompiledRule:
    rule_id: str
    emits: list[str]         # ClaimType values this rule can produce
    signals: list[SignalSpec]
    modifiers: list[ModifierSpec]
    contradictions: list[ContradictionSpec]
    provenance: str          # must be non-empty (fail-closed if missing)

    # Derived: which tools are needed (for gap detection)
    required_tools: set[str] = field(default_factory=set)
    optional_tools: set[str] = field(default_factory=set)

    def tools_for_claim(self, claim_type: str) -> list[SignalSpec]:
        return [s for s in self.signals if s.supports == claim_type]


# ---------------------------------------------------------------------------
# Predicate evaluator (simple field OP value expressions)
# ---------------------------------------------------------------------------

_OPERATORS: dict[str, Callable[[Any, Any], bool]] = {
    "==": operator.eq,
    "!=": operator.ne,
    ">":  operator.gt,
    ">=": operator.ge,
    "<":  operator.lt,
    "<=": operator.le,
    "NOT_IN": lambda a, b: a not in b,
    "IN":     lambda a, b: a in b,
}

_PREDICATE_RE = re.compile(
    r"^(\w+)\s+(==|!=|>=|<=|>|<|NOT_IN|IN)\s+(.+)$"
)


def evaluate_predicate(predicate: str, record: dict) -> bool:
    """
    Evaluate a predicate string against a tool record dict.
    Returns True if the predicate holds (or if predicate is None/empty).
    Fails closed: malformed predicates return False.
    """
    if not predicate:
        return True

    m = _PREDICATE_RE.match(predicate.strip())
    if not m:
        return False

    field_name, op_str, raw_value = m.groups()
    raw_value = raw_value.strip().strip('"').strip("'")

    if field_name not in record:
        return False

    actual = record[field_name]
    op_fn = _OPERATORS.get(op_str)
    if op_fn is None:
        return False

    # Type coercion: booleans
    if raw_value.lower() == "true":
        raw_value = True
    elif raw_value.lower() == "false":
        raw_value = False

    try:
        return bool(op_fn(actual, raw_value))
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Compiler
# ---------------------------------------------------------------------------

class DSLCompileError(Exception):
    pass


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise DSLCompileError(msg)


def compile_rule(raw: dict) -> CompiledRule:
    """Compile a raw YAML dict into a CompiledRule. Raises DSLCompileError on bad input."""
    rule_id = raw.get("rule", "")
    _require(bool(rule_id), "rule: field is required and must be a non-empty string")
    _require(re.match(r"^\w+$", rule_id), f"rule ID '{rule_id}' must be alphanumeric/underscore")

    emits_raw = raw.get("emits", [])
    _require(isinstance(emits_raw, list) and emits_raw, f"Rule '{rule_id}': emits must be a non-empty list")
    for e in emits_raw:
        _require(e in KNOWN_CLAIM_TYPES, f"Rule '{rule_id}': unknown claim type '{e}'")

    provenance = raw.get("provenance", "")
    _require(bool(provenance), f"Rule '{rule_id}': provenance is required (cite your DFIR source)")

    # --- signals ---
    signals_raw = raw.get("signals", [])
    _require(isinstance(signals_raw, list) and signals_raw, f"Rule '{rule_id}': signals must be non-empty")

    signals = []
    for i, s in enumerate(signals_raw):
        artifact = s.get("artifact", "")
        _require(artifact in KNOWN_TOOLS, f"Rule '{rule_id}' signal {i}: unknown tool '{artifact}'")
        supports = s.get("supports", "")
        _require(supports in KNOWN_CLAIM_TYPES, f"Rule '{rule_id}' signal {i}: unknown claim '{supports}'")
        weight = float(s.get("weight", 0.0))
        _require(0.0 <= weight <= 1.0, f"Rule '{rule_id}' signal {i}: weight must be in [0,1]")
        # independent_of determines group; default = same as artifact (fully independent)
        independent_of = s.get("independent_of", artifact)
        signals.append(SignalSpec(
            artifact=artifact,
            supports=supports,
            weight=weight,
            independent_group=independent_of,
            requires=s.get("requires"),
        ))

    # --- contradictions ---
    contradictions = []
    for c in raw.get("contradictions", []):
        artifact = c.get("artifact", "")
        _require(artifact in KNOWN_TOOLS, f"Rule '{rule_id}' contradiction: unknown tool '{artifact}'")
        weight = float(c.get("weight", 0.5))
        contradictions.append(ContradictionSpec(
            artifact=artifact,
            weight=weight,
            requires=c.get("requires"),
        ))

    # --- modifiers ---
    modifiers = []
    for m in raw.get("modifiers", []):
        artifact = m.get("artifact", "")
        effect = m.get("effect", "")
        _require(effect in ("benign_indicator", "suspicion"),
                 f"Rule '{rule_id}' modifier: effect must be 'benign_indicator' or 'suspicion'")
        modifiers.append(ModifierSpec(
            artifact=artifact,
            effect=effect,
            requires=m.get("requires"),
            note=m.get("note", ""),
        ))

    # Derive tool sets
    required_tools = {s.artifact for s in signals}
    optional_tools = {m.artifact for m in modifiers} | {c.artifact for c in contradictions}

    return CompiledRule(
        rule_id=rule_id,
        emits=emits_raw,
        signals=signals,
        modifiers=modifiers,
        contradictions=contradictions,
        provenance=provenance,
        required_tools=required_tools,
        optional_tools=optional_tools,
    )


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, CompiledRule] = {}

    def load_directory(self, rules_dir: Path) -> list[str]:
        """
        Load all *.yaml files from rules_dir. Returns list of loaded rule IDs.
        Supports multi-document YAML files (rules separated by ---).
        Fails closed: any invalid rule in any file aborts the load.
        """
        loaded = []
        errors = []
        for path in sorted(rules_dir.glob("*.yaml")):
            try:
                with open(path) as f:
                    # yaml.safe_load_all handles both single-doc and multi-doc (---) files
                    docs = list(yaml.safe_load_all(f))
                for doc in docs:
                    if doc is None:
                        continue
                    items = doc if isinstance(doc, list) else [doc]
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        rule = compile_rule(item)
                        self._rules[rule.rule_id] = rule
                        loaded.append(rule.rule_id)
            except DSLCompileError as e:
                errors.append(f"{path.name}: {e}")
            except Exception as e:
                errors.append(f"{path.name}: YAML parse error: {e}")
        if errors:
            raise DSLCompileError("Rule load errors:\n" + "\n".join(errors))
        return loaded

    def get(self, rule_id: str) -> Optional[CompiledRule]:
        return self._rules.get(rule_id)

    def all_rules(self) -> list[CompiledRule]:
        return list(self._rules.values())

    def rules_for_claim(self, claim_type: str) -> list[CompiledRule]:
        return [r for r in self._rules.values() if claim_type in r.emits]

    def catalog_hash(self) -> str:
        """Deterministic hash of the loaded rule set — pinned in the ledger genesis entry."""
        import hashlib
        import json
        catalog = {
            rid: {
                "emits": r.emits,
                "provenance": r.provenance,
                "signal_count": len(r.signals),
            }
            for rid, r in sorted(self._rules.items())
        }
        return hashlib.sha256(json.dumps(catalog, sort_keys=True).encode()).hexdigest()
