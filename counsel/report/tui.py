"""
COUNSEL Rich Terminal UI — live investigation display for SIFT Workstation.

Terminal-first design (no browser needed). Shows:
  1. Live claim state updates with color-coded 5-state tokens
  2. Corroboration graph (ASCII-art for terminal)
  3. Agent rationale stream (Analyst Training Mode)
  4. Ledger replay interface

Claim-state color tokens:
  OBSERVED      — dim white [OBS]
  INFERENCE     — yellow    [INF]
  CORROBORATED  — green     [COR]
  CONTRADICTED  — red       [CON]
  UNRESOLVED    — grey      [UNR]
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from ..engine.model import Claim, ClaimGraph, ClaimState

console = Console()

# State -> (color, token) mapping
STATE_STYLE: dict[ClaimState, tuple[str, str]] = {
    ClaimState.OBSERVED:     ("dim white",  "[OBS]"),
    ClaimState.INFERENCE:    ("yellow",     "[INF]"),
    ClaimState.CORROBORATED: ("bold green", "[COR]"),
    ClaimState.CONTRADICTED: ("bold red",   "[CON]"),
    ClaimState.UNRESOLVED:   ("grey50",     "[UNR]"),
}


def _state_badge(state: ClaimState) -> Text:
    color, token = STATE_STYLE.get(state, ("white", "[???]"))
    return Text(token, style=color)


def print_banner() -> None:
    console.print(Panel(
        "[bold cyan]COUNSEL[/bold cyan] — Corroboration-First Autonomous DFIR Agent\n"
        "[dim]Every finding traces to evidence. Every ruling is earned.[/dim]\n"
        "[dim]SANS FIND EVIL! Hackathon 2026[/dim]",
        border_style="cyan",
        padding=(1, 4),
    ))


def print_investigation_start(run_id: str, evidence_root: Path, rules_count: int) -> None:
    console.print(Rule(f"[cyan]Investigation Started[/cyan]"))
    console.print(f"  Run ID:        [bold]{run_id}[/bold]")
    console.print(f"  Evidence root: [cyan]{evidence_root}[/cyan]")
    console.print(f"  Rules loaded:  [green]{rules_count}[/green] corroboration rules")
    console.print()


def print_triage_start() -> None:
    console.print(Rule("[yellow]PHASE: TRIAGE[/yellow]"))
    console.print("[dim]Running fast broad sweep to seed hypotheses...[/dim]")


def print_tool_call(tool: str, args: dict, iteration: int) -> None:
    args_short = json.dumps(args)[:80]
    console.print(
        f"  [dim]iter {iteration:02d}[/dim] [cyan]{tool}[/cyan]"
        f"[dim]({args_short})[/dim]"
    )


def print_tool_result(
    tool: str,
    record_count: int,
    parse_quality: float,
    warnings: list[str],
    seq: int,
) -> None:
    quality_color = "green" if parse_quality >= 0.8 else ("yellow" if parse_quality >= 0.5 else "red")
    console.print(
        f"  [dim]  -> seq={seq} records={record_count} "
        f"quality=[{quality_color}]{parse_quality:.0%}[/{quality_color}][/dim]"
    )
    for w in warnings:
        console.print(f"  [dim yellow]  !! {w}[/dim yellow]")


def print_claim_state_change(
    claim_id: str,
    claim_type: str,
    subject: str,
    from_state: str,
    to_state: str,
    support: float,
    is_ruling_change: bool = False,
) -> None:
    from_cs = ClaimState(from_state) if from_state != "NONE" else None
    to_cs = ClaimState(to_state)

    if from_cs is None:
        line = (
            f"  CLAIM [{claim_id}] {claim_type} ({subject[:40]}): "
        )
        line_text = Text(line)
        line_text.append_text(_state_badge(to_cs))
        line_text.append(f" support={support:.2f}")
    else:
        line_text = Text(f"  CLAIM [{claim_id}] {claim_type}: ")
        line_text.append_text(_state_badge(from_cs))
        line_text.append(" -> ")
        line_text.append_text(_state_badge(to_cs))
        line_text.append(f" support={support:.2f}")

    if is_ruling_change:
        console.print()
        console.print(Panel(
            line_text,
            title="[bold yellow]RULING CHANGE[/bold yellow]",
            border_style="yellow",
            padding=(0, 2),
        ))
        console.print()
    else:
        console.print(line_text)


def print_self_correction(description: str) -> None:
    console.print()
    console.print(Panel(
        f"[bold]SELF-CORRECTION[/bold]\n{description}",
        border_style="magenta",
        padding=(0, 2),
    ))
    console.print()


def print_claims_table(claim_graph: ClaimGraph) -> None:
    table = Table(
        "ID", "Type", "Subject", "State", "Support", "Contradiction", "Evidence",
        title="[bold]Current Claims[/bold]",
        box=box.ROUNDED,
        border_style="cyan",
        show_lines=True,
    )

    for claim in claim_graph.claims:
        color, token = STATE_STYLE.get(claim.state, ("white", "[???]"))
        table.add_row(
            claim.id,
            claim.claim_type.value,
            claim.subject[:35] + ("…" if len(claim.subject) > 35 else ""),
            Text(token, style=color),
            f"{claim.support_score:.2f}",
            f"{claim.contradiction_score:.2f}",
            str(len(claim.evidence)),
        )

    console.print(table)


def print_corroboration_graph(claim_graph: ClaimGraph) -> None:
    """ASCII corroboration graph — shows relationships between claims."""
    console.print(Rule("[cyan]Corroboration Graph[/cyan]"))

    if not claim_graph.claims:
        console.print("[dim]  (no claims yet)[/dim]")
        return

    tree = Tree("[bold cyan]Investigation[/bold cyan]")

    # Group by state
    by_state: dict[ClaimState, list[Claim]] = {}
    for claim in claim_graph.claims:
        by_state.setdefault(claim.state, []).append(claim)

    for state in ClaimState:
        claims = by_state.get(state, [])
        if not claims:
            continue
        color, token = STATE_STYLE.get(state, ("white", "[???]"))
        state_branch = tree.add(Text(f"{token} {state.value} ({len(claims)})", style=color))
        for claim in claims:
            claim_node = state_branch.add(
                f"[dim]{claim.id}[/dim] {claim.claim_type.value} — {claim.subject[:40]}"
            )
            for ev in claim.evidence[:3]:
                claim_node.add(
                    f"[dim]seq={ev.ledger_seq} {ev.tool} w={ev.weight:.2f}[/dim]"
                )

    console.print(tree)


def print_verdict(claim_graph: ClaimGraph, elapsed_seconds: float, run_id: str) -> None:
    console.print()
    console.print(Rule("[bold green]COUNSEL VERDICT[/bold green]"))

    summary = claim_graph.investigation_summary()

    console.print(f"[dim]Run ID:[/dim] {run_id}")
    console.print(f"[dim]Elapsed:[/dim] {elapsed_seconds:.1f}s")
    console.print()

    # Corroborated
    corroborated = claim_graph.corroborated_claims()
    if corroborated:
        console.print("[bold green]CORROBORATED FINDINGS:[/bold green]")
        for c in corroborated:
            technique = c.attack_technique.value if c.attack_technique else "ATT&CK TBD"
            console.print(
                f"  [green][COR][/green] {c.claim_type.value} — {c.subject}\n"
                f"       ATT&CK: {technique}  |  Confidence: {c.support_score:.2f}\n"
                f"       Evidence: {' + '.join(ev.tool for ev in c.evidence)}"
            )

    # Inference
    inference = [c for c in claim_graph.claims if c.state == ClaimState.INFERENCE]
    if inference:
        console.print()
        console.print("[yellow]INFERENCE (not yet corroborated):[/yellow]")
        for c in inference:
            console.print(
                f"  [yellow][INF][/yellow] {c.claim_type.value} — {c.subject}\n"
                f"       Support: {c.support_score:.2f} — needs independent corroboration"
            )

    # Unresolved
    unresolved = claim_graph.unresolved_claims()
    if unresolved:
        console.print()
        console.print("[grey50]UNRESOLVED:[/grey50]")
        for c in unresolved:
            console.print(f"  [grey50][UNR][/grey50] {c.claim_type.value} — {c.subject}")

    # ATT&CK summary
    techniques = summary.get("attack_techniques", [])
    if techniques:
        console.print()
        console.print("[bold]ATT&CK Techniques Identified:[/bold]")
        for t in techniques:
            console.print(f"  [cyan]{t}[/cyan]")

    console.print()
    console.print(Rule("[dim]End of Verdict[/dim]"))


def print_ledger_replay(replay_result: dict) -> None:
    match = replay_result.get("match", False)
    verdict = replay_result.get("verdict", "UNKNOWN")
    color = "green" if match else "red"
    console.print(Panel(
        f"[bold]Ledger Replay — seq={replay_result.get('seq')}[/bold]\n"
        f"Tool: {replay_result.get('tool', 'unknown')}\n"
        f"Original SHA256:  {replay_result.get('original_sha256', '')[:32]}…\n"
        f"Replayed SHA256:  {replay_result.get('replayed_sha256', '')[:32]}…\n"
        f"Verdict: [{color}]{verdict}[/{color}]",
        border_style=color,
        title="[bold]Replay Verification[/bold]",
    ))
