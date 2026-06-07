"""
COUNSEL Launcher - Trusted Entry Point.

The launcher is the only process that:
  1. Holds the evidence path and verifies the read-only mount
  2. Generates the run_id and hashes the evidence (genesis)
  3. Spawns the MCP server with correct environment
  4. After agent exit, calls the Verifier to sign the ledger
  5. Generates the HTML Case File and optional replay

Trust boundary: the launcher never shares its signing key with the agent.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from ..agent.loop import CounselLoop, LoopConfig
from ..mcp_server.config import ServerConfig
from ..redteam.suite import RedTeamSuite
from ..report import html_report, tui
from ..verifier.verify import export_case_package, verify_and_sign
from ..ledger.ledger import Ledger

app = typer.Typer(
    name="counsel",
    help="COUNSEL - Corroboration-First Autonomous DFIR Agent",
    no_args_is_help=True,
)
console = Console()

logging.basicConfig(
    level=os.environ.get("COUNSEL_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("counsel.launcher")


def _hash_evidence(evidence_path: Path) -> str:
    """SHA256 of evidence root. Slow for large images - uses streaming."""
    h = hashlib.sha256()
    if evidence_path.is_file():
        with open(evidence_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
    elif evidence_path.is_dir():
        for child in sorted(evidence_path.rglob("*")):
            if child.is_file():
                h.update(str(child.relative_to(evidence_path)).encode())
                with open(child, "rb") as f:
                    while chunk := f.read(65536):
                        h.update(chunk)
    return h.hexdigest()


def _verify_read_only(evidence_path: Path) -> bool:
    """Verify the evidence root is not writable."""
    probe = evidence_path / ".counsel_mount_probe"
    try:
        probe.write_text("probe")
        probe.unlink()
        return False  # Writable - should fail
    except (PermissionError, OSError):
        return True   # Read-only - correct


@app.command()
def investigate(
    evidence: Path = typer.Argument(..., help="Path to evidence root (read-only mount)"),
    output_dir: Path = typer.Option(
        Path("./counsel-output"), help="Output directory for ledger, report, case package"
    ),
    signing_key: Optional[Path] = typer.Option(None, help="Path to Ed25519 private key PEM"),
    training_mode: bool = typer.Option(False, help="Enable Analyst Training Mode narration"),
    max_iterations: int = typer.Option(25, help="Maximum agent iterations"),
    run_id: Optional[str] = typer.Option(None, help="Override auto-generated run ID"),
    skip_hash: bool = typer.Option(False, help="Skip evidence hashing (fast start, weaker integrity)"),
) -> None:
    """Run a full COUNSEL investigation on an evidence image."""
    tui.print_banner()

    if not evidence.exists():
        console.print(f"[red]Evidence path does not exist: {evidence}[/red]")
        raise typer.Exit(1)

    # Verify read-only mount
    is_ro = _verify_read_only(evidence)
    if not is_ro:
        console.print(
            "[yellow]WARNING: Evidence root appears to be writable. "
            "Mount read-only with: mount -o ro,loop /path/to/image /mnt/evidence[/yellow]"
        )

    run_id = run_id or str(uuid.uuid4())[:12]
    output_dir = output_dir / run_id
    output_dir.mkdir(parents=True, exist_ok=True)
    ledger_path = output_dir / "counsel-ledger.jsonl"

    console.print(f"[dim]Evidence:  {evidence}[/dim]")
    console.print(f"[dim]Run ID:    {run_id}[/dim]")
    console.print(f"[dim]Output:    {output_dir}[/dim]")
    console.print(f"[dim]Read-only: {'yes' if is_ro else 'NO (WARNING)'}[/dim]")

    # Hash evidence
    evidence_sha256 = ""
    if not skip_hash:
        console.print("[dim]Computing evidence SHA256 (may take a moment for large images)…[/dim]")
        start = time.monotonic()
        evidence_sha256 = _hash_evidence(evidence)
        console.print(
            f"[dim]Evidence SHA256: {evidence_sha256[:32]}… ({time.monotonic() - start:.1f}s)[/dim]"
        )
    else:
        console.print("[yellow]Evidence hashing skipped (integrity attestation will be incomplete)[/yellow]")

    # Load rules
    rules_dir = Path(__file__).parent.parent / "rules"

    config = LoopConfig(
        run_id=run_id,
        evidence_root=evidence,
        ledger_path=ledger_path,
        rules_dir=rules_dir,
        training_mode=training_mode,
        max_iterations=max_iterations,
        evidence_sha256=evidence_sha256,
    )

    # Run investigation
    tui.print_investigation_start(run_id, evidence, 0)  # rules count filled in loop
    start = time.monotonic()

    loop = CounselLoop(config)
    claim_graph = asyncio.run(loop.run())
    elapsed = time.monotonic() - start

    # Print verdict to terminal
    tui.print_verdict(claim_graph, elapsed, run_id)
    tui.print_claims_table(claim_graph)
    tui.print_corroboration_graph(claim_graph)

    # Verify and sign
    chain_valid = True
    evidence_sha_out = ""
    if signing_key and signing_key.exists():
        console.print("[dim]Running external verification and signing…[/dim]")
        ver_result = verify_and_sign(
            ledger_path=ledger_path,
            evidence_path=evidence,
            private_key_path=signing_key,
            output_dir=output_dir,
            run_id=run_id,
        )
        chain_valid = ver_result.chain_valid
        evidence_sha_out = ver_result.evidence_sha256_out
        console.print(
            f"[{'green' if ver_result.passed else 'red'}]"
            f"Verification: {'PASSED' if ver_result.passed else 'FAILED'}[/]"
        )
    else:
        console.print("[yellow]Signing key not provided - ledger unsigned (use --signing-key for court-grade)[/yellow]")

    # Generate HTML Case File
    ledger = Ledger(ledger_path, run_id)
    report_path = output_dir / f"counsel_case_{run_id}.html"
    html_report.generate(
        claim_graph=claim_graph,
        ledger=ledger,
        output_path=report_path,
        run_id=run_id,
        elapsed_seconds=elapsed,
        evidence_sha_in=evidence_sha256,
        evidence_sha_out=evidence_sha_out,
        chain_valid=chain_valid,
    )
    console.print(f"[green]HTML Case File: {report_path}[/green]")

    # Export case package
    package_path = output_dir / f"counsel_case_{run_id}.tar.gz"
    manifest_path = output_dir / f"manifest_{run_id}.json"
    if manifest_path.exists():
        export_case_package(
            ledger_path=ledger_path,
            manifest_path=manifest_path,
            report_dir=output_dir,
            output_path=package_path,
            run_id=run_id,
        )
        console.print(f"[green]Case Package: {package_path}[/green]")

    console.print(f"\n[bold green]Investigation complete.[/bold green] Elapsed: {elapsed:.1f}s")


@app.command()
def replay(
    ledger_file: Path = typer.Argument(..., help="Path to ledger JSONL file"),
    seq: int = typer.Argument(..., help="Ledger sequence number to replay"),
    evidence: Path = typer.Option(..., help="Path to evidence root"),
) -> None:
    """Replay a specific ledger entry and verify its raw output hash."""
    from ..mcp_server.config import ServerConfig
    cfg = ServerConfig(evidence_root=evidence, run_id="replay")
    ledger = Ledger(ledger_file, run_id="replay")
    result = ledger.replay(seq, cfg)
    tui.print_ledger_replay(result)


@app.command()
def redteam(
    evidence: Path = typer.Argument(..., help="Path to evidence root (can be empty dir)"),
    ledger_file: Optional[Path] = typer.Option(None, help="Ledger file for RT6 chain test"),
) -> None:
    """Run the RT1-RT7 red-team test suite against the current configuration."""
    tui.print_banner()
    console.print("[bold]Red-Team Test Suite[/bold]")
    suite = RedTeamSuite(evidence_root=evidence, ledger_path=ledger_file)
    suite.run_all()
    suite.print_report()


@app.command()
def keygen(
    key_dir: Path = typer.Argument(Path("~/.counsel/keys"), help="Directory to store keypair"),
) -> None:
    """Generate an Ed25519 signing keypair for ledger verification."""
    from ..verifier.verify import generate_keypair
    key_dir = key_dir.expanduser()
    priv, pub = generate_keypair(key_dir)
    console.print(f"[green]Private key:[/green] {priv}")
    console.print(f"[green]Public key:[/green]  {pub}")
    console.print("[yellow]Keep the private key outside the evidence analysis environment.[/yellow]")


@app.command()
def verify_package(
    package: Path = typer.Argument(..., help="Path to .tar.gz case package"),
    public_key: Path = typer.Argument(..., help="Path to Ed25519 public key PEM"),
) -> None:
    """Verify a COUNSEL case package exported by another analyst."""
    from ..verifier.verify import verify_package as vp
    result = vp(package, public_key)
    color = "green" if result["valid"] else "red"
    console.print(f"[{color}]Package valid: {result['valid']}[/{color}]")
    if result.get("signature_valid") is not None:
        console.print(f"Signature valid: {result['signature_valid']}")
    if result.get("errors"):
        for e in result["errors"]:
            console.print(f"[red]  {e}[/red]")
    console.print(json.dumps(result.get("manifest", {}), indent=2))


# ─── Allow direct invocation ─────────────────────────────────────────────────

import json  # noqa: E402 - needed for verify_package command above

if __name__ == "__main__":
    app()
