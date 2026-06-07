"""
COUNSEL External Verifier + Ed25519 Signer.

Runs as a SEPARATE PROCESS after agent exit. The agent never sees the signing key.
This is the critical trust boundary: ledger chain is tamper-evident only if
the final manifest is signed by a key the agent cannot access.

Steps:
  1. Re-hash the evidence image - confirms byte-identical (no spoliation).
  2. Re-verify the entire hash chain from genesis.
  3. Sign the manifest with Ed25519 key stored in a file the agent cannot read.
  4. Write signed manifest alongside the ledger.
  5. Export a sealed case package (ledger + manifest + signature + report).
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
        load_pem_private_key,
        load_pem_public_key,
    )
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


def _sha256_path(path: Path, chunk_size: int = 65536) -> str:
    """Compute SHA256 of a file or directory recursively."""
    h = hashlib.sha256()
    if path.is_file():
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
    elif path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.is_file():
                h.update(str(child.relative_to(path)).encode())
                with open(child, "rb") as f:
                    while chunk := f.read(chunk_size):
                        h.update(chunk)
    return h.hexdigest()


# ─── Key management ──────────────────────────────────────────────────────────

def generate_keypair(key_dir: Path) -> tuple[Path, Path]:
    """
    Generate an Ed25519 keypair and save to key_dir.
    Returns (private_key_path, public_key_path).
    Called once during setup - private key must never be accessible to the agent.
    """
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("cryptography package required: pip install cryptography")

    key_dir.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_path = key_dir / "counsel_signing.pem"
    pub_path = key_dir / "counsel_signing_pub.pem"

    priv_path.write_bytes(
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    pub_path.write_bytes(
        public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    # Restrict private key permissions (Unix)
    try:
        os.chmod(priv_path, 0o600)
    except OSError:
        pass

    return priv_path, pub_path


def load_private_key(key_path: Path) -> "Ed25519PrivateKey":
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("cryptography package required")
    return load_pem_private_key(key_path.read_bytes(), password=None)


def load_public_key(key_path: Path) -> "Ed25519PublicKey":
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("cryptography package required")
    return load_pem_public_key(key_path.read_bytes())


# ─── Verification pipeline ───────────────────────────────────────────────────

class VerificationResult:
    def __init__(self) -> None:
        self.chain_valid: bool = False
        self.chain_errors: list[str] = []
        self.evidence_sha256_in: str = ""
        self.evidence_sha256_out: str = ""
        self.evidence_intact: bool = False
        self.manifest_signed: bool = False
        self.signature_hex: str = ""
        self.run_id: str = ""
        self.ts: str = datetime.now(timezone.utc).isoformat()

    @property
    def passed(self) -> bool:
        return self.chain_valid and self.evidence_intact

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "ts": self.ts,
            "chain_valid": self.chain_valid,
            "chain_errors": self.chain_errors,
            "evidence_sha256_in": self.evidence_sha256_in,
            "evidence_sha256_out": self.evidence_sha256_out,
            "evidence_intact": self.evidence_intact,
            "manifest_signed": self.manifest_signed,
            "signature_hex": self.signature_hex,
            "passed": self.passed,
        }


def verify_and_sign(
    ledger_path: Path,
    evidence_path: Path,
    private_key_path: Path,
    output_dir: Path,
    run_id: str,
) -> VerificationResult:
    """
    Full verification pipeline. Called after agent exit.

    1. Verify hash chain integrity
    2. Re-hash evidence (confirms no spoliation)
    3. Sign manifest with Ed25519 private key
    4. Write signed manifest to output_dir
    """
    from ..ledger.ledger import Ledger, GENESIS_HASH

    result = VerificationResult()
    result.run_id = run_id

    # Step 1: Chain verification
    ledger = Ledger(ledger_path, run_id)
    result.chain_valid, result.chain_errors = ledger.verify_chain()

    # Step 2: Evidence re-hash
    genesis_entry = ledger.read_entry(0)
    if genesis_entry:
        result.evidence_sha256_in = genesis_entry["payload"].get("evidence_sha256_in", "")

    if evidence_path.exists():
        result.evidence_sha256_out = _sha256_path(evidence_path)
        result.evidence_intact = (
            result.evidence_sha256_in == result.evidence_sha256_out
        )
    else:
        result.chain_errors.append(f"Evidence path not found: {evidence_path}")

    # Step 3: Sign manifest
    manifest = {
        "run_id": run_id,
        "chain_head_hash": ledger.head_hash(),
        "evidence_sha256_in": result.evidence_sha256_in,
        "evidence_sha256_out": result.evidence_sha256_out,
        "evidence_intact": result.evidence_intact,
        "chain_valid": result.chain_valid,
        "ts": result.ts,
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, ensure_ascii=True).encode()

    if HAS_CRYPTOGRAPHY and private_key_path.exists():
        try:
            priv_key = load_private_key(private_key_path)
            signature = priv_key.sign(manifest_bytes)
            result.signature_hex = signature.hex()
            result.manifest_signed = True
        except Exception as e:
            result.chain_errors.append(f"Signing failed: {e}")
    else:
        result.chain_errors.append(
            "Ed25519 signing skipped - cryptography not installed or key not found"
        )

    # Write manifest + signature
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / f"manifest_{run_id}.json"
    manifest_path.write_text(
        json.dumps({**manifest, "signature": result.signature_hex}, indent=2),
        encoding="utf-8",
    )

    return result


def export_case_package(
    ledger_path: Path,
    manifest_path: Path,
    report_dir: Path,
    output_path: Path,
    run_id: str,
) -> Path:
    """
    Bundle ledger + manifest + report into a single verifiable archive.
    Any practitioner can independently validate with verify_package().
    """
    with tarfile.open(output_path, "w:gz") as tar:
        for path in [ledger_path, manifest_path]:
            if path.exists():
                tar.add(path, arcname=f"counsel_case_{run_id}/{path.name}")
        if report_dir.exists():
            for f in report_dir.rglob("*"):
                if f.is_file():
                    tar.add(f, arcname=f"counsel_case_{run_id}/report/{f.relative_to(report_dir)}")
    return output_path


def verify_package(package_path: Path, public_key_path: Path) -> dict:
    """
    Verify a case package exported by export_case_package().
    Returns verification result dict - can be run by any third party.
    """
    import tempfile
    results: dict = {"package": str(package_path), "valid": False, "errors": []}

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        with tarfile.open(package_path, "r:gz") as tar:
            tar.extractall(tmp)

        # Find manifest
        manifests = list(tmp.rglob("manifest_*.json"))
        if not manifests:
            results["errors"].append("No manifest found in package")
            return results

        manifest_data = json.loads(manifests[0].read_text())
        sig_hex = manifest_data.pop("signature", "")

        if HAS_CRYPTOGRAPHY and public_key_path.exists() and sig_hex:
            try:
                pub_key = load_public_key(public_key_path)
                sig_bytes = bytes.fromhex(sig_hex)
                manifest_bytes = json.dumps(manifest_data, sort_keys=True, ensure_ascii=True).encode()
                pub_key.verify(sig_bytes, manifest_bytes)
                results["signature_valid"] = True
            except Exception as e:
                results["errors"].append(f"Signature invalid: {e}")
                results["signature_valid"] = False
        else:
            results["signature_valid"] = None  # not verified

        results["manifest"] = manifest_data
        results["valid"] = not results["errors"]

    return results
