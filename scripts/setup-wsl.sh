#!/usr/bin/env bash
# COUNSEL WSL2/SIFT setup script
# Run this inside Ubuntu (WSL2) after: wsl --install -d Ubuntu-22.04
# Usage: bash setup-wsl.sh [path-to-evidence]
set -e

EVIDENCE_DIR="${1:-/mnt/evidence}"
COUNSEL_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== COUNSEL SIFT Setup ==="
echo "Repo:     $COUNSEL_DIR"
echo "Evidence: $EVIDENCE_DIR"
echo ""

# 1. System dependencies
echo "[1/6] Installing system packages..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    python3 python3-pip python3-venv \
    mono-complete \
    tshark \
    yara \
    libssl-dev

# 2. Install evtx_dump (Rust binary for Windows event log parsing)
echo "[2/6] Installing evtx_dump..."
if ! command -v evtx_dump &>/dev/null; then
    pip3 install --quiet evtx 2>/dev/null || \
    cargo install evtx 2>/dev/null || \
    echo "  evtx_dump not installed - EVTX parsing will be limited"
fi

# 3. Install Protocol SIFT (Eric Zimmerman tools + vol3 etc.)
echo "[3/6] Installing Protocol SIFT..."
if ! command -v rla &>/dev/null && ! test -f /usr/share/doc/recmd/rla.exe; then
    curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash
else
    echo "  Protocol SIFT already installed, skipping."
fi

# 4. Install COUNSEL Python package
echo "[4/6] Installing COUNSEL..."
cd "$COUNSEL_DIR"
pip3 install --quiet -e .

# 5. Generate signing key (if not present)
echo "[5/6] Checking signing key..."
KEY_DIR="$HOME/.counsel/keys"
if [ ! -f "$KEY_DIR/counsel_signing.pem" ]; then
    mkdir -p "$KEY_DIR"
    counsel keygen "$KEY_DIR"
    echo "  Signing key generated at $KEY_DIR"
else
    echo "  Signing key already exists at $KEY_DIR"
fi

# 6. Verify ANTHROPIC_API_KEY is set
echo "[6/6] Checking environment..."
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo ""
    echo "  IMPORTANT: Set your Anthropic API key before running:"
    echo "  export ANTHROPIC_API_KEY=your_key_here"
    echo "  (Add to ~/.bashrc to persist)"
fi

echo ""
echo "=== Setup complete ==="
echo ""
echo "To run an investigation:"
echo "  # Mount evidence read-only (replace szechuan.raw with your image):"
echo "  sudo mkdir -p /mnt/evidence"
echo "  sudo mount -o ro,loop /path/to/szechuan.raw /mnt/evidence"
echo ""
echo "  # Run COUNSEL:"
echo "  counsel investigate /mnt/evidence \\"
echo "      --signing-key $KEY_DIR/counsel_signing.pem \\"
echo "      --output-dir ./counsel-output"
echo ""
echo "  # Or fixture mode (no real evidence needed):"
echo "  counsel investigate counsel/fixtures/szechuan_sauce/ \\"
echo "      --signing-key $KEY_DIR/counsel_signing.pem"
