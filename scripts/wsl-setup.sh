#!/usr/bin/env bash
# Run this inside WSL2 Ubuntu (any version):
#   bash '/mnt/c/Hackathons/FIND EVIL!/scripts/wsl-setup.sh'
set -e

# Fix any interrupted dpkg first
sudo dpkg --configure -a 2>/dev/null || true

echo "=== [1/6] Installing system dependencies ==="
sudo apt-get install -y \
    python3 python3-pip python3-venv python3-dev \
    mono-complete \
    tshark \
    yara \
    git \
    curl \
    libssl-dev

echo "Python: $(python3 --version)"

echo ""
echo "=== [2/6] Installing Protocol SIFT ==="
if command -v rla &>/dev/null || test -f /usr/share/doc/recmd/rla.exe; then
    echo "Protocol SIFT already installed, skipping."
else
    curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash || \
        echo "Protocol SIFT install had errors (may be partial - continuing)"
fi

echo ""
echo "=== [3/6] Installing evtx_dump ==="
pip3 install --quiet evtx 2>/dev/null && echo "evtx installed" || \
    pip3 install --break-system-packages --quiet evtx 2>/dev/null && echo "evtx installed" || \
    echo "evtx install skipped"

echo ""
echo "=== [4/6] Installing COUNSEL ==="
COUNSEL_DIR='/mnt/c/Hackathons/FIND EVIL!'
cd "$COUNSEL_DIR"
# Ubuntu 24.04 needs --break-system-packages or a venv
pip3 install --break-system-packages -e . 2>/dev/null || pip3 install -e .
echo "COUNSEL installed. Testing..."
counsel --help | head -3

echo ""
echo "=== [5/6] Generating signing key ==="
KEY_DIR="$HOME/.counsel/keys"
mkdir -p "$KEY_DIR"
if [ ! -f "$KEY_DIR/counsel_signing.pem" ]; then
    counsel keygen "$KEY_DIR"
    echo "Key generated: $KEY_DIR"
else
    echo "Key already exists: $KEY_DIR"
fi

echo ""
echo "=== [6/6] Tool detection ==="
python3 - <<'EOF'
import sys
sys.path.insert(0, '/mnt/c/Hackathons/FIND EVIL!')
from counsel.mcp_server.config import ToolPaths
t = ToolPaths()
tools = {
    "RECmd (registry)":  t.recmd,
    "PECmd (prefetch)":  t.pecmd,
    "AmcacheParser":     t.amcache_parser,
    "MFTECmd":           t.mft_ecmd,
    "Volatility3":       t.volatility,
    "tshark":            t.tshark,
    "yara":              t.yara,
    "evtx_dump":         t.evtx_dump,
}
for name, path in tools.items():
    icon = "[OK]" if path else "[--]"
    print(f"  {icon} {name}: {path or 'not found'}")
EOF

echo ""
echo "=== Setup complete ==="
echo ""
echo "Set your API key (if not already in ~/.bashrc):"
echo "  export ANTHROPIC_API_KEY=your_key_here"
echo ""
echo "Then investigate:"
echo "  counsel investigate ~/evidence/ --signing-key $HOME/.counsel/keys/counsel_signing.pem"
