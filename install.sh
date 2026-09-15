#!/usr/bin/env bash
# install.sh — Installation script for CLI Network Scanner
#
# This script:
#   1. Checks for Python 3.11+, nmap, and tshark
#   2. Creates a Python virtual environment
#   3. Installs Python dependencies
#
# Usage:
#   chmod +x install.sh
#   ./install.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"

echo "========================================================"
echo "  CLI Network Scanner — Installation"
echo "========================================================"
echo ""

# ------------------------------------------------------------------
# Check Python
# ------------------------------------------------------------------
echo "[*] Checking Python..."

if command -v python3 &>/dev/null; then
    PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

    if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 11 ]; then
        echo "[+] Python ${PY_VERSION} — OK"
    else
        echo "[!] Python ${PY_VERSION} found (3.11+ recommended)"
        echo "    The tool may still work with Python 3.8+"
    fi
else
    echo "[-] Python 3 not found!"
    echo "    Install: sudo apt install python3 python3-venv python3-pip"
    exit 1
fi

# ------------------------------------------------------------------
# Check system dependencies
# ------------------------------------------------------------------
echo ""
echo "[*] Checking system dependencies..."

MISSING=""

if command -v nmap &>/dev/null; then
    NMAP_VER=$(nmap --version 2>/dev/null | head -1)
    echo "[+] Nmap — ${NMAP_VER}"
else
    echo "[-] Nmap not found"
    MISSING="${MISSING} nmap"
fi

if command -v tshark &>/dev/null; then
    TSHARK_VER=$(tshark --version 2>/dev/null | head -1)
    echo "[+] Tshark — ${TSHARK_VER}"
else
    echo "[-] Tshark not found"
    MISSING="${MISSING} tshark"
fi

if [ -n "$MISSING" ]; then
    echo ""
    echo "[!] Missing system packages:${MISSING}"
    echo ""
    echo "    Install with:"
    echo "    sudo apt update && sudo apt install${MISSING}"
    echo ""
    echo "    For tshark, you may also need:"
    echo "    sudo usermod -aG wireshark \$USER"
    echo "    (then log out and back in)"
    echo ""
    read -p "    Continue without them? [y/N] " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# ------------------------------------------------------------------
# Create virtual environment
# ------------------------------------------------------------------
echo ""
echo "[*] Setting up Python virtual environment..."

if [ -d "$VENV_DIR" ]; then
    echo "[+] Virtual environment already exists at ${VENV_DIR}"
else
    python3 -m venv "$VENV_DIR"
    echo "[+] Created virtual environment at ${VENV_DIR}"
fi

# ------------------------------------------------------------------
# Install Python dependencies
# ------------------------------------------------------------------
echo ""
echo "[*] Installing Python dependencies..."

source "${VENV_DIR}/bin/activate"
pip install --upgrade pip -q
pip install -r "${SCRIPT_DIR}/requirements.txt" -q

echo "[+] Python dependencies installed"

# ------------------------------------------------------------------
# Verify
# ------------------------------------------------------------------
echo ""
echo "[*] Verifying installation..."

python3 -c "import psutil; print(f'[+] psutil {psutil.__version__} — OK')"
python3 -c "import pytest; print(f'[+] pytest {pytest.__version__} — OK')"

echo ""
echo "========================================================"
echo "  Installation Complete!"
echo "========================================================"
echo ""
echo "  To activate the virtual environment:"
echo "    source .venv/bin/activate"
echo ""
echo "  To run the full lab:"
echo "    python3 src/main.py full"
echo ""
echo "  Or use the run script:"
echo "    ./run.sh full"
echo ""
