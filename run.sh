#!/usr/bin/env bash
# run.sh — Run the CLI Network Scanner
#
# Automatically activates the virtual environment and runs the scanner.
#
# Usage:
#   chmod +x run.sh
#   ./run.sh full        # Complete autopilot workflow
#   ./run.sh scan        # Port scan only
#   ./run.sh lab         # Start lab servers only
#   ./run.sh capture     # Packet capture only
#   ./run.sh --help      # Show help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"

# Activate virtual environment if it exists
if [ -d "$VENV_DIR" ]; then
    source "${VENV_DIR}/bin/activate"
fi

# Run the scanner with all provided arguments
python3 "${SCRIPT_DIR}/src/main.py" "$@"
