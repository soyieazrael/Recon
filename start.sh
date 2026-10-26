#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Clear the terminal before showing the startup message.
clear 2>/dev/null || printf '\033[2J\033[H'
printf '\n========================================\n'
printf '          SoyieSec starting...\n'
printf '     Authorized security testing only\n'
printf '========================================\n\n'

if ! command -v python3 >/dev/null 2>&1; then
    echo '[!] Python 3 is required. Run ./install.sh first.'
    exit 1
fi

if [[ ! -f "$SCRIPT_DIR/soyie.py" ]]; then
    echo '[!] soyie.py was not found beside start.sh.'
    exit 1
fi

exec sudo python3 "$SCRIPT_DIR/soyie.py"
