#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

printf '\n========================================\n'
printf '        SoyieSec Setup Installer\n'
printf '========================================\n\n'

if ! command -v python3 >/dev/null 2>&1; then
    echo '[!] Python 3 was not found.'
    echo '[*] On Kali/Debian/Ubuntu, install it with:'
    echo '    sudo apt update && sudo apt install -y python3 python3-pip'
    exit 1
fi

python3 --version

if ! python3 -m pip --version >/dev/null 2>&1; then
    echo '[*] pip is not available; attempting to install it through apt...'
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update
        sudo apt-get install -y python3-pip
    else
        echo '[!] Please install pip for Python 3 using your OS package manager.'
        exit 1
    fi
fi

if grep -Eq '^[[:space:]]*[^#[:space:]]' "$SCRIPT_DIR/requirements.txt"; then
    echo '[*] Installing Python requirements...'
    python3 -m pip install -r "$SCRIPT_DIR/requirements.txt"
else
    echo '[*] No third-party Python packages are required by the current version.'
fi

echo
echo '[+] Setup complete.'
echo '[*] Start the tool with: ./start.sh'
