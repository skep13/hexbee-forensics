#!/usr/bin/env bash
# HexBee Queen setup for Kali Linux (the ThinkPad T470 analyst workstation).
# Installs the analyst CLI (hexbee-queen) and the Comb forensic toolkit
# (hexbee-comb) into an isolated venv via pipx, and pulls in the system
# forensics tools Comb can use.
#
# Run from the repo root:  bash queen/setup-kali.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> HexBee Queen setup (Kali)"

if ! command -v pipx >/dev/null 2>&1; then
    echo "==> Installing pipx"
    sudo apt-get update
    sudo apt-get install -y pipx
    pipx ensurepath
fi

# Sleuth Kit powers `hexbee-comb tsk-ls` (deep filesystem walks). Kali's
# 'forensics' metapackage usually already provides it; install directly so
# this works on a plain Kali too. libmagic aids future typing work.
echo "==> Installing system forensics tooling (sleuthkit, mount helpers)"
sudo apt-get install -y sleuthkit libewf-tools ewf-tools 2>/dev/null \
    || sudo apt-get install -y sleuthkit
# libewf-tools gives ewfmount for E01 images; ok if unavailable.

echo "==> Installing hexbee-queen (analyst CLI)"
pipx install --force "$REPO_ROOT/queen"

echo "==> Installing hexbee-comb (forensic triage toolkit)"
pipx install --force "$REPO_ROOT/comb"

echo
echo "Installed. Verify:"
echo "  hexbee-queen --help"
echo "  hexbee-comb --help"
echo "  which mmls fls          # Sleuth Kit present -> tsk-ls enabled"
echo
echo "Connect to your Hive:"
echo "  hexbee-queen connect http://<hive-address>:8080 -u <user>"
echo
echo "Optional — local AI for Hive Mind (runs on this laptop, stays offline):"
echo "  curl -fsSL https://ollama.com/install.sh | sh"
echo "  ollama pull llama3.2"
echo "  # then on the Hive set HEXBEE_AI_URL=http://<this-laptop>:11434"
