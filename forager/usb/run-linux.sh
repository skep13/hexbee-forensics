#!/usr/bin/env bash
# ===================================================================
#  HexBee Forager - USB triage launcher (Linux/macOS)
#  Authorized forensic collection only. Read-only: does not modify
#  this machine. Run with sudo for full process/network visibility.
# ===================================================================
set -euo pipefail
cd "$(dirname "$0")"

HOST="$(hostname)"
STAMP="${HOST}_$(date -u +%Y%m%dT%H%M%SZ)"
OUTFILE="collections/${STAMP}.json"
mkdir -p collections

# The Linux binary is built separately (see build_linux.sh); if you only have
# Python on hand, you can also run:  python3 -m hexbee_forager collect ...
BIN="./forager"
[ -x "$BIN" ] || BIN="python3 -m hexbee_forager"

echo "HexBee Forager - collecting from ${HOST} ..."
$BIN collect --output "$OUTFILE"

if [ -f forager.json ]; then
    echo "Hive config found - submitting collection..."
    $BIN submit "$OUTFILE"
else
    echo "No forager.json - collection saved to the USB only: $OUTFILE"
    echo "Submit later:  $BIN --hive http://HIVE:8080 --key KEY submit \"$OUTFILE\""
fi

echo "Done. Safely unmount the USB stick."
