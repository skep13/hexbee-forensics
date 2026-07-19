#!/usr/bin/env bash
# ===================================================================
#  HexBee Forager - USB triage launcher (Linux/macOS)
#  Authorized forensic collection only. Read-only: does not modify
#  this machine. Run with sudo for full process/network visibility.
# ===================================================================
set -uo pipefail
cd "$(dirname "$0")"

HOST="$(hostname)"
BIN="./forager"
[ -x "$BIN" ] || BIN="python3 -m hexbee_forager"
mkdir -p collections

collect() {
    local out="collections/${HOST}_$(date -u +%Y%m%dT%H%M%SZ).json"
    echo "Collecting from ${HOST} ..."
    $BIN collect --output "$out"
    if [ -f forager.json ]; then
        echo "Hive config found - submitting..."
        $BIN submit "$out"
    else
        echo "Saved to the USB only: $out"
        echo "Submit later:  $BIN --hive http://HIVE:8080 --key KEY submit \"$out\""
    fi
}

while true; do
    clear
    echo "============================================"
    echo "   HexBee Forager - USB triage"
    echo "   Host: ${HOST}"
    echo "============================================"
    echo
    echo "  [1]  Collect now  (one-shot snapshot)"
    echo "  [2]  Monitor      (watch for new activity)"
    echo "  [3]  Status       (config + backlog)"
    echo "  [4]  Quit"
    echo
    read -rp "Choose 1-4: " choice
    case "$choice" in
        1) collect; read -rp "Press Enter..." _ ;;
        2) echo "Monitoring - Ctrl-C to stop."; $BIN watch --interval 60 || true ;;
        3) $BIN status; read -rp "Press Enter..." _ ;;
        4) exit 0 ;;
    esac
done
