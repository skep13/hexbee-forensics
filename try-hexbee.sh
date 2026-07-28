#!/usr/bin/env bash
# ===================================================================
#  HexBee — one-command local test on macOS / Linux.
#
#  Prefer not to touch a terminal at all? Two ways:
#    * double-click try-hexbee.command (macOS, works straight from a download)
#    * install it as a real app:  bash scripts/make-macos-app.sh
#                                 bash scripts/make-linux-app.sh
#  Both build the environment themselves and open the dashboard, which walks
#  you through creating your account.
#
#  This script differs in one way: it also loads demo evidence, so you get a
#  populated Explorer rather than an empty one.
#
#  Usage:  bash try-hexbee.sh
#  It installs HexBee into a venv, starts the Hive, loads a demo
#  incident, and opens the dashboard. Login: admin / hexbee-demo-1
# ===================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
VENV="$ROOT/.venv"
PY="$VENV/bin/python"

if [ ! -x "$PY" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV"
fi

echo "Installing HexBee (hive, comb, queen, forager)..."
"$PY" -m pip install -q --upgrade pip
"$PY" -m pip install -q \
    -e "$ROOT/hive" \
    -e "$ROOT/comb" \
    -e "$ROOT/queen" \
    -e "$ROOT/forager"

export HEXBEE_DATA_DIR="$ROOT/dev-data"
export HEXBEE_INGEST_KEY="devkey"

echo "Initialising database + demo admin..."
"$PY" -m hexbee_hive.cli init
"$PY" "$ROOT/scripts/demo_seed.py"

echo "Starting the Hive..."
"$PY" -m hexbee_hive.cli web &
WEB_PID=$!
sleep 4

echo "Loading a demo incident (simulated Scout)..."
"$PY" "$ROOT/scout/simulator/scout_sim.py" \
    --rest http://127.0.0.1:8080 --key devkey --scenario incident

open "http://127.0.0.1:8080" 2>/dev/null || xdg-open "http://127.0.0.1:8080" 2>/dev/null || true

echo ""
echo "=================================================="
echo " HexBee is running:  http://127.0.0.1:8080"
echo " Login:  admin  /  hexbee-demo-1"
echo "=================================================="
echo " Try more:"
echo "   .venv/bin/hexbee-forager --hive http://127.0.0.1:8080 --key devkey collect"
echo "   .venv/bin/hexbee-comb serve"
echo ""
echo " Stop the Hive later with:  kill $WEB_PID"
