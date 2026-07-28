#!/usr/bin/env bash
# Double-click this in Finder to start HexBee on macOS.
#
# It is the same launcher the HexBee.app uses; this file exists so the repo
# works straight out of a download, before anything is installed. It builds a
# private Python environment on first run, starts the Hive, and opens the
# dashboard — which walks you through creating your account.
cd "$(dirname "$0")" || exit 1
exec python3 scripts/hexbee_launcher.py
