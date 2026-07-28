#!/usr/bin/env bash
# Stage the three things you physically carry: a USB triage stick, the Pi's
# Hive, and the analyst laptop.
#
#   bash scripts/make-deploy-bundles.sh            # -> dist/
#   bash scripts/make-deploy-bundles.sh --dest /Volumes/EVIDENCE
#
# Each bundle is self-describing: copy the folder to its destination and read
# the START-HERE file inside it. Nothing here needs the repo afterwards.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$REPO_ROOT/dist"

while [ $# -gt 0 ]; do
    case "$1" in
        --dest) DEST="$2"; shift ;;
        -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

# Never ship caches, egg-info or a virtualenv: they are large, machine-specific
# and, in the case of dev-data, actual evidence from the build machine.
copy() {  # copy <src> <dst>
    mkdir -p "$(dirname "$2")"
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --exclude '__pycache__' --exclude '*.pyc' --exclude '*.egg-info' \
              --exclude '.venv' --exclude 'build' --exclude 'dist' "$1" "$2"
    else
        cp -R "$1" "$2"
        find "$2" \( -name '__pycache__' -o -name '*.egg-info' \) -prune -exec rm -rf {} + 2>/dev/null || true
    fi
}

rm -rf "$DEST"
mkdir -p "$DEST"
echo "==> Staging deployment bundles in $DEST"

# ===================================================================
#  1. USB triage stick — runs on a target machine with nothing installed
# ===================================================================
USB="$DEST/1-usb-forager"
mkdir -p "$USB/collections"
copy "$REPO_ROOT/forager/usb/" "$USB/"
# The package travels with the stick so `python3 -m hexbee_forager` works from
# this folder with no install on the target — that is the whole point of a
# triage stick, and it is why the package sits at the top level rather than
# inside a subfolder.
copy "$REPO_ROOT/forager/hexbee_forager" "$USB/"
rm -f "$USB/build_windows.ps1"          # a build tool, not something you carry
chmod +x "$USB/run-linux.sh" 2>/dev/null || true

cat > "$USB/START-HERE.txt" <<'EOF'
HexBee Forager — USB triage stick
=================================

Copy EVERYTHING in this folder to the root of a USB stick.

AT THE SCENE
  macOS / Linux   open a terminal on the stick and run:  sudo ./run-linux.sh
  Windows         right-click RUN-WINDOWS.bat > "Run as administrator"

  Evidence is written to  collections\<HOST>_<UTC timestamp>.json  on the
  stick itself. Nothing is installed on the target and nothing is modified:
  the collector only reads.

TO SEND FINDINGS TO YOUR HIVE AUTOMATICALLY (optional, do this beforehand)
  1. Copy forager.example.json to forager.json
  2. Fill in your Hive URL and ingest key, e.g.
       {"hive_url": "http://192.168.1.50:8080", "ingest_key": "..."}
  Without it, evidence stays on the stick and you import it later with:
       hexbee-forager submit collections/<file>.json

WINDOWS TARGETS WITH NO PYTHON
  The launcher needs Python 3 on the target. If the machines you attend do
  not have it, build a standalone .exe first, on any Windows box with Python:
       pip install pyinstaller psutil
       powershell -ExecutionPolicy Bypass -File forager\usb\build_windows.ps1
  then copy the contents of forager/usb/dist/HexBee-Forager-USB/ onto the
  stick alongside these files.

Authorised collection only. Read-only by design — see USB-README.txt.
EOF
echo "    1-usb-forager      run-from-stick collector (no install on target)"

# ===================================================================
#  2. Raspberry Pi — the Hive (evidence hub)
# ===================================================================
PI="$DEST/2-rpi-hive"
mkdir -p "$PI"
copy "$REPO_ROOT/hive" "$PI/"
copy "$REPO_ROOT/netmon" "$PI/"          # raw capture is Linux-only: it lives here
copy "$REPO_ROOT/scout/simulator" "$PI/"
copy "$REPO_ROOT/scripts/demo_seed.py" "$PI/scripts/"
copy "$REPO_ROOT/docs/DEPLOYMENT.md" "$PI/docs/"

cat > "$PI/START-HERE.txt" <<'EOF'
HexBee on the Raspberry Pi
==========================

There are two ways to use the Pi. Pick one.

-------------------------------------------------------------------
A. AS A COLLECTOR, reporting into the Hive on your Mac  (recommended
   when the Mac is your hub — which it is if you ran the app there)
-------------------------------------------------------------------
On the Mac, generate the configs:

    python3 scripts/provision-devices.py --wifi-ssid "<your network>"

Copy this folder AND the generated device-configs/pi-setup.sh to the Pi,
then on the Pi:

    bash pi-setup.sh

That installs Forager and Netmon into ~/hexbee-venv, points both at the
Mac's address and ingest key, and grants raw-capture capability once.

    ~/hexbee-venv/bin/hexbee-forager collect          # one-shot triage
    ~/hexbee-venv/bin/hexbee-forager watch            # continuous
    ~/hexbee-venv/bin/hexbee-netmon run --mode ids --iface wlan0

Netmon lives here rather than on the Mac because raw packet capture needs
Linux; macOS cannot do it without extra drivers.

-------------------------------------------------------------------
B. AS THE HIVE, hosting the evidence log itself
-------------------------------------------------------------------
    cd hive && sudo bash install.sh

Installs Mosquitto, a locked-down `hexbee` user, a virtualenv in
/opt/hexbee, evidence in /var/lib/hexbee, and two systemd services that
start on boot. It prints an INGEST KEY — write it down.

Then browse to http://<pi-ip>:8080 and create your account on the first
page. Point the Mac at it with:

    hexbee-queen connect http://<pi-ip>:8080 -u <your-user>

-------------------------------------------------------------------
Either way, test with no hardware at all:

    python3 simulator/scout_sim.py --rest <hive-url> --key <KEY> \
        --scenario incident

Before real casework, put evidence on an external disk rather than the SD
card: set HEXBEE_DATA_DIR. See docs/DEPLOYMENT.md.
EOF
echo "    2-rpi-hive         collector for the Mac, or a Hive in its own right"

# ===================================================================
#  3. Analyst laptop — Mac today, Asahi later
# ===================================================================
MAC="$DEST/3-mac-queen"
mkdir -p "$MAC"
for component in queen comb forager hive; do
    copy "$REPO_ROOT/$component" "$MAC/"
done
copy "$REPO_ROOT/scripts" "$MAC/"
copy "$REPO_ROOT/docs" "$MAC/"
for f in try-hexbee.command try-hexbee.sh try-hexbee.ps1 HexBee.bat README.md; do
    [ -f "$REPO_ROOT/$f" ] && cp "$REPO_ROOT/$f" "$MAC/"
done
chmod +x "$MAC/try-hexbee.command" "$MAC/try-hexbee.sh" 2>/dev/null || true

cat > "$MAC/START-HERE.txt" <<'EOF'
HexBee — analyst workstation (macOS, and Asahi/Linux later)
===========================================================

THE SHORT VERSION — no terminal at all
    Double-click  try-hexbee.command
It builds its own Python environment on first run (a minute or two), starts
the Hive, and opens the dashboard. The first page asks you to create your
account. Nothing is installed system-wide and nothing needs admin rights.

TO KEEP IT AS A REAL APP
    bash scripts/make-macos-app.sh        # -> ~/Applications/HexBee.app
    bash scripts/make-linux-app.sh        # Asahi/Fedora/Kali: menu entry
Open it like any app; quitting it stops the dashboard. Evidence lives in
~/Library/Application Support/HexBee (macOS) or ~/.local/share/hexbee (Linux).

THE ANALYST TOOLING (Comb disk triage, engagement tools)
    bash queen/setup-macos.sh             # Homebrew + pipx + Sleuth Kit
    bash queen/setup-linux.sh             # Fedora/Asahi, Kali, Arch, openSUSE

    hexbee-comb serve                     # point-and-click triage UI :8091
    hexbee-queen connect http://<pi-ip>:8080 -u <your-user>

WHAT THIS MACHINE CANNOT DO ON macOS (by Apple's design, not a fault)
    * Memory capture      — acquire from Windows/Linux targets instead
    * hexbee-netmon       — raw packet capture belongs on the Pi
    * --pdf reports       — print the HTML report to PDF from the browser
  Moving to Asahi Linux gets memory capture and Netmon back; see
  docs/INSTALL.md.

WHERE TO LOOK FIRST
    Explorer      the three-pane evidence browser — sources, results, detail
    Start Here    guided jobs written for someone who has not done this before
EOF
echo "    3-mac-queen        analyst workstation + Explorer + Comb"

# If the devices have been provisioned, ship those configs with the bundles
# so the stick and the Pi arrive already pointing at the right Hive.
if [ -d "$REPO_ROOT/device-configs" ]; then
    [ -f "$REPO_ROOT/device-configs/forager.json" ] && \
        cp "$REPO_ROOT/device-configs/forager.json" "$USB/forager.json"
    [ -f "$REPO_ROOT/device-configs/pi-setup.sh" ] && \
        cp "$REPO_ROOT/device-configs/pi-setup.sh" "$PI/pi-setup.sh"
    for f in stinger-config.py iphone.txt START-HERE.txt; do
        [ -f "$REPO_ROOT/device-configs/$f" ] && \
            copy "$REPO_ROOT/device-configs/$f" "$DEST/0-device-configs/"
    done
    echo "    0-device-configs   Stinger + iPhone details (contains your keys)"
fi

cat > "$DEST/README.txt" <<'EOF'
HexBee deployment bundles
=========================

  1-usb-forager   -> copy onto a USB stick; run at the scene, installs nothing
  2-rpi-hive      -> copy to the Raspberry Pi; `sudo bash hive/install.sh`
  3-mac-queen     -> copy to the analyst laptop; double-click try-hexbee.command

Each folder has a START-HERE.txt with the exact steps. Do the Pi first if you
want the collectors to report into it — they need its address and ingest key.
EOF

echo
du -sh "$DEST"/* 2>/dev/null | sed 's/^/    /'
echo
echo "Done. Each folder has a START-HERE.txt. Order: Pi first, then the stick."
