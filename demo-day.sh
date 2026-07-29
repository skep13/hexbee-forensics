#!/usr/bin/env bash
# ===================================================================
#  HexBee — set the whole kit up on the day. Run this once, on the Mac,
#  after joining the hotspot.
#
#      bash demo-day.sh
#
#  It re-points every device at wherever this Mac has landed, restarts
#  the Hive, checks it is actually reachable, and prints what to copy
#  onto each piece of hardware. Safe to re-run — and you will need to,
#  because a phone hotspot hands out a new address every time it starts.
#
#  First run asks for the Wi-Fi password once and remembers it in
#  device-configs/ (gitignored). After that: no arguments, no typing.
# ===================================================================
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
CONF_DIR="$REPO/device-configs"
WIFI_FILE="$CONF_DIR/.demo-wifi"
APP="$HOME/Applications/HexBee.app"
PORT=8080

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m    %s\n' "$*"; }
warn() { printf '  \033[33mwarn\033[0m  %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }

# -- 1. which network are we on, and on which band ------------------------
say "1. Network"

WIFI_INFO="$(system_profiler SPAirPortDataType 2>/dev/null || true)"
CURRENT="$(printf '%s' "$WIFI_INFO" | sed -n '/Current Network Information:/,/Other Local/p')"
SSID_NOW="$(printf '%s' "$CURRENT" | sed -n '2p' | sed 's/^ *//; s/: *$//')"
CHANNEL="$(printf '%s' "$CURRENT" | awk -F': ' '/Channel:/{print $2; exit}')"

# `ipconfig getifaddr` reports nothing on an iPhone hotspot — the address is
# there (192.0.0.2 with a 192.0.0.1 gateway) but not in the form that command
# reports. Ask the routing table which address actually leaves this machine,
# and keep ipconfig only as a fallback.
IP="$(python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.connect(("8.8.8.8", 80))          # no packet is sent
    print(s.getsockname()[0])
except OSError:
    pass
finally:
    s.close()
' 2>/dev/null || true)"
if [ -z "$IP" ]; then
    IFACE="$(route -n get default 2>/dev/null | awk "/interface:/{print \$2}")"
    [ -n "$IFACE" ] && IP="$(ifconfig "$IFACE" 2>/dev/null | awk "/inet /{print \$2; exit}")"
fi
[ -n "$IP" ] || IP="$(ipconfig getifaddr en0 2>/dev/null || true)"
if [ -z "$IP" ]; then
    bad "This Mac has no Wi-Fi address. Join the hotspot first, then re-run."
    exit 1
fi
ok "address: $IP"
[ -n "$SSID_NOW" ] && ok "network: $SSID_NOW"

# The ESP32-C3 has a 2.4 GHz radio and nothing else. On 5 GHz it will not
# associate, and it fails silently — no error, it simply never appears.
case "$CHANNEL" in
    *5GHz*)
        warn "this network is 5 GHz ($CHANNEL)"
        warn "the ESP32-C3 is 2.4 GHz only and will NEVER connect to it."
        warn "On the phone: Settings > Personal Hotspot > Maximize Compatibility = ON"
        warn "Then rejoin on the Mac and run this again."
        printf '\n  Continue anyway (everything except the C3 will work)? [y/N] '
        read -r reply
        [ "$reply" = "y" ] || [ "$reply" = "Y" ] || exit 1
        ;;
    *2GHz*|*2.4GHz*) ok "band: $CHANNEL — the C3 can join this" ;;
    *) [ -n "$CHANNEL" ] && warn "band unknown ($CHANNEL); if the C3 never appears, force 2.4 GHz" ;;
esac

case "$IP" in
    172.20.10.*) ok "this looks like an iPhone hotspot" ;;
esac

# -- 2. credentials, asked once -------------------------------------------
say "2. Wi-Fi credentials for the devices"
mkdir -p "$CONF_DIR"
if [ -f "$WIFI_FILE" ]; then
    # shellcheck disable=SC1090
    . "$WIFI_FILE"
    ok "reusing saved credentials for: $DEMO_SSID"
else
    DEFAULT_SSID="${SSID_NOW:-}"
    printf '  Wi-Fi name the DEVICES will join [%s]: ' "$DEFAULT_SSID"
    read -r entered
    DEMO_SSID="${entered:-$DEFAULT_SSID}"
    # -s: the password is not echoed, and it is written only to a gitignored
    # file with owner-only permissions.
    printf '  Wi-Fi password: '
    read -rs DEMO_PASS
    printf '\n'
    # printf %q escapes quotes and spaces, so an SSID like "Jacob's Iphone"
    # survives being sourced back in.
    printf 'DEMO_SSID=%q\nDEMO_PASS=%q\n' "$DEMO_SSID" "$DEMO_PASS" > "$WIFI_FILE"
    chmod 600 "$WIFI_FILE"
    ok "saved to device-configs/.demo-wifi (gitignored, owner-only)"
fi

# -- 3. regenerate every device config ------------------------------------
say "3. Re-pointing the devices at $IP"
python3 "$REPO/scripts/provision-devices.py" \
    --wifi-ssid "$DEMO_SSID" --wifi-password "$DEMO_PASS" --ip "$IP" >/dev/null
ok "device configs written"
bash "$REPO/scripts/make-deploy-bundles.sh" >/dev/null
ok "bundles rebuilt in dist/"

KEY="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["ingest_key"])' \
        "$CONF_DIR/forager.json")"

# -- 4. restart the Hive so it uses the same key --------------------------
say "4. Starting HexBee"
if [ -d "$APP" ]; then
    osascript -e 'tell application "HexBee" to quit' >/dev/null 2>&1 || true
    sleep 3
    open -a "$APP"
else
    warn "HexBee.app not found — starting the launcher instead"
    nohup python3 "$REPO/scripts/hexbee_launcher.py" >/dev/null 2>&1 &
fi

for _ in $(seq 1 60); do
    curl -fsS -m 2 "http://127.0.0.1:$PORT/api/v1/health" >/dev/null 2>&1 && break
    sleep 1
done

# -- 5. prove the devices can actually reach it ---------------------------
say "5. Checks"
if curl -fsS -m 5 "http://127.0.0.1:$PORT/api/v1/health" >/dev/null 2>&1; then
    ok "Hive is running"
else
    bad "the Hive did not start — open HexBee.app by hand and re-run"
    exit 1
fi

if curl -fsS -m 5 "http://$IP:$PORT/api/v1/health" >/dev/null 2>&1; then
    ok "reachable from the network as $IP — devices can see it"
else
    bad "not reachable on $IP. Allow Python in System Settings > Network > Firewall."
fi

PROBE="$(curl -fsS -m 5 -X POST "http://$IP:$PORT/api/v1/ingest" \
    -H 'Content-Type: application/json' -H "X-HexBee-Ingest-Key: $KEY" \
    -d '{"device":"demo-day-check","event_type":"scout_online","payload":{"check":true}}' \
    2>/dev/null || true)"
case "$PROBE" in
    *'"stored": 1'*|*'"stored":1'*) ok "ingest works with the key the devices carry" ;;
    *) bad "ingest rejected the key — restart HexBee and re-run" ;;
esac

# -- 6. what to do with the hardware --------------------------------------
cat <<EOF

$(printf '\033[1m%s\033[0m' "Ready. Dashboard: http://$IP:$PORT")

  Hive address   http://$IP:$PORT
  Ingest key     $KEY

Copy these, in this order:

  USB STICKS   everything in  dist/1-usb-forager/
               at the scene:  sudo ./run-linux.sh
                              (Windows: right-click RUN-WINDOWS.bat > run as admin)

  RASPBERRY PI everything in  dist/2-rpi-hive/
               on the Pi:     bash pi-setup.sh
                              ~/hexbee-venv/bin/hexbee-forager collect
                              ~/hexbee-venv/bin/hexbee-netmon run --mode ids --iface wlan0

  ESP32-C3     dist/0-device-configs/stinger-config.py  ->  the board, as config.py
               mpremote connect /dev/cu.usbmodem* fs cp \\
                   dist/0-device-configs/stinger-config.py :config.py
               test first:    mpremote connect /dev/cu.usbmodem* run \\
                                  scout/c3-stinger/selftest.py

  IPHONE XR    open Safari at http://$IP:$PORT/field
               Share > Add to Home Screen

On the Mac: click Explorer in the sidebar to watch it all arrive.

If the hotspot restarts, the address changes — run this script again and
re-copy stinger-config.py and forager.json.
EOF
