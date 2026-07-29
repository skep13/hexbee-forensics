#!/usr/bin/env python3
"""Point every piece of field hardware at the Hive running on this Mac.

The Mac is the hub: the Raspberry Pi, the ESP32-C3 Stinger, the iPhone and the
USB sticks are all collectors that report into it. Each needs the same two
facts — where the Hive is, and the ingest key — and getting either wrong fails
in a way that looks like a network problem.

So this generates the real config file for each device rather than telling you
what to type. Re-run it whenever the network changes: a phone hotspot hands out
a different address every time it comes up, and a stale address in a flashed
board is a bad afternoon.

    python3 scripts/provision-devices.py --wifi-ssid "Jacob's Iphone"

Output lands in device-configs/, which is gitignored — these files hold your
Wi-Fi password and ingest key and must never reach a repository.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shlex
import socket
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "device-configs"
APP_ENV = Path.home() / ".hexbee-app.env"
PORT = 8080


def lan_ip() -> str | None:
    """This Mac's address on the network the devices will also be on.

    Asking the routing table beats parsing `ifconfig`: on a phone hotspot the
    interface is still en0 but the subnet is 172.20.10.x, and on Wi-Fi it is
    whatever the router hands out.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))     # no packet is sent
            return sock.getsockname()[0]
    except OSError:
        pass
    for iface in ("en0", "en1"):
        try:
            out = subprocess.run(["ipconfig", "getifaddr", iface],
                                 capture_output=True, text=True, timeout=5)
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            continue
    return None


def ingest_key() -> tuple[str, bool]:
    """The key every collector authenticates with. Reuse the one the app
    already runs with; only mint a new one if there is nothing to reuse —
    changing it silently would orphan every device already in the field."""
    if env := os.environ.get("HEXBEE_INGEST_KEY"):
        if env != "devkey":
            return env, False
    if APP_ENV.is_file():
        for line in APP_ENV.read_text().splitlines():
            if line.startswith("HEXBEE_INGEST_KEY="):
                value = line.split("=", 1)[1].strip()
                if value and value != "devkey":
                    return value, False
    return secrets.token_hex(24), True


def write_app_env(key: str, data_dir: Path) -> None:
    """The app reads this on launch, so the Hive and the devices agree.

    Values are quoted because this file is *sourced* by the launcher, and the
    default data directory on macOS is "~/Library/Application Support/HexBee".
    Unquoted, the shell splits on that space, HEXBEE_DATA_DIR comes out unset,
    and evidence silently lands in the fallback location instead of the one
    the operator chose — the worst kind of bug in a forensics tool, because
    nothing appears to be wrong.
    """
    APP_ENV.write_text(
        f"HEXBEE_DATA_DIR={shlex.quote(str(data_dir))}\n"
        f"HEXBEE_INGEST_KEY={shlex.quote(key)}\n")
    APP_ENV.chmod(0o600)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate device configs pointing at this Mac's Hive.")
    parser.add_argument("--wifi-ssid", help="the network the devices join")
    parser.add_argument("--wifi-password", help="its password (stored only in "
                                                "device-configs/, never in git)")
    parser.add_argument("--ip", help="override the detected address")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--device-prefix", default="C3-Stinger",
                        help="identity prefix for the Stinger board")
    args = parser.parse_args()

    ip = args.ip or lan_ip()
    if not ip:
        print("Could not work out this Mac's address. Connect to the network "
              "first, or pass --ip.", file=sys.stderr)
        return 1
    hive_url = f"http://{ip}:{args.port}"

    key, minted = ingest_key()
    data_dir = Path.home() / "Library" / "Application Support" / "HexBee"
    # Always rewrite, not just when the key is new: an env file written by an
    # older version is unquoted, and only rewriting on first mint would leave
    # that broken file in place forever.
    write_app_env(key, data_dir)

    OUT.mkdir(exist_ok=True)
    (OUT / ".gitignore").write_text("*\n")   # belt and braces: never commit these

    # -- ESP32-C3 Stinger --------------------------------------------------
    template = (REPO / "scout" / "c3-stinger" / "config.example.py").read_text()
    stinger = template
    for field, value in (("device", f"{args.device_prefix}-01"),
                         ("hive_url", hive_url),
                         ("ingest_key", key),
                         ("wifi_ssid", args.wifi_ssid or ""),
                         ("wifi_password", args.wifi_password or "")):
        stinger = re.sub(rf'("{field}":\s*)"[^"]*"',
                         lambda m, v=value: m.group(1) + json.dumps(v),
                         stinger, count=1)
    stinger = stinger.replace(
        '"""Copy to config.py and edit before flashing.',
        '"""Generated by scripts/provision-devices.py — already filled in.')
    (OUT / "stinger-config.py").write_text(stinger)

    # -- USB triage sticks --------------------------------------------------
    (OUT / "forager.json").write_text(json.dumps(
        {"hive_url": hive_url, "ingest_key": key}, indent=2) + "\n")

    # -- Raspberry Pi -------------------------------------------------------
    (OUT / "pi-setup.sh").write_text(f"""#!/usr/bin/env bash
# Run ON THE PI. Makes it a collector reporting into the Mac's Hive.
set -euo pipefail
HIVE="{hive_url}"
KEY="{key}"

sudo apt-get update
sudo apt-get install -y python3-venv python3-pip libcap2-bin

python3 -m venv ~/hexbee-venv
~/hexbee-venv/bin/pip install -q ./forager ./netmon

~/hexbee-venv/bin/hexbee-forager config --hive "$HIVE" --key "$KEY"
~/hexbee-venv/bin/hexbee-netmon  config --hive "$HIVE" --key "$KEY"

# Raw capture needs the capability once; no root at run time afterwards.
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(which python3)")"

echo "Collect once:      ~/hexbee-venv/bin/hexbee-forager collect"
echo "Watch continuously:~/hexbee-venv/bin/hexbee-forager watch"
echo "Network IDS:       ~/hexbee-venv/bin/hexbee-netmon run --mode ids --iface wlan0"
""")
    (OUT / "pi-setup.sh").chmod(0o755)

    # -- iPhone XR ----------------------------------------------------------
    (OUT / "iphone.txt").write_text(f"""HexBee field companion — iPhone XR
==================================

On the phone, joined to the same network as this Mac, open Safari at:

    {hive_url}/field

Then Share > Add to Home Screen. It installs as an app: no App Store, no
account, works offline once loaded.

Sign in with the HexBee account you created in the browser. The phone can
view open incidents and photograph evidence straight into the hash chain.

If the page does not load, it is almost always one of two things:
  * the phone is on a different network from the Mac
  * macOS is blocking incoming connections — see START-HERE.txt
""")

    summary = f"""HexBee — this Mac is the hub
============================

  Hive address   {hive_url}
  Ingest key     {key}
  Evidence       {data_dir}

Generated, ready to use:

  stinger-config.py   -> ESP32-C3. Copy to the board AS config.py:
                           mpremote connect /dev/cu.usbmodem* fs cp \\
                               device-configs/stinger-config.py :config.py
  forager.json        -> copy to the root of each USB triage stick
  pi-setup.sh         -> copy to the Pi with the forager/ and netmon/ folders,
                         then: bash pi-setup.sh
  iphone.txt          -> what to open on the iPhone XR

IMPORTANT — the address changes with the network
  A phone hotspot hands out a new address each time it starts. When that
  happens the flashed board and the USB sticks are pointing at nothing. Re-run
  this script and re-copy the files.

macOS firewall
  If devices cannot reach the Hive, allow incoming connections for Python:
  System Settings > Network > Firewall > Options. Turning the firewall off
  entirely is not necessary.

These files contain your Wi-Fi password and ingest key. device-configs/ is
gitignored — keep it that way, and do not paste the key into an issue.
"""
    (OUT / "START-HERE.txt").write_text(summary)

    print(summary)
    if minted:
        print(f"A new ingest key was generated and written to {APP_ENV}.")
        print("Restart HexBee so the Hive picks it up.")
    else:
        print("Reused the ingest key already configured for this Mac.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
