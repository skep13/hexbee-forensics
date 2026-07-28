#!/usr/bin/env python3
"""Start HexBee from a double-click, on any operating system.

This is the whole first-run story for someone who does not use a terminal:
it builds the environment if there isn't one, starts the Hive, waits until the
dashboard genuinely answers, and opens a browser at it. If no account exists
yet the dashboard sends them to `/setup`, so the entire path from "downloaded
a zip" to "logged into a forensics console" involves no typed commands.

Stdlib only, and deliberately so — the thing that installs the dependencies
cannot itself have any.

Run it directly (`python3 scripts/hexbee_launcher.py`) or, more usually, from
the per-OS wrapper: HexBee.app, the Linux .desktop entry, or HexBee.bat.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
COMPONENTS = ("hive", "comb", "queen", "forager")
HOST, PORT = "127.0.0.1", 8080
IS_WINDOWS = platform.system() == "Windows"
IS_MACOS = platform.system() == "Darwin"


def log(message: str) -> None:
    print(f"[hexbee] {message}", flush=True)


def data_dir() -> Path:
    """Where evidence lives, per platform convention.

    Never inside the repo: on macOS a double-clicked app is refused access to
    ~/Downloads, ~/Desktop and ~/Documents by TCC, and it is refused silently.
    """
    if env := os.environ.get("HEXBEE_DATA_DIR"):
        return Path(env)
    home = Path.home()
    if IS_WINDOWS:
        base = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        return base / "HexBee"
    if IS_MACOS:
        return home / "Library" / "Application Support" / "HexBee"
    return Path(os.environ.get("XDG_DATA_HOME", home / ".local" / "share")) / "hexbee"


def venv_python(venv: Path) -> Path:
    return venv / ("Scripts" if IS_WINDOWS else "bin") / (
        "python.exe" if IS_WINDOWS else "python")


def find_interpreter() -> Path:
    """An interpreter with HexBee importable — an existing install, the repo
    venv, or a venv we build now."""
    # 1. Already installed (pipx, pip install, system package).
    for candidate in (shutil.which("hexbee-hive"),):
        if candidate:
            log(f"using installed HexBee: {candidate}")
            return Path(candidate)

    # 2. The repo's own venv, if it already has the Hive in it.
    venv = REPO / ".venv"
    python = venv_python(venv)
    if python.exists() and _importable(python):
        log(f"using existing environment: {venv}")
        return python

    # 3. Build one. First run only; this is the slow path.
    if not python.exists():
        log("first run — creating a private Python environment (a minute or so)")
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
        python = venv_python(venv)
    log("installing HexBee components")
    subprocess.run([str(python), "-m", "pip", "install", "-q", "--upgrade", "pip"],
                   check=False)
    subprocess.run(
        [str(python), "-m", "pip", "install", "-q"]
        + [str(REPO / c) for c in COMPONENTS],
        check=True)
    return python


def _importable(python: Path) -> bool:
    result = subprocess.run([str(python), "-c", "import hexbee_hive"],
                            capture_output=True)
    return result.returncode == 0


def port_open(port: int, host: str = HOST, timeout: float = 0.4) -> bool:
    with socket.socket() as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def start_hive(interpreter: Path, env: dict, port: int) -> subprocess.Popen | None:
    if port_open(port):
        log(f"HexBee is already running on {port} — opening that")
        return None
    if interpreter.name.startswith("hexbee-hive"):
        cmd = [str(interpreter), "web"]
    else:
        cmd = [str(interpreter), "-m", "hexbee_hive.cli", "web"]

    # Initialise the database if this is a fresh data directory. `init` is
    # safe to re-run; it reports what already exists rather than clobbering.
    init = list(cmd[:-1]) + ["init"]
    subprocess.run(init, env=env, capture_output=True)

    log("starting the Hive")
    creation = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0
    return subprocess.Popen(cmd, env=env, creationflags=creation,
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def main() -> int:
    parser = argparse.ArgumentParser(description="Start HexBee and open it.")
    parser.add_argument("--no-browser", action="store_true",
                        help="start the server but do not open a browser")
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()

    env = dict(os.environ)
    directory = data_dir()
    directory.mkdir(parents=True, exist_ok=True)
    env["HEXBEE_DATA_DIR"] = str(directory)
    env.setdefault("HEXBEE_INGEST_KEY", "devkey")
    # The server reads its port from the environment, so --port has to be told
    # to it as well as used for the readiness check — otherwise the launcher
    # waits forever on a port nothing is listening to.
    env["HEXBEE_WEB_PORT"] = str(args.port)
    log(f"evidence directory: {directory}")

    try:
        interpreter = find_interpreter()
    except subprocess.CalledProcessError as exc:
        log(f"could not build the environment: {exc}")
        return 1

    child = start_hive(interpreter, env, args.port)

    for _ in range(120):
        if port_open(args.port):
            break
        time.sleep(0.25)
    else:
        log("the Hive did not start listening — see the log in the data directory")
        if child:
            child.terminate()
        return 1

    url = f"http://{HOST}:{args.port}/"
    log(f"HexBee is up: {url}")
    if not args.no_browser:
        webbrowser.open(url)

    if child is None:          # someone else's server; do not adopt or kill it
        return 0
    try:
        child.wait()
    except KeyboardInterrupt:
        log("stopping")
        child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
