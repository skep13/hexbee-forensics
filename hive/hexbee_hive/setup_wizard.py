"""`hexbee-hive setup` — first run, for someone who has never done this.

The wizard exists because the alternative is a README that assumes you
already know what an ingest key is. Each step says what it is doing and why
it matters before it does it, and every prompt has a working default so the
whole thing can be completed by pressing Enter.

Nothing here is irreversible: it creates a directory, a database, a key file,
and one user account. Run it twice and it will tell you what already exists
rather than clobbering it.
"""

from __future__ import annotations

import getpass
import os
import secrets
import sys
from pathlib import Path

RULE = "-" * 62


def _say(text: str = "") -> None:
    print(text)


def _heading(step: int, total: int, title: str) -> None:
    _say()
    _say(RULE)
    _say(f"Step {step} of {total}: {title}")
    _say(RULE)


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        answer = input(f"{prompt}{suffix}: ").strip()
    except EOFError:
        return default
    return answer or default


def _confirm(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    try:
        answer = input(f"{prompt} [{hint}]: ").strip().lower()
    except EOFError:
        return default
    if not answer:
        return default
    return answer.startswith("y")


def _default_data_dir() -> Path:
    """Prefer an external drive if an obvious one is mounted.

    Evidence and threat-intel feeds get large, and a beginner will not think
    about which disk that lands on until it is full.
    """
    import platform

    candidates = []
    system = platform.system()
    if system == "Darwin":
        volumes = Path("/Volumes")
        if volumes.is_dir():
            for entry in sorted(volumes.iterdir()):
                if entry.name not in ("Macintosh HD",) and entry.is_dir():
                    candidates.append(entry / "hexbee")
    elif system == "Linux":
        for base in ("/mnt/evidence", "/media"):
            path = Path(base)
            if path.is_dir():
                candidates.append(path / "hexbee" if base == "/media"
                                  else path)
    for candidate in candidates:
        try:
            if candidate.parent.exists() and os.access(candidate.parent, os.W_OK):
                return candidate
        except OSError:
            continue
    return Path.home() / "hexbee-data"


def run() -> int:
    total = 5
    _say()
    _say("HexBee setup")
    _say("=" * 62)
    _say("This gets HexBee ready to use. It takes about a minute.")
    _say()
    _say("HexBee collects digital evidence and keeps it in a tamper-evident")
    _say("log, so you can show later that nothing was altered. This wizard")
    _say("creates that log and the account you will log in with.")
    _say()
    _say("Press Enter to accept any suggestion in [brackets].")

    # -- 1. where things live ---------------------------------------------
    _heading(1, total, "Where should HexBee keep evidence?")
    _say("Everything HexBee collects goes in one folder: the evidence log,")
    _say("exported reports, offline maps, and downloaded threat feeds.")
    _say()
    _say("Put this on an external drive if you have one. Evidence files get")
    _say("large, and keeping them off your system disk means you can unplug")
    _say("the drive and take the evidence with you.")
    _say()
    suggested = os.environ.get("HEXBEE_DATA_DIR") or str(_default_data_dir())
    data_dir = Path(_ask("Folder", suggested)).expanduser()
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _say(f"\nCannot create {data_dir}: {exc}")
        _say("Pick somewhere you have permission to write and run setup again.")
        return 1
    os.environ["HEXBEE_DATA_DIR"] = str(data_dir)

    from .config import load_config
    from .db import Database

    cfg = load_config()
    _say(f"\n  Using {cfg.data_dir}")

    # -- 2. the evidence log ----------------------------------------------
    _heading(2, total, "Creating the evidence log")
    _say("Every piece of evidence is written into a database where each")
    _say("record is sealed with a fingerprint of the one before it. Change")
    _say("any past record and the seal breaks — visibly, and permanently.")
    _say()
    _say("That is what lets you prove the evidence has not been edited.")
    _say()
    existed = cfg.db_path.exists()
    db = Database(cfg.db_path)
    if existed:
        events = db.query_one("SELECT COUNT(*) AS n FROM events")["n"]
        _say(f"  Already exists — {events} record(s). Leaving it alone.")
    else:
        _say(f"  Created {cfg.db_path}")

    # -- 3. the collection key --------------------------------------------
    _heading(3, total, "Setting the collection key")
    _say("The collection tools — the ones that gather evidence from")
    _say("computers, USB sticks and the network — send what they find back")
    _say("to this Hive. They prove they are yours with a shared key.")
    _say()
    _say("Without a key, nothing can send evidence in.")
    _say()
    key = cfg.ingest_key
    if key:
        _say(f"  Already set ({len(key)} characters). Keeping it.")
    else:
        key = secrets.token_hex(24)
        _say("  Generated a new key.")
        _say()
        _say("  Save this line somewhere — you will need it on every machine")
        _say("  you collect from:")
        _say()
        _say(f"      export HEXBEE_INGEST_KEY={key}")
        _say()
        key_file = cfg.data_dir / "ingest-key.txt"
        if _confirm(f"  Also write it to {key_file}?", True):
            try:
                key_file.write_text(key + "\n", encoding="utf-8")
                key_file.chmod(0o600)
                _say(f"  Written to {key_file} (readable only by you)")
            except OSError as exc:
                _say(f"  Could not write it: {exc}")
        os.environ["HEXBEE_INGEST_KEY"] = key

    # -- 4. your login -----------------------------------------------------
    _heading(4, total, "Creating your login")
    _say("You investigate through a web dashboard, which needs an account.")
    _say("This one will be an administrator, so it can do everything.")
    _say()
    from .auth import create_user

    row = db.query_one("SELECT username FROM users WHERE role='administrator' "
                       "AND disabled=0 LIMIT 1")
    if row:
        _say(f"  An administrator already exists ({row['username']}). "
             f"Skipping.")
    else:
        username = _ask("Username", os.environ.get("USER") or "analyst")
        _say()
        _say(f"  Passwords must be at least {cfg.min_password_length} "
             f"characters.")
        _say("  Length matters far more than symbols — three or four random")
        _say("  words is both stronger and easier to type in a hurry.")
        _say()
        while True:
            password = getpass.getpass("  Password: ")
            confirm = getpass.getpass("  Confirm:  ")
            if password != confirm:
                _say("  They do not match. Try again.\n")
                continue
            try:
                create_user(db, username, password, "administrator",
                            actor="setup",
                            min_length=cfg.min_password_length)
            except Exception as exc:
                _say(f"  {exc}\n")
                continue
            _say(f"\n  Created {username}.")
            break

    # -- 5. what you can do now -------------------------------------------
    _heading(5, total, "Checking what this machine can do")
    from . import doctor

    report = doctor.run(cfg, db)
    unlocked = [c for c in report.checks if c.status == doctor.OK and c.enables]
    locked = [c for c in report.checks if c.status == doctor.WARN and c.enables]

    if unlocked:
        _say("Ready to use:")
        for check in unlocked[:8]:
            _say(f"  - {check.enables}")
    if locked:
        _say()
        _say("Available once you install something extra:")
        for check in locked[:8]:
            _say(f"  - {check.enables}  ({check.fix})")

    db.close()

    _say()
    _say(RULE)
    _say("Setup complete.")
    _say(RULE)
    _say()
    _say("Start the dashboard:")
    _say("    hexbee-hive web")
    _say()
    _say("Then open http://localhost:8080 and click 'Start Here'. It walks")
    _say("through the common jobs step by step.")
    _say()
    _say("You can also just ask:")
    _say('    hexbee-hive howto "someone gave me a usb stick"')
    _say()
    _say("And to see the full picture of what works on this machine:")
    _say("    hexbee-hive doctor")
    _say()
    if not cfg.ingest_key and key:
        _say("Remember to set the collection key in your shell profile so it")
        _say("survives a restart:")
        _say(f"    echo 'export HEXBEE_INGEST_KEY={key}' >> ~/.zshrc")
        _say()
    return 0
