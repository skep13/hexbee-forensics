"""`hexbee-hive doctor` — what works on this machine, and how to fix what doesn't.

Written for someone who has never used a forensics tool. Every check answers
three questions in plain English:

    What is this?      — one sentence, no jargon
    Is it working?     — ok / warn / missing
    How do I fix it?   — the exact command to run

Two rules the checks follow:

**Missing optional things are not failures.** HexBee is designed so that
almost everything degrades gracefully — no YARA means no malware matching,
not a crash. The report says so rather than implying the install is broken.

**Never say "not found" without saying what to do.** A beginner reading
"tsk_recover: not found" learns nothing. "You cannot open disk images yet —
run `brew install sleuthkit`" is actionable.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

OK, WARN, MISSING, INFO = "ok", "warn", "missing", "info"

SYSTEM = platform.system()
IS_MACOS = SYSTEM == "Darwin"
IS_WINDOWS = SYSTEM == "Windows"
IS_LINUX = SYSTEM == "Linux"


@dataclass
class Check:
    name: str
    status: str
    what: str                       # what this is, for someone who doesn't know
    detail: str = ""                # what we actually found
    fix: str = ""                   # exact command or step
    enables: str = ""               # what you can do once it works

    @property
    def blocking(self) -> bool:
        return self.status == MISSING and not self.enables


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)

    def add(self, check: Check) -> None:
        self.checks.append(check)

    def count(self, status: str) -> int:
        return sum(1 for c in self.checks if c.status == status)

    @property
    def ready(self) -> bool:
        """True when the core works — optional extras may still be missing."""
        return not any(c.status == MISSING and c.name in CORE for c in self.checks)


# Checks that must pass for HexBee to be usable at all.
CORE = {"python", "data directory", "evidence database", "administrator account"}


def _pkg_manager_hint(package: str) -> str:
    if IS_MACOS:
        return f"brew install {package}"
    if IS_LINUX:
        return f"sudo apt install {package}"
    return f"install {package} and put it on your PATH"


# -- individual checks -----------------------------------------------------

def check_python(report: Report) -> None:
    version = sys.version_info
    ok = version >= (3, 9)
    report.add(Check(
        "python", OK if ok else MISSING,
        "The language HexBee is written in.",
        f"Python {version.major}.{version.minor}.{version.micro} on "
        f"{SYSTEM} {platform.machine()}",
        "" if ok else "Install Python 3.9 or newer.",
    ))


def check_data_dir(cfg, report: Report) -> None:
    path = cfg.data_dir
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".hexbee-write-test"
        probe.write_text("x", encoding="utf-8")
        probe.unlink()
        writable = True
    except OSError as exc:
        writable = False
        detail = f"{path} — cannot write ({exc})"
    if writable:
        try:
            free = shutil.disk_usage(path).free // (1024 ** 3)
        except OSError:
            free = 0
        detail = f"{path} ({free} GB free)"
    report.add(Check(
        "data directory", OK if writable else MISSING,
        "Where HexBee keeps evidence, exports, maps and its database. "
        "Put it on your external drive so evidence never fills the system disk.",
        detail,
        "" if writable else
        f"Choose a writable location: export HEXBEE_DATA_DIR=/path/to/drive",
    ))


def check_database(cfg, db, report: Report) -> None:
    from .integrity import verify_chain

    # Ask the database we were handed rather than looking for a file at the
    # configured path — they can legitimately differ, and what matters is
    # whether the log we are actually using is sound.
    try:
        events = db.query_one("SELECT COUNT(*) AS n FROM events")["n"]
    except Exception:
        report.add(Check(
            "evidence database", MISSING,
            "The tamper-evident log every piece of evidence is written to.",
            "not created yet",
            "hexbee-hive setup",
        ))
        return
    result = verify_chain(db)
    if result["ok"]:
        report.add(Check(
            "evidence database", OK,
            "The tamper-evident log every piece of evidence is written to. "
            "Each record is sealed with the one before it, so nothing can be "
            "changed after the fact without it showing.",
            f"{events} record(s), integrity verified",
        ))
    else:
        report.add(Check(
            "evidence database", MISSING,
            "The tamper-evident log every piece of evidence is written to.",
            f"INTEGRITY CHECK FAILED at record {result['first_bad_id']} — "
            f"the log has been altered since it was written",
            "Do not add more evidence. Preserve a copy of the database file "
            "and investigate how it was modified.",
        ))


def check_users(db, report: Report) -> None:
    try:
        row = db.query_one("SELECT COUNT(*) AS n FROM users "
                           "WHERE role='administrator' AND disabled=0")
        admins = row["n"] if row else 0
    except Exception:
        admins = 0
    report.add(Check(
        "administrator account", OK if admins else MISSING,
        "The login you use for the dashboard.",
        f"{admins} active administrator(s)" if admins else "none created yet",
        "" if admins else "hexbee-hive setup",
    ))


def check_ingest_key(cfg, report: Report) -> None:
    key = cfg.ingest_key
    if not key:
        status, detail = WARN, "not set — collectors cannot send anything in"
    elif len(key) < 16:
        status, detail = WARN, f"set but short ({len(key)} characters)"
    else:
        status, detail = OK, f"set ({len(key)} characters)"
    report.add(Check(
        "collection key", status,
        "A shared password the collection tools use to send findings to the "
        "Hive. Without it, nothing can be collected.",
        detail,
        "" if status == OK else
        'export HEXBEE_INGEST_KEY="$(python -c \'import secrets;'
        'print(secrets.token_hex(24))\')"',
    ))


def check_web_deps(report: Report) -> None:
    try:
        import flask  # noqa: F401
        report.add(Check("dashboard", OK,
                         "The web interface you investigate from.",
                         "ready — start it with: hexbee-hive web"))
    except ImportError:
        report.add(Check("dashboard", MISSING,
                         "The web interface you investigate from.",
                         "Flask is not installed",
                         "pip install flask"))


def check_optional_python(report: Report) -> None:
    optional = [
        ("paho.mqtt", "paho-mqtt", "Receiving events from Scout sensors over "
                                   "MQTT.", "hexbee-hive engine"),
        ("PIL", "pillow", "Reading photo metadata, including GPS coordinates "
                          "from images.", "GPS evidence on the map"),
        ("segno", "segno", "Generating QR labels for evidence bags.",
         "printable case labels"),
        ("yara", "yara-python", "Matching files against malware signatures.",
         "malware detection during a scan"),
        ("psutil", "psutil", "Richer process and network detail when "
                             "collecting from a live computer.",
         "fuller live-response collection"),
        ("serial", "pyserial", "Talking to the Pico evidence-seal token over "
                               "USB.", "hardware case sealing"),
    ]
    for module, package, what, enables in optional:
        try:
            __import__(module)
            report.add(Check(package, OK, what, "installed", enables=enables))
        except ImportError:
            report.add(Check(package, WARN, what, "not installed",
                             f"pip install {package}", enables))


def check_external_tools(report: Report) -> None:
    tools = [
        ("tsk_recover", "sleuthkit",
         "Opens disk images and pulls the files out, without mounting them.",
         "examining disk images and USB sticks"),
        ("nmap", "nmap",
         "Scans a network to find machines and the services they run.",
         "hexbee-queen recon"),
        ("smartctl", "smartmontools",
         "Reads a disk's own health report.",
         "disk failure warnings in diagnostics mode"),
        ("ollama", "ollama",
         "Runs the local AI assistant on your own machine. Nothing is sent "
         "to the internet.",
         "conversational help and report drafting"),
        ("wkhtmltopdf", "wkhtmltopdf",
         "Turns a finished report into a PDF.",
         "PDF report export"),
    ]
    for binary, package, what, enables in tools:
        found = shutil.which(binary)
        if found:
            report.add(Check(package, OK, what, found, enables=enables))
        else:
            report.add(Check(package, WARN, what, "not installed",
                             _pkg_manager_hint(package), enables))


def check_ai(cfg, report: Report) -> None:
    from .ai import LocalAI

    engine = LocalAI(cfg.ai_url, cfg.ai_model)
    if engine.available():
        report.add(Check(
            "local AI model", OK,
            "Answers questions and drafts report text on your own hardware.",
            f"{cfg.ai_model} reachable at {cfg.ai_url}",
            enables="conversational assistance",
        ))
        return
    report.add(Check(
        "local AI model", WARN,
        "Answers questions and drafts report text on your own hardware. "
        "Optional — everything still works without it, just less "
        "conversationally.",
        f"nothing reachable at {cfg.ai_url}",
        "ollama pull llama3.2:3b   (then: export HEXBEE_AI_URL=http://<that "
        "machine>:11434)",
        "conversational assistance",
    ))


def check_knowledge(report: Report) -> None:
    from . import knowledge

    kb = knowledge.get()
    recipes = sum(1 for d in kb.docs if d.kind == "recipe")
    commands = sum(1 for d in kb.docs if d.kind == "command")
    status = OK if commands else WARN
    report.add(Check(
        "built-in manual", status,
        "The assistant's reference. It answers 'how do I…' questions with real "
        "commands instead of guessing.",
        f"{len(kb.docs)} documents ({recipes} guides, {commands} commands)",
        "" if commands else "python scripts/build_knowledge.py",
        enables="hexbee-hive howto",
    ))


def check_companion_tools(report: Report) -> None:
    tools = [
        ("hexbee-queen", "The analyst command line — cases, searching, "
                         "reports, and the engagement tools."),
        ("hexbee-comb", "Examines disk images, USB sticks and folders."),
        ("hexbee-forager", "Collects evidence from a computer that is "
                           "switched on."),
        ("hexbee-netmon", "Watches network traffic for suspicious activity."),
    ]
    for binary, what in tools:
        found = shutil.which(binary)
        report.add(Check(
            binary, OK if found else WARN, what,
            found or "not installed",
            "" if found else f"pipx install ./{binary.split('-')[1]}",
        ))


def check_platform_capabilities(report: Report) -> None:
    """Things this operating system can and cannot do, stated up front."""
    # Raw packet capture
    if IS_LINUX:
        detail, status, fix = "available on Linux", OK, ""
    else:
        detail = f"not available on {SYSTEM}"
        status, fix = INFO, "Run network monitoring on the Raspberry Pi instead."
    report.add(Check(
        "network capture", status,
        "Watching raw network traffic. Only Linux can do this without extra "
        "drivers, which is why it belongs on the Raspberry Pi.",
        detail, fix, "hexbee-netmon"))

    # Memory acquisition
    if IS_MACOS:
        report.add(Check(
            "memory capture", INFO,
            "Copying a computer's live memory for analysis.",
            "not possible on macOS — Apple blocks the access this needs",
            "Capture memory on Windows or Linux targets instead.",
        ))
    else:
        from pathlib import Path as _P
        tool = shutil.which("winpmem_mini_x64.exe") if IS_WINDOWS else (
            os.environ.get("HEXBEE_LIME_MODULE")
            or next((p for p in ("/opt/hexbee/lime.ko", "./lime.ko")
                     if _P(p).is_file()), None))
        report.add(Check(
            "memory capture", OK if tool else WARN,
            "Copying a computer's live memory for analysis — where running "
            "malware actually lives.",
            tool or "no capture tool found",
            "" if tool else (
                "Put winpmem_mini_x64.exe on your PATH" if IS_WINDOWS else
                "Build LiME for this kernel, then: export "
                "HEXBEE_LIME_MODULE=/path/lime.ko"),
            "hexbee-forager memory",
        ))

    # Disk images
    report.add(Check(
        "disk images", INFO,
        "Opening a forensic disk image.",
        ("Use `hexbee-comb extract` — it reads the image directly and never "
         "mounts it, which works on every platform and is safer than mounting."),
    ))


def check_scope(db, report: Report) -> None:
    from .scope import list_rules

    rules = [r for r in list_rules(db) if r["active"]]
    if rules:
        report.add(Check(
            "engagement scope", OK,
            "The list of systems you are authorised to test. HexBee refuses "
            "to touch anything not on it.",
            f"{len(rules)} active rule(s)",
        ))
    else:
        report.add(Check(
            "engagement scope", INFO,
            "The list of systems you are authorised to test. HexBee refuses "
            "to touch anything not on it — so with nothing listed, the active "
            "tools are blocked. That is deliberate.",
            "no rules defined — active testing tools are blocked",
            "hexbee-queen scope add cidr 10.0.0.0/24 --auth-ref <client ref>",
            "recon, Responder, and the other active tools",
        ))


# -- assembly and rendering -----------------------------------------------

def run(cfg, db) -> Report:
    report = Report()
    check_python(report)
    check_data_dir(cfg, report)
    check_database(cfg, db, report)
    check_users(db, report)
    check_ingest_key(cfg, report)
    check_web_deps(report)
    check_knowledge(report)
    check_scope(db, report)
    check_companion_tools(report)
    check_optional_python(report)
    check_external_tools(report)
    check_ai(cfg, report)
    check_platform_capabilities(report)
    return report


_MARK = {OK: "[ ok ]", WARN: "[ -- ]", MISSING: "[FAIL]", INFO: "[note]"}


def render(report: Report, verbose: bool = False) -> str:
    """Plain-text report. Explains rather than just listing."""
    lines = [
        "HexBee health check",
        "=" * 60,
        f"Running on {SYSTEM} {platform.machine()}",
        "",
    ]

    blocking = [c for c in report.checks if c.status == MISSING]
    if blocking:
        lines.append("NEEDS ATTENTION — HexBee will not work properly until "
                     "these are fixed:")
        lines.append("")
        for check in blocking:
            lines.append(f"  {_MARK[check.status]} {check.name}")
            lines.append(f"         {check.what}")
            lines.append(f"         Found: {check.detail}")
            if check.fix:
                lines.append(f"         Fix:   {check.fix}")
            lines.append("")

    optional = [c for c in report.checks if c.status == WARN]
    if optional:
        lines.append("OPTIONAL — everything works without these, but you get "
                     "more with them:")
        lines.append("")
        for check in optional:
            lines.append(f"  {_MARK[check.status]} {check.name} — {check.detail}")
            lines.append(f"         {check.what}")
            if check.enables:
                lines.append(f"         Unlocks: {check.enables}")
            if check.fix:
                lines.append(f"         Install: {check.fix}")
            lines.append("")

    notes = [c for c in report.checks if c.status == INFO]
    if notes:
        lines.append("GOOD TO KNOW — how things work on this machine:")
        lines.append("")
        for check in notes:
            lines.append(f"  {_MARK[check.status]} {check.name} — {check.detail}")
            if check.fix:
                lines.append(f"         {check.fix}")
            lines.append("")

    working = [c for c in report.checks if c.status == OK]
    if verbose:
        lines.append("WORKING:")
        lines.append("")
        for check in working:
            lines.append(f"  {_MARK[check.status]} {check.name} — {check.detail}")
        lines.append("")
    else:
        lines.append(f"WORKING: {len(working)} check(s) passed "
                     f"(run with --verbose to list them)")
        lines.append("")

    lines.append("-" * 60)
    if report.ready:
        lines.append("HexBee is ready to use.")
        lines.append("")
        lines.append("Not sure where to start? Open the dashboard and click "
                     "Start Here:")
        lines.append("    hexbee-hive web")
        lines.append("")
        lines.append("Or ask it directly:")
        lines.append('    hexbee-hive howto "someone gave me a usb stick, '
                     'what do I do"')
    else:
        lines.append("HexBee is not ready yet. Fix the items above, then run "
                     "this again:")
        lines.append("    hexbee-hive doctor")
        lines.append("")
        lines.append("If this is a fresh install, this does most of it for you:")
        lines.append("    hexbee-hive setup")
    return "\n".join(lines)
