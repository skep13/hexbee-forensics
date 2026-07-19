"""Forensic collectors.

Each collector returns a list of Hive-normalized event dicts:
    {"event_type": str, "occurred_at": ISO-8601, "payload": {...}}
(the agent stamps the device name). Every collector is read-only and wrapped
so a failure in one source never aborts the run.

Platform coverage: Windows and Linux/macOS. psutil is used when importable for
richer process/network/user data; native OS commands and stdlib are the
fallback so the tool runs on a bare target with no pip.
"""

from __future__ import annotations

import csv
import getpass
import io
import os
import platform
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

IS_WINDOWS = platform.system() == "Windows"

try:
    import psutil  # type: ignore
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _from_epoch(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return _now()


def _event(event_type: str, payload: dict, occurred_at: str | None = None) -> dict:
    return {"event_type": event_type, "occurred_at": occurred_at or _now(), "payload": payload}


def _run(cmd: list[str], timeout: int = 30) -> str:
    """Run a command read-only; return stdout (empty string on any failure)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              errors="ignore")
        return proc.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


# -- host information -----------------------------------------------------

def collect_host_info() -> list[dict]:
    uname = platform.uname()
    info = {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "os": uname.system,
        "os_release": uname.release,
        "os_version": uname.version,
        "arch": uname.machine,
        "python": sys.version.split()[0],
        "current_user": getpass.getuser(),
        "collector": "hexbee-forager",
    }
    # IP addresses
    addrs = set()
    try:
        for res in socket.getaddrinfo(socket.gethostname(), None):
            addrs.add(res[4][0])
    except socket.gaierror:
        pass
    info["ip_addresses"] = sorted(addrs)
    if HAVE_PSUTIL:
        try:
            info["boot_time"] = _from_epoch(psutil.boot_time())
        except Exception:
            pass
    return [_event("host_info", info)]


# -- processes ------------------------------------------------------------

def collect_processes() -> list[dict]:
    events = []
    if HAVE_PSUTIL:
        for proc in psutil.process_iter(["pid", "name", "username", "cmdline",
                                         "create_time", "exe"]):
            try:
                i = proc.info
                events.append(_event("process_snapshot", {
                    "pid": i.get("pid"),
                    "name": i.get("name"),
                    "user": i.get("username"),
                    "exe": i.get("exe"),
                    "cmdline": " ".join(i.get("cmdline") or [])[:500],
                    "started": _from_epoch(i["create_time"]) if i.get("create_time") else None,
                }))
            except Exception:
                continue
        return events

    # Fallback: native commands
    if IS_WINDOWS:
        out = _run(["tasklist", "/v", "/fo", "csv"])
        for row in _parse_csv(out):
            events.append(_event("process_snapshot", {
                "name": row.get("Image Name"),
                "pid": _int(row.get("PID")),
                "user": row.get("User Name"),
                "session": row.get("Session Name"),
                "window": row.get("Window Title"),
            }))
    else:
        out = _run(["ps", "-eo", "pid,user,comm,args", "--no-headers"])
        for line in out.splitlines():
            parts = line.split(None, 3)
            if len(parts) >= 3:
                events.append(_event("process_snapshot", {
                    "pid": _int(parts[0]), "user": parts[1], "name": parts[2],
                    "cmdline": (parts[3] if len(parts) > 3 else "")[:500],
                }))
    return events


# -- network connections --------------------------------------------------

def collect_network() -> list[dict]:
    events = []
    if HAVE_PSUTIL:
        try:
            pid_names = {p.pid: p.info["name"] for p in psutil.process_iter(["name"])}
        except Exception:
            pid_names = {}
        try:
            for c in psutil.net_connections(kind="inet"):
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                etype = "network_listening" if c.status == "LISTEN" else "network_connection"
                events.append(_event(etype, {
                    "proto": "tcp" if c.type == socket.SOCK_STREAM else "udp",
                    "local": laddr, "remote": raddr, "state": c.status,
                    "pid": c.pid, "process": pid_names.get(c.pid),
                }))
        except (psutil.AccessDenied, Exception):
            pass
        return events

    # Fallback
    if IS_WINDOWS:
        out = _run(["netstat", "-ano"])
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] in ("TCP", "UDP"):
                state = parts[4] if len(parts) > 4 and parts[0] == "TCP" else ""
                etype = "network_listening" if state == "LISTENING" else "network_connection"
                events.append(_event(etype, {
                    "proto": parts[0].lower(), "local": parts[1], "remote": parts[2],
                    "state": state, "pid": _int(parts[-1]),
                }))
    else:
        out = _run(["ss", "-tunap"]) or _run(["netstat", "-tunap"])
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                events.append(_event("network_connection", {
                    "proto": parts[0], "state": parts[1],
                    "local": parts[4] if len(parts) > 4 else "",
                    "remote": parts[5] if len(parts) > 5 else "",
                }))
    return events


# -- logged-on users ------------------------------------------------------

def collect_logons() -> list[dict]:
    events = []
    if HAVE_PSUTIL:
        try:
            for u in psutil.users():
                events.append(_event("logon_session", {
                    "user": u.name, "terminal": u.terminal, "host": u.host or "local",
                    "started": _from_epoch(u.started),
                }))
            return events
        except Exception:
            pass
    if IS_WINDOWS:
        out = _run(["query", "user"]) or _run(["quser"])
        for line in out.splitlines()[1:]:
            parts = line.split()
            if parts:
                events.append(_event("logon_session", {"user": parts[0].lstrip(">"),
                                                       "raw": line.strip()}))
    else:
        for line in _run(["who"]).splitlines():
            parts = line.split()
            if len(parts) >= 2:
                events.append(_event("logon_session", {
                    "user": parts[0], "terminal": parts[1], "raw": line.strip()}))
    return events


# -- autoruns / persistence ----------------------------------------------

def collect_autoruns() -> list[dict]:
    return _autoruns_windows() if IS_WINDOWS else _autoruns_posix()


def _autoruns_windows() -> list[dict]:
    import winreg

    events = []
    run_keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    for hive, subkey in run_keys:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                for i in range(winreg.QueryInfoKey(key)[1]):
                    name, value, _ = winreg.EnumValue(key, i)
                    events.append(_event("persistence_item", {
                        "type": "registry_run", "location": subkey,
                        "name": name, "command": str(value)[:500]}))
        except OSError:
            continue
    # Startup folders
    for folder in filter(None, [os.environ.get("APPDATA"), os.environ.get("PROGRAMDATA")]):
        startup = Path(folder) / r"Microsoft\Windows\Start Menu\Programs\Startup"
        if startup.is_dir():
            for item in startup.iterdir():
                if item.name.lower() != "desktop.ini":
                    events.append(_event("persistence_item", {
                        "type": "startup_folder", "location": str(startup),
                        "name": item.name}))
    return events


def _autoruns_posix() -> list[dict]:
    events = []
    cron_paths = ["/etc/crontab", "/etc/cron.d", "/var/spool/cron"]
    for p in cron_paths:
        path = Path(p)
        if path.is_file():
            events.append(_event("persistence_item", {"type": "cron", "location": p}))
        elif path.is_dir():
            for item in path.rglob("*"):
                if item.is_file():
                    events.append(_event("persistence_item",
                                         {"type": "cron", "location": str(item)}))
    # Enabled systemd units
    out = _run(["systemctl", "list-unit-files", "--state=enabled", "--no-legend", "--no-pager"])
    for line in out.splitlines():
        parts = line.split()
        if parts:
            events.append(_event("persistence_item",
                                 {"type": "systemd_unit", "name": parts[0]}))
    for shell_rc in ["/etc/rc.local", str(Path.home() / ".bashrc"),
                     str(Path.home() / ".profile")]:
        if Path(shell_rc).is_file():
            events.append(_event("persistence_item",
                                 {"type": "shell_init", "location": shell_rc}))
    return events


# -- USB device history ---------------------------------------------------

def collect_usb() -> list[dict]:
    if IS_WINDOWS:
        return _usb_windows()
    return _usb_posix()


def _usb_windows() -> list[dict]:
    import winreg

    events = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Enum\USBSTOR") as key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                device = winreg.EnumKey(key, i)
                events.append(_event("usb_device", {"type": "USBSTOR", "device": device}))
    except OSError:
        pass
    return events


def _usb_posix() -> list[dict]:
    events = []
    for line in _run(["lsusb"]).splitlines():
        if line.strip():
            events.append(_event("usb_device", {"raw": line.strip()}))
    return events


# -- recent files ---------------------------------------------------------

def collect_recent_files(days: int = 7, cap: int = 200) -> list[dict]:
    """Files modified within `days` under common user locations (metadata only
    — fast, no hashing of large trees)."""
    import time

    cutoff = time.time() - days * 86400
    roots = []
    home = Path.home()
    for sub in ("Downloads", "Desktop", "Documents"):
        roots.append(home / sub)
    roots.append(Path(os.environ.get("TEMP", "/tmp")))

    found = []
    for root in roots:
        if not root.is_dir():
            continue
        try:
            for path in root.rglob("*"):
                if len(found) >= cap:
                    break
                try:
                    if not path.is_file():
                        continue
                    st = path.stat()
                    if st.st_mtime >= cutoff:
                        found.append((st.st_mtime, path, st.st_size))
                except OSError:
                    continue
        except OSError:
            continue
    found.sort(reverse=True)
    return [_event("recent_file", {
        "path": str(p), "size": size, "modified": _from_epoch(mtime)},
        occurred_at=_from_epoch(mtime)) for mtime, p, size in found[:cap]]


# -- helpers --------------------------------------------------------------

def _parse_csv(text: str) -> list[dict]:
    if not text.strip():
        return []
    try:
        return list(csv.DictReader(io.StringIO(text)))
    except csv.Error:
        return []


def _int(value) -> int | None:
    try:
        return int(str(value).strip().strip('"'))
    except (TypeError, ValueError):
        return None


# Registry of collectors: (name, function, volatile?)
# Volatile collectors are the ones `watch` mode re-samples for change detection.
ALL_COLLECTORS = [
    ("host_info", collect_host_info, False),
    ("processes", collect_processes, True),
    ("network", collect_network, True),
    ("logons", collect_logons, True),
    ("usb", collect_usb, True),
    ("autoruns", collect_autoruns, False),
    ("recent_files", collect_recent_files, False),
]
