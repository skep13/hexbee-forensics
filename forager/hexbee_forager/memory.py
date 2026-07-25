"""Memory acquisition.

Memory is where running malware actually lives, so this is the one Forager
capability that produces a large artifact rather than a small event. Every
design choice here follows from one hardware fact: **the analyst laptop has
4 GB of RAM and the target may have 16 GB or more.**

Consequences, enforced in code:

  * The dump is written straight to the destination — an external HDD — by
    the acquisition tool itself. Forager never holds the image.
  * Hashing streams the file back in fixed-size chunks. Peak memory for a
    64 GB dump is one chunk.
  * Free space is checked *before* acquisition starts, because running a
    target out of disk mid-dump is worse than not dumping at all.
  * Analysis (Volatility 3) is explicitly not run here. It happens later, on
    the Queen, against the file on the HDD.

Acquisition is the only Forager operation that is not read-only in the
strictest sense: LiME and winpmem load a driver on the target. That is
unavoidable for live memory capture and it is called out loudly in the CLI.
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("hexbee.forager.memory")

IS_WINDOWS = platform.system() == "Windows"
CHUNK = 8 * 1024 * 1024          # hashing chunk: 8 MB, constant peak memory

# Where the acquisition tools are looked for, in order.
LIME_PATHS = ["/opt/hexbee/lime.ko", "/usr/local/lib/lime.ko", "./lime.ko"]
WINPMEM_NAMES = ["winpmem_mini_x64.exe", "winpmem.exe", "winpmem_mini_x86.exe"]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _event(event_type: str, payload: dict) -> dict:
    return {"event_type": event_type, "occurred_at": _now(), "payload": payload}


def physical_memory_bytes() -> int:
    """Installed RAM, used for the free-space precheck."""
    try:
        import psutil  # type: ignore
        return int(psutil.virtual_memory().total)
    except ImportError:
        pass
    if IS_WINDOWS:
        try:
            import ctypes

            class Status(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong),
                            ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

            status = Status()
            status.dwLength = ctypes.sizeof(Status)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))
            return int(status.ullTotalPhys)
        except Exception:
            return 0
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        return 0


def find_tool(method: str = "auto") -> tuple[str, str] | None:
    """Return (method, path) for the first usable acquisition tool."""
    if method in ("auto", "winpmem") and IS_WINDOWS:
        for name in WINPMEM_NAMES:
            found = shutil.which(name)
            if found:
                return "winpmem", found
            local = Path(name)
            if local.is_file():
                return "winpmem", str(local.resolve())
        if method == "winpmem":
            return None
    if method in ("auto", "lime") and not IS_WINDOWS:
        env = os.environ.get("HEXBEE_LIME_MODULE", "")
        for candidate in ([env] if env else []) + LIME_PATHS:
            if candidate and Path(candidate).is_file():
                return "lime", str(Path(candidate).resolve())
        if method == "lime":
            return None
    if method in ("auto", "kcore") and not IS_WINDOWS:
        if Path("/proc/kcore").exists() and os.access("/proc/kcore", os.R_OK):
            return "kcore", "/proc/kcore"
    return None


def check_space(dest_dir: Path, needed: int) -> tuple[bool, dict]:
    """Refuse to start unless the destination can hold the image plus 10%."""
    try:
        usage = shutil.disk_usage(dest_dir)
    except OSError as exc:
        return False, {"error": f"cannot stat {dest_dir}: {exc}"}
    required = int(needed * 1.1) if needed else 0
    return usage.free >= required, {
        "free": usage.free, "required": required, "ram": needed,
        "destination": str(dest_dir),
    }


def hash_stream(path: Path, chunk: int = CHUNK, progress=None) -> tuple[str, int]:
    """SHA-256 of a file, read `chunk` bytes at a time. Peak memory is one
    chunk regardless of file size — this is what makes a 64 GB dump safe to
    hash on a 4 GB laptop."""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            digest.update(block)
            size += len(block)
            if progress:
                progress(size)
    return digest.hexdigest(), size


def acquire(dest_dir: str | Path, *, method: str = "auto",
            device: str = "", case_id: int | None = None,
            note: str = "", chunk: int = CHUNK,
            dry_run: bool = False) -> list[dict]:
    """Capture physical memory to `dest_dir`. Returns Hive event dicts.

    The caller (the CLI) ships these through the normal Forager path, so a
    dump performed on an isolated target still lands in the evidence chain
    once the stick comes back to a networked machine.
    """
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    ram = physical_memory_bytes()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    host = platform.node() or "unknown"
    out_path = dest_dir / f"{host}_{stamp}_memory.raw"

    tool = find_tool(method)
    started = _event("memory_acquisition_started", {
        "destination": str(out_path), "method": tool[0] if tool else method,
        "ram_bytes": ram, "host": host, "case_id": case_id, "note": note[:500],
        "warning": "acquisition loads a kernel driver on the target",
    })
    if tool is None:
        return [started, _event("memory_acquisition_failed", {
            "destination": str(out_path),
            "reason": _missing_tool_message(method),
            "ram_bytes": ram})]

    ok, space = check_space(dest_dir, ram)
    if not ok:
        return [started, _event("memory_acquisition_failed", {
            "destination": str(out_path), "reason": "insufficient free space",
            **space})]
    if dry_run:
        return [started, _event("memory_acquisition_failed", {
            "destination": str(out_path), "reason": "dry run — nothing captured",
            "method": tool[0], "tool": tool[1], **space})]

    method_name, tool_path = tool
    begin = time.time()
    try:
        if method_name == "lime":
            _acquire_lime(tool_path, out_path)
        elif method_name == "winpmem":
            _acquire_winpmem(tool_path, out_path)
        else:
            _acquire_kcore(out_path, chunk)
    except Exception as exc:
        log.exception("memory acquisition failed")
        return [started, _event("memory_acquisition_failed", {
            "destination": str(out_path), "method": method_name,
            "reason": str(exc)[:500]})]

    if not out_path.exists() or out_path.stat().st_size == 0:
        return [started, _event("memory_acquisition_failed", {
            "destination": str(out_path), "method": method_name,
            "reason": "acquisition tool produced no output"})]

    digest, size = hash_stream(out_path, chunk)
    elapsed = round(time.time() - begin, 1)
    return [started, _event("memory_acquired", {
        "path": str(out_path), "sha256": digest, "size": size,
        "method": method_name, "tool": tool_path, "host": host,
        "ram_bytes": ram, "seconds": elapsed, "case_id": case_id,
        "note": note[:500],
        "next_step": "analyse on the Queen: vol -f <path> <plugin>",
    })]


def _missing_tool_message(method: str) -> str:
    if IS_WINDOWS:
        return ("winpmem not found. Put winpmem_mini_x64.exe on the triage "
                "stick beside forager.exe, or on PATH.")
    return ("no acquisition method available. Build LiME for this kernel and "
            "set HEXBEE_LIME_MODULE=/path/lime.ko, or run as root where "
            "/proc/kcore is readable.")


def _acquire_lime(module: str, out_path: Path) -> None:
    """LiME writes the image itself — Forager never touches the bytes."""
    cmd = ["insmod", module, f"path={out_path}", "format=lime"]
    if os.geteuid() != 0:
        cmd = ["sudo", "-n"] + cmd
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    if proc.returncode != 0:
        raise RuntimeError(f"insmod failed: {(proc.stderr or '').strip()[:300]}")
    # The module stays loaded until removed; leaving it in place would be an
    # unnecessary change to the target.
    subprocess.run((["sudo", "-n"] if os.geteuid() != 0 else []) + ["rmmod", "lime"],
                   capture_output=True, text=True, timeout=120)


def _acquire_winpmem(tool: str, out_path: Path) -> None:
    proc = subprocess.run([tool, str(out_path)], capture_output=True,
                          text=True, timeout=7200)
    if proc.returncode != 0:
        raise RuntimeError(f"winpmem failed: {(proc.stderr or proc.stdout or '').strip()[:300]}")


def _acquire_kcore(out_path: Path, chunk: int) -> None:
    """Last-resort capture by streaming /proc/kcore.

    Chunked copy, never a full read. /proc/kcore is an ELF view of kernel
    memory: usable for strings and some Volatility workflows, inferior to a
    LiME image, and unavailable when kernel lockdown is on.
    """
    src = Path("/proc/kcore")
    if not os.access(src, os.R_OK):
        raise RuntimeError("/proc/kcore is not readable (need root, and kernel "
                           "lockdown must be off)")
    with open(src, "rb") as fin, open(out_path, "wb") as fout:
        while True:
            block = fin.read(chunk)
            if not block:
                break
            fout.write(block)


def status() -> dict:
    """What acquisition would do right now, without doing it."""
    tool = find_tool("auto")
    ram = physical_memory_bytes()
    return {
        "platform": platform.system(),
        "ram_bytes": ram,
        "ram_human": f"{ram / (1024 ** 3):.1f} GB" if ram else "unknown",
        "method": tool[0] if tool else None,
        "tool": tool[1] if tool else None,
        "ready": tool is not None,
        "reason": "ready" if tool else _missing_tool_message("auto"),
        "elevated": (IS_WINDOWS and _is_admin_windows())
                    or (not IS_WINDOWS and os.geteuid() == 0),
    }


def _is_admin_windows() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
