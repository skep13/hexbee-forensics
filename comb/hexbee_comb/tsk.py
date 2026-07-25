"""Optional Sleuth Kit integration.

When `mmls`/`fls` are on PATH (Kali installs sleuthkit by default), Comb can
walk NTFS/ext4/HFS+ filesystems inside images without mounting them. On
systems without TSK everything degrades to the pure-Python capabilities.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


def available() -> bool:
    return shutil.which("mmls") is not None and shutil.which("fls") is not None


def recover_available() -> bool:
    return shutil.which("tsk_recover") is not None


@dataclass
class TskEntry:
    path: str
    size: int
    modified: int   # unix epoch
    accessed: int
    created: int
    deleted: bool


def list_files(image_path: str, sector_offset: int = 0,
               timeout: int = 600) -> list[TskEntry]:
    """Recursive file listing of one filesystem via `fls -r -m` (bodyfile).

    Bodyfile columns: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
    """
    cmd = ["fls", "-r", "-m", "/", "-o", str(sector_offset), str(image_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"fls failed: {proc.stderr.strip()}")
    entries = []
    for line in proc.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < 11:
            continue
        name = parts[1]
        deleted = "(deleted)" in name
        entries.append(
            TskEntry(
                path=name.replace(" (deleted)", ""),
                size=int(parts[6] or 0),
                accessed=int(parts[7] or 0),
                modified=int(parts[8] or 0),
                created=int(parts[10] or 0),
                deleted=deleted,
            )
        )
    return entries


def recover(image_path: str, out_dir: str, sector_offset: int = 0,
            allocated_only: bool = False, timeout: int = 3600) -> dict:
    """Extract files out of an image into `out_dir` — without mounting it.

    This is what makes Comb work on macOS and Windows. Mounting a forensic
    image needs a loop device, which is Linux-only; `tsk_recover` reads the
    filesystem directly and writes the files out, so the extraction can then
    be scanned like any ordinary folder.

    It is also the safer option everywhere: the evidence is never mounted by
    the host OS, so there is no chance of the operating system touching
    timestamps or writing recovery files to it. By default deleted files are
    recovered too, which is usually the point.
    """
    from pathlib import Path

    if not recover_available():
        raise RuntimeError(
            "tsk_recover not found. Install Sleuth Kit:\n"
            "  macOS:  brew install sleuthkit\n"
            "  Debian: sudo apt install sleuthkit")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    cmd = ["tsk_recover"]
    # -e recovers every file including deleted; -a only allocated ones.
    cmd.append("-a" if allocated_only else "-e")
    if sector_offset:
        cmd += ["-o", str(sector_offset)]
    cmd += [str(image_path), str(out)]

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"tsk_recover failed: {proc.stderr.strip()[:400]}")

    recovered = sum(1 for p in out.rglob("*") if p.is_file())
    return {
        "output_dir": str(out),
        "files": recovered,
        "deleted_included": not allocated_only,
        "message": (proc.stdout or "").strip()[:400],
    }
