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
