"""File inventory: walk a target directory (a mounted image, an extraction,
or a live folder) hashing and typing every file."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .magic import EXECUTABLE_TYPES, HEADER_LEN, extension_mismatch, identify


@dataclass
class FileRecord:
    path: str
    size: int
    sha256: str
    magic_type: str | None
    mismatch: bool
    executable: bool
    modified: str
    created: str


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_file(path: Path) -> tuple[str, str | None]:
    """(sha256, magic_type) in one pass."""
    digest = hashlib.sha256()
    header = b""
    with open(path, "rb") as fh:
        first = fh.read(HEADER_LEN)
        header = first
        digest.update(first)
        while chunk := fh.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest(), identify(header)


def walk(target: str | Path, max_files: int | None = None) -> Iterator[FileRecord]:
    """Yield a FileRecord per regular file under `target`. Unreadable files
    are skipped (locked hives on a live system, dangling links, ...)."""
    target = Path(target)
    count = 0
    for root, _dirs, files in os.walk(target):
        for name in files:
            if max_files is not None and count >= max_files:
                return
            path = Path(root) / name
            try:
                stat = path.stat()
                sha256, magic_type = hash_file(path)
            except (OSError, PermissionError):
                continue
            count += 1
            yield FileRecord(
                path=str(path.relative_to(target)),
                size=stat.st_size,
                sha256=sha256,
                magic_type=magic_type,
                mismatch=extension_mismatch(magic_type, name),
                executable=magic_type in EXECUTABLE_TYPES,
                modified=_iso(stat.st_mtime),
                created=_iso(stat.st_ctime),
            )
