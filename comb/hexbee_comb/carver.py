"""Signature-based file carving from raw disk images.

Recovers deleted or unallocated files by scanning the raw bytes for known
header/footer pairs — the classic foremost/scalpel technique. Uses mmap so
multi-GB images don't need to fit in RAM.
"""

from __future__ import annotations

import hashlib
import mmap
from dataclasses import dataclass
from pathlib import Path

# (type, header, footer, footer_tail_bytes_to_include, max_size)
CARVE_RULES: list[tuple[str, bytes, bytes | None, int, int]] = [
    ("jpeg", b"\xff\xd8\xff", b"\xff\xd9", 2, 20 * 1024 * 1024),
    ("png", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", 8, 20 * 1024 * 1024),
    ("gif", b"GIF89a", b"\x00\x3b", 2, 10 * 1024 * 1024),
    ("pdf", b"%PDF-", b"%%EOF", 5, 50 * 1024 * 1024),
    ("zip", b"PK\x03\x04", b"PK\x05\x06", 22, 100 * 1024 * 1024),
    ("sqlite", b"SQLite format 3\x00", None, 0, 4 * 1024 * 1024),
]


@dataclass
class CarvedFile:
    kind: str
    offset: int
    size: int
    sha256: str
    path: str


def carve(image_path: str | Path, out_dir: str | Path) -> list[CarvedFile]:
    """Scan `image_path` and write recovered files into `out_dir`.

    Returns one record per carved file. Overlapping matches of the same type
    are suppressed (a match starting inside a previously carved region of the
    same kind is skipped).
    """
    image_path = Path(image_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    results: list[CarvedFile] = []

    with open(image_path, "rb") as fh:
        size = image_path.stat().st_size
        if size == 0:
            return results
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for kind, header, footer, tail, max_size in CARVE_RULES:
                pos = 0
                carved_until = -1
                while True:
                    start = mm.find(header, pos)
                    if start == -1:
                        break
                    if start < carved_until:
                        pos = start + 1
                        continue
                    window_end = min(start + max_size, size)
                    if footer is None:
                        end = window_end
                    else:
                        hit = mm.find(footer, start + len(header), window_end)
                        if hit == -1:
                            pos = start + 1
                            continue
                        end = hit + tail
                    data = mm[start:end]
                    digest = hashlib.sha256(data).hexdigest()
                    name = f"{start:012x}_{kind}.{_ext(kind)}"
                    out_path = out_dir / name
                    out_path.write_bytes(data)
                    results.append(
                        CarvedFile(kind, start, len(data), digest, str(out_path))
                    )
                    carved_until = end
                    pos = end if footer is not None else start + 1
    return results


def _ext(kind: str) -> str:
    return {"jpeg": "jpg", "sqlite": "db"}.get(kind, kind)
