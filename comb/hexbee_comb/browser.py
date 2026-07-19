"""Browser history parsing: Chrome/Chromium `History` and Firefox
`places.sqlite`, from a mounted image or extracted profile.

Databases are copied to a temp file before opening — the originals may be
locked (live system) and evidence must never be opened read-write.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Profile locations relative to a target root (mounted image or user dir).
CHROME_GLOBS = [
    "Users/*/AppData/Local/Google/Chrome/User Data/*/History",
    "Users/*/AppData/Local/Microsoft/Edge/User Data/*/History",
    "Users/*/AppData/Local/Chromium/User Data/*/History",
    "home/*/.config/google-chrome/*/History",
    "home/*/.config/chromium/*/History",
]
FIREFOX_GLOBS = [
    "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
    "home/*/.mozilla/firefox/*/places.sqlite",
]


@dataclass
class Visit:
    browser: str
    profile: str
    url: str
    title: str
    visited_at: str  # UTC ISO-8601
    visit_count: int


def _chrome_time(webkit_us: int) -> str:
    """Chrome stores microseconds since 1601-01-01."""
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return (epoch + timedelta(microseconds=webkit_us)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _unix_us(us: int) -> str:
    return datetime.fromtimestamp(us / 1_000_000, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


@contextlib.contextmanager
def _copy_open(db_path: Path):
    """Open a read-only copy of an SQLite DB, then shred the copy.

    Evidence databases may be locked (live system) and must never be opened
    read-write, so we work on a copy. The copy is deleted on exit — leaving a
    duplicate of a subject's browser history in /tmp would itself be an
    evidence-handling failure.
    """
    tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    tmp.close()
    try:
        shutil.copyfile(db_path, tmp.name)
        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp.name)


def parse_chrome(db_path: str | Path, limit: int = 500) -> list[Visit]:
    db_path = Path(db_path)
    with _copy_open(db_path) as conn:
        rows = conn.execute(
            """SELECT url, title, visit_count, last_visit_time
               FROM urls WHERE last_visit_time > 0
               ORDER BY last_visit_time DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    profile = db_path.parent.name
    return [
        Visit("chrome", profile, r["url"], r["title"] or "",
              _chrome_time(r["last_visit_time"]), r["visit_count"])
        for r in rows
    ]


def parse_firefox(db_path: str | Path, limit: int = 500) -> list[Visit]:
    db_path = Path(db_path)
    with _copy_open(db_path) as conn:
        rows = conn.execute(
            """SELECT p.url, p.title, p.visit_count, MAX(v.visit_date) AS last_visit
               FROM moz_places p JOIN moz_historyvisits v ON v.place_id = p.id
               GROUP BY p.id ORDER BY last_visit DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    profile = db_path.parent.name
    return [
        Visit("firefox", profile, r["url"], r["title"] or "",
              _unix_us(r["last_visit"]), r["visit_count"])
        for r in rows
    ]


def find_and_parse(target_root: str | Path, limit_per_profile: int = 500) -> list[Visit]:
    """Autodetect browser profiles under a target root and parse them all."""
    root = Path(target_root)
    visits: list[Visit] = []
    for pattern in CHROME_GLOBS:
        for db in root.glob(pattern):
            try:
                visits.extend(parse_chrome(db, limit_per_profile))
            except sqlite3.Error:
                continue
    for pattern in FIREFOX_GLOBS:
        for db in root.glob(pattern):
            try:
                visits.extend(parse_firefox(db, limit_per_profile))
            except sqlite3.Error:
                continue
    visits.sort(key=lambda v: v.visited_at, reverse=True)
    return visits
