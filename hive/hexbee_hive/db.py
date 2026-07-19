"""SQLite storage layer for the Hive.

SQLite is deliberate: the Hive runs on a Raspberry Pi 3B+ with 1 GB of RAM,
and the write pattern (single ingest process, many small inserts) suits WAL
mode well. All schema lives here so `hexbee-hive init` can build a fresh
database and migrations stay in one place.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS devices (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL DEFAULT 'scout',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    notes       TEXT NOT NULL DEFAULT ''
);

-- Append-only evidence log. Each row's hash chains over the previous row's
-- hash, so any retroactive edit breaks verification from that point on.
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY,
    received_at  TEXT NOT NULL,           -- Hive receipt time, UTC ISO-8601
    occurred_at  TEXT NOT NULL,           -- Scout-reported time, UTC ISO-8601
    device_id    INTEGER NOT NULL REFERENCES devices(id),
    event_type   TEXT NOT NULL,
    payload      TEXT NOT NULL,           -- canonical JSON
    severity     INTEGER NOT NULL DEFAULT 0,
    prev_hash    TEXT NOT NULL,
    event_hash   TEXT NOT NULL UNIQUE,
    incident_id  INTEGER REFERENCES incidents(id)
);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_device ON events(device_id);
CREATE INDEX IF NOT EXISTS idx_events_occurred ON events(occurred_at);
CREATE INDEX IF NOT EXISTS idx_events_incident ON events(incident_id);

CREATE TABLE IF NOT EXISTS incidents (
    id          INTEGER PRIMARY KEY,
    opened_at   TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL DEFAULT 'open',   -- open | triaged | closed
    case_id     INTEGER REFERENCES cases(id)
);

CREATE TABLE IF NOT EXISTS cases (
    id           INTEGER PRIMARY KEY,
    case_number  TEXT NOT NULL UNIQUE,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'open',  -- open | active | closed
    created_at   TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    closed_at    TEXT
);

CREATE TABLE IF NOT EXISTS case_notes (
    id         INTEGER PRIMARY KEY,
    case_id    INTEGER NOT NULL REFERENCES cases(id),
    author     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    body       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tags (
    id        INTEGER PRIMARY KEY,
    name      TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS event_tags (
    event_id  INTEGER NOT NULL REFERENCES events(id),
    tag_id    INTEGER NOT NULL REFERENCES tags(id),
    PRIMARY KEY (event_id, tag_id)
);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,      -- pbkdf2:sha256:<iters>:<salt>:<hash>
    role          TEXT NOT NULL,      -- administrator | investigator | viewer
    created_at    TEXT NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS api_tokens (
    token       TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL
);

-- Indicators of compromise. Matched against event payloads at ingest.
CREATE TABLE IF NOT EXISTS iocs (
    id        INTEGER PRIMARY KEY,
    kind      TEXT NOT NULL,     -- sha256 | filename | ip | domain | substring
    value     TEXT NOT NULL,
    note      TEXT NOT NULL DEFAULT '',
    added_by  TEXT NOT NULL,
    added_at  TEXT NOT NULL,
    UNIQUE (kind, value)
);

CREATE TABLE IF NOT EXISTS ioc_hits (
    id         INTEGER PRIMARY KEY,
    ioc_id     INTEGER NOT NULL REFERENCES iocs(id),
    event_id   INTEGER NOT NULL REFERENCES events(id),
    matched_at TEXT NOT NULL,
    UNIQUE (ioc_id, event_id)
);

-- Append-only audit trail of analyst actions (chain-of-custody support).
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY,
    at         TEXT NOT NULL,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT ''
);
"""


class Database:
    """Thread-safe wrapper around a single SQLite file.

    Flask serves requests from multiple threads while the MQTT ingest loop
    writes from its own thread, so every access goes through a lock. On a
    Pi 3B+ contention is negligible at Scout event rates.
    """

    def __init__(self, path: Path | str):
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._lock:
            self._conn.executescript(SCHEMA)

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def transaction(self):
        """Context manager: `with db.transaction() as conn:` — commit on
        success, rollback on exception, all under the lock."""
        return _Txn(self._lock, self._conn)

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class _Txn:
    def __init__(self, lock: threading.RLock, conn: sqlite3.Connection):
        self._lock = lock
        self._conn = conn

    def __enter__(self) -> sqlite3.Connection:
        self._lock.acquire()
        return self._conn

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if exc_type is None:
                self._conn.commit()
            else:
                self._conn.rollback()
        finally:
            self._lock.release()
