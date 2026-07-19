"""Event persistence: the single write path into the evidence log.

Every event — whether it arrived over MQTT or REST ingest — goes through
`store_event`, which is the only code that appends to the events table.
Keeping one write path is what makes the hash chain trustworthy.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .db import Database
from .integrity import GENESIS_HASH, canonical_json, chain_hash, event_record


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def upsert_device(db: Database, name: str, kind: str = "scout") -> int:
    now = _utcnow_iso()
    row = db.query_one("SELECT id FROM devices WHERE name = ?", (name,))
    if row:
        db.execute("UPDATE devices SET last_seen = ? WHERE id = ?", (now, row["id"]))
        return row["id"]
    cur = db.execute(
        "INSERT INTO devices (name, kind, first_seen, last_seen) VALUES (?, ?, ?, ?)",
        (name, kind, now, now),
    )
    return cur.lastrowid


def store_event(db: Database, normalized: dict) -> int:
    """Append a normalized event to the hash-chained log. Returns event id."""
    device_id = upsert_device(db, normalized["device"])
    record = event_record(
        normalized["occurred_at"],
        normalized["device"],
        normalized["event_type"],
        normalized["payload"],
    )
    with db.transaction() as conn:
        row = conn.execute(
            "SELECT event_hash FROM events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = row["event_hash"] if row else GENESIS_HASH
        cur = conn.execute(
            """INSERT INTO events
               (received_at, occurred_at, device_id, event_type, payload,
                severity, prev_hash, event_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                _utcnow_iso(),
                normalized["occurred_at"],
                device_id,
                normalized["event_type"],
                canonical_json(normalized["payload"]),
                normalized["severity"],
                prev_hash,
                chain_hash(prev_hash, record),
            ),
        )
        return cur.lastrowid


def audit(db: Database, actor: str, action: str, detail: str = "") -> None:
    db.execute(
        "INSERT INTO audit_log (at, actor, action, detail) VALUES (?, ?, ?, ?)",
        (_utcnow_iso(), actor, action, detail),
    )


def event_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "received_at": row["received_at"],
        "occurred_at": row["occurred_at"],
        "device": row["device"],
        "event_type": row["event_type"],
        "payload": json.loads(row["payload"]),
        "severity": row["severity"],
        "event_hash": row["event_hash"],
        "incident_id": row["incident_id"],
    }


EVENT_SELECT = """
    SELECT e.id, e.received_at, e.occurred_at, e.event_type, e.payload,
           e.severity, e.prev_hash, e.event_hash, e.incident_id,
           d.name AS device
    FROM events e JOIN devices d ON d.id = e.device_id
"""
