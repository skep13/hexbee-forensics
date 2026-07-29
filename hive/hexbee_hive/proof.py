"""Demonstrate what the hash chain actually guarantees.

The claim "tamper-evident" is worth nothing to an examiner, a client or a court
until someone shows the tamper being caught. This module does that arithmetic
live, on real records, and — importantly — **without writing anything**.

Every function here is pure: it reads a record, recomputes hashes over an
altered *copy* held in memory, and reports what would break. A forensics tool
must never ship a button that edits evidence, not even to prove a point, so
there isn't one. The database is opened read-only-in-spirit: no INSERT, no
UPDATE, no DELETE appears anywhere in this file.

What this shows that a per-file hash cannot:

  * a per-file hash proves *this file* was not altered;
  * a chain proves the *sequence* was not altered — nothing inserted, nothing
    deleted, nothing reordered — because every record commits to the entire
    history before it.

That difference is the whole argument for a live evidence log over a folder of
hashed exhibits, and it is what the page built on this module makes visible.
"""

from __future__ import annotations

import json

from .db import Database
from .integrity import GENESIS_HASH, chain_hash, event_record, verify_chain


def chain_status(db: Database) -> dict:
    """Live verification plus the numbers a demo needs on screen."""
    result = verify_chain(db)
    total = db.query("SELECT COUNT(*) AS n FROM events")[0]["n"]
    devices = db.query("SELECT COUNT(DISTINCT device_id) AS n FROM events")[0]["n"]
    head = db.query(
        "SELECT id, event_hash, occurred_at FROM events ORDER BY id DESC LIMIT 1")
    return {
        "ok": result["ok"],
        "checked": result["checked"],
        "first_bad_id": result.get("first_bad_id"),
        "total_events": total,
        "devices": devices,
        "head": dict(head[0]) if head else None,
    }


def _record_for(db: Database, event_id: int) -> dict | None:
    rows = db.query(
        """SELECT e.id, e.occurred_at, e.event_type, e.payload, e.prev_hash,
                  e.event_hash, d.name AS device
             FROM events e JOIN devices d ON d.id = e.device_id
            WHERE e.id = ?""", (event_id,))
    return dict(rows[0]) if rows else None


def explain(db: Database, event_id: int) -> dict | None:
    """The exact inputs one record's hash commits to.

    Shown rather than described, because "it's hashed" is the part people nod
    along to without believing.
    """
    row = _record_for(db, event_id)
    if row is None:
        return None
    try:
        payload = json.loads(row["payload"])
    except (TypeError, ValueError):
        payload = row["payload"]
    record = event_record(row["occurred_at"], row["device"],
                          row["event_type"], payload)
    recomputed = chain_hash(row["prev_hash"] or GENESIS_HASH, record)
    return {
        "event_id": row["id"],
        "inputs": {
            "previous_hash": row["prev_hash"] or GENESIS_HASH,
            "occurred_at": row["occurred_at"],
            "device": row["device"],
            "event_type": row["event_type"],
            "payload": payload,
        },
        "stored_hash": row["event_hash"],
        "recomputed_hash": recomputed,
        "matches": recomputed == row["event_hash"],
    }


def tamper_preview(db: Database, event_id: int, field: str,
                   new_value: str) -> dict | None:
    """Alter one field **on a copy** and report the damage.

    `field` is one of occurred_at / device / event_type / payload. Nothing is
    written; the altered record exists only for the length of this call.
    """
    row = _record_for(db, event_id)
    if row is None:
        return None
    try:
        payload = json.loads(row["payload"])
    except (TypeError, ValueError):
        payload = row["payload"]

    original = {
        "occurred_at": row["occurred_at"], "device": row["device"],
        "event_type": row["event_type"], "payload": payload,
    }
    altered = dict(original)
    if field == "payload":
        try:
            altered["payload"] = json.loads(new_value)
        except (TypeError, ValueError):
            altered["payload"] = new_value
    elif field in altered:
        altered[field] = new_value
    else:
        return None

    prev = row["prev_hash"] or GENESIS_HASH
    before = chain_hash(prev, event_record(**original))
    after = chain_hash(prev, event_record(**altered))

    # Every later record commits to this one, so they all become unverifiable.
    downstream = db.query(
        "SELECT COUNT(*) AS n FROM events WHERE id > ?", (event_id,))[0]["n"]

    return {
        "event_id": event_id,
        "field": field,
        "original_value": original.get(field) if field != "payload" else payload,
        "tampered_value": altered.get(field),
        "hash_before": before,
        "hash_after": after,
        "changed": before != after,
        "downstream_broken": downstream,
        "total_invalidated": downstream + 1,
        # The point an examiner needs in one sentence.
        "verdict": (
            f"Changing {field} on event #{event_id} changes its hash, which "
            f"breaks the {downstream} record(s) chained after it. "
            f"`hexbee-hive verify` would name #{event_id} as the first bad "
            f"record." if before != after else
            "That value is already what is stored — nothing would change."
        ),
    }
