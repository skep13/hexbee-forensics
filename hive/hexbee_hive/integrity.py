"""Evidence integrity: hash chaining and verification.

Every stored event gets `event_hash = SHA-256(prev_hash || canonical_record)`
where `prev_hash` is the hash of the previously stored event (the genesis
value for the first). Because each hash commits to the entire history before
it, editing or deleting any past row breaks verification from that row
forward — giving an append-only evidence log without needing external
infrastructure.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS_HASH = "0" * 64


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no insignificant whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def chain_hash(prev_hash: str, record: dict) -> str:
    material = prev_hash + canonical_json(record)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def event_record(occurred_at: str, device: str, event_type: str, payload: dict) -> dict:
    """The exact fields committed to by the hash chain.

    `received_at` is intentionally excluded: it is Hive-local bookkeeping and
    including it would make independent re-verification from a Scout's own
    records impossible.
    """
    return {
        "occurred_at": occurred_at,
        "device": device,
        "event_type": event_type,
        "payload": payload,
    }


def verify_chain(db) -> dict:
    """Walk the whole event table in insertion order and recompute the chain.

    Returns {"ok": bool, "checked": int, "first_bad_id": int | None}.
    """
    rows = db.query(
        """SELECT e.id, e.occurred_at, e.event_type, e.payload,
                  e.prev_hash, e.event_hash, d.name AS device
           FROM events e JOIN devices d ON d.id = e.device_id
           ORDER BY e.id"""
    )
    prev = GENESIS_HASH
    for row in rows:
        record = event_record(
            row["occurred_at"], row["device"], row["event_type"], json.loads(row["payload"])
        )
        if row["prev_hash"] != prev or chain_hash(prev, record) != row["event_hash"]:
            return {"ok": False, "checked": len(rows), "first_bad_id": row["id"]}
        prev = row["event_hash"]
    return {"ok": True, "checked": len(rows), "first_bad_id": None}
