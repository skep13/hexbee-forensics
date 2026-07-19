"""Indicator-of-compromise matching.

Investigators load known-bad indicators (file hashes, filenames, IPs,
domains, or free substrings); every incoming event's payload is checked at
ingest. A match:

  - boosts the event to severity 3, which guarantees the correlation engine
    opens (or extends) an incident,
  - records a row in ioc_hits,
  - tags the event `ioc`,
  - lands in the audit log.

Matching is plain case-insensitive containment against every string value in
the payload (checked recursively). At Scout event rates and realistic IOC
list sizes (hundreds), a linear scan on a Pi 3B+ is microseconds; no index
gymnastics needed.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .db import Database
from .store import audit

KINDS = ("sha256", "filename", "ip", "domain", "substring")

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def add_ioc(db: Database, kind: str, value: str, note: str, actor: str) -> int:
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    value = value.strip()
    if not value:
        raise ValueError("empty IOC value")
    if kind == "sha256":
        value = value.lower()
        if not _SHA256_RE.match(value):
            raise ValueError("sha256 IOC must be 64 hex characters")
    if kind == "ip" and not _IP_RE.match(value):
        raise ValueError("ip IOC must be a dotted IPv4 address")
    cur = db.execute(
        "INSERT INTO iocs (kind, value, note, added_by, added_at) VALUES (?, ?, ?, ?, ?)",
        (kind, value, note, actor, _now()),
    )
    audit(db, actor, "ioc_added", f"{kind}:{value}")
    return cur.lastrowid


def remove_ioc(db: Database, ioc_id: int, actor: str) -> bool:
    row = db.query_one("SELECT kind, value FROM iocs WHERE id = ?", (ioc_id,))
    if row is None:
        return False
    with db.transaction() as conn:
        conn.execute("DELETE FROM ioc_hits WHERE ioc_id = ?", (ioc_id,))
        conn.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
    audit(db, actor, "ioc_removed", f"{row['kind']}:{row['value']}")
    return True


def list_iocs(db: Database) -> list[dict]:
    rows = db.query(
        """SELECT i.*, COUNT(h.id) AS hits
           FROM iocs i LEFT JOIN ioc_hits h ON h.ioc_id = i.id
           GROUP BY i.id ORDER BY i.id DESC"""
    )
    return [dict(r) for r in rows]


def list_hits(db: Database, limit: int = 200) -> list[dict]:
    rows = db.query(
        """SELECT h.matched_at, i.kind, i.value, i.note,
                  e.id AS event_id, e.event_type, e.occurred_at, e.incident_id,
                  d.name AS device
           FROM ioc_hits h
           JOIN iocs i ON i.id = h.ioc_id
           JOIN events e ON e.id = h.event_id
           JOIN devices d ON d.id = e.device_id
           ORDER BY h.id DESC LIMIT ?""",
        (max(1, min(limit, 2000)),),
    )
    return [dict(r) for r in rows]


def _payload_strings(value) -> list[str]:
    """All string leaves of a payload, lowercased (numbers included as text)."""
    out: list[str] = []
    if isinstance(value, dict):
        for v in value.values():
            out.extend(_payload_strings(v))
    elif isinstance(value, list):
        for v in value:
            out.extend(_payload_strings(v))
    elif isinstance(value, str):
        out.append(value.lower())
    elif isinstance(value, (int, float)):
        out.append(str(value))
    return out


def match_iocs(db: Database, payload: dict) -> list[dict]:
    """IOC rows whose value appears in any payload string."""
    haystacks = _payload_strings(payload)
    if not haystacks:
        return []
    matches = []
    for ioc in db.query("SELECT * FROM iocs"):
        needle = ioc["value"].lower()
        if any(needle in hay for hay in haystacks):
            matches.append(dict(ioc))
    return matches


def record_hits(db: Database, event_id: int, matches: list[dict]) -> None:
    from .cases import tag_event  # local import to avoid a cycle

    for ioc in matches:
        db.execute(
            "INSERT OR IGNORE INTO ioc_hits (ioc_id, event_id, matched_at) VALUES (?, ?, ?)",
            (ioc["id"], event_id, _now()),
        )
        audit(db, "ioc-engine", "ioc_hit",
              f"event {event_id} matched {ioc['kind']}:{ioc['value']}")
    if matches:
        tag_event(db, event_id, "ioc", actor="ioc-engine")
