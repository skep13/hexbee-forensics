"""Case management: cases, notes, tags, and incident assignment."""

from __future__ import annotations

from datetime import datetime, timezone

from .db import Database
from .store import audit


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _next_case_number(db: Database) -> str:
    year = datetime.now(timezone.utc).year
    row = db.query_one(
        "SELECT COUNT(*) AS n FROM cases WHERE case_number LIKE ?", (f"HB-{year}-%",)
    )
    return f"HB-{year}-{(row['n'] if row else 0) + 1:04d}"


def create_case(db: Database, title: str, description: str, created_by: str) -> dict:
    number = _next_case_number(db)
    cur = db.execute(
        """INSERT INTO cases (case_number, title, description, status, created_at, created_by)
           VALUES (?, ?, ?, 'open', ?, ?)""",
        (number, title, description, _now(), created_by),
    )
    audit(db, created_by, "case_created", f"{number}: {title}")
    return get_case(db, cur.lastrowid)


def get_case(db: Database, case_id: int) -> dict | None:
    row = db.query_one("SELECT * FROM cases WHERE id = ?", (case_id,))
    if row is None:
        return None
    case = dict(row)
    case["incidents"] = [
        dict(r) for r in db.query("SELECT * FROM incidents WHERE case_id = ? ORDER BY id", (case_id,))
    ]
    case["notes"] = [
        dict(r)
        for r in db.query(
            "SELECT * FROM case_notes WHERE case_id = ? ORDER BY created_at", (case_id,)
        )
    ]
    return case


def list_cases(db: Database, status: str | None = None) -> list[dict]:
    if status:
        rows = db.query("SELECT * FROM cases WHERE status = ? ORDER BY id DESC", (status,))
    else:
        rows = db.query("SELECT * FROM cases ORDER BY id DESC")
    return [dict(r) for r in rows]


def set_case_status(db: Database, case_id: int, status: str, actor: str) -> bool:
    if status not in ("open", "active", "closed"):
        raise ValueError(f"invalid case status: {status}")
    closed_at = _now() if status == "closed" else None
    cur = db.execute(
        "UPDATE cases SET status = ?, closed_at = ? WHERE id = ?",
        (status, closed_at, case_id),
    )
    if cur.rowcount:
        audit(db, actor, "case_status", f"case {case_id} -> {status}")
    return bool(cur.rowcount)


def add_note(db: Database, case_id: int, author: str, body: str) -> int:
    cur = db.execute(
        "INSERT INTO case_notes (case_id, author, created_at, body) VALUES (?, ?, ?, ?)",
        (case_id, author, _now(), body),
    )
    audit(db, author, "case_note_added", f"case {case_id}")
    return cur.lastrowid


def assign_incident(db: Database, incident_id: int, case_id: int, actor: str) -> bool:
    cur = db.execute("UPDATE incidents SET case_id = ? WHERE id = ?", (case_id, incident_id))
    if cur.rowcount:
        audit(db, actor, "incident_assigned", f"incident {incident_id} -> case {case_id}")
    return bool(cur.rowcount)


def set_incident_status(db: Database, incident_id: int, status: str, actor: str) -> bool:
    if status not in ("open", "triaged", "closed"):
        raise ValueError(f"invalid incident status: {status}")
    cur = db.execute(
        "UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?",
        (status, _now(), incident_id),
    )
    if cur.rowcount:
        audit(db, actor, "incident_status", f"incident {incident_id} -> {status}")
    return bool(cur.rowcount)


# -- tags ----------------------------------------------------------------


def tag_event(db: Database, event_id: int, tag: str, actor: str) -> None:
    tag = tag.strip().lower()
    if not tag:
        raise ValueError("empty tag")
    with db.transaction() as conn:
        conn.execute("INSERT OR IGNORE INTO tags (name) VALUES (?)", (tag,))
        tag_id = conn.execute("SELECT id FROM tags WHERE name = ?", (tag,)).fetchone()["id"]
        conn.execute(
            "INSERT OR IGNORE INTO event_tags (event_id, tag_id) VALUES (?, ?)",
            (event_id, tag_id),
        )
    audit(db, actor, "event_tagged", f"event {event_id} tag={tag}")


def event_tags(db: Database, event_id: int) -> list[str]:
    rows = db.query(
        """SELECT t.name FROM tags t JOIN event_tags et ON et.tag_id = t.id
           WHERE et.event_id = ? ORDER BY t.name""",
        (event_id,),
    )
    return [r["name"] for r in rows]
