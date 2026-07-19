"""Evidence search: filter events by device, type, time, incident, tag, or
free text over the payload (filenames, hashes, hosts, ...)."""

from __future__ import annotations

from .db import Database
from .store import EVENT_SELECT, event_to_dict


def search_events(
    db: Database,
    text: str | None = None,
    device: str | None = None,
    event_type: str | None = None,
    incident_id: int | None = None,
    tag: str | None = None,
    since: str | None = None,
    until: str | None = None,
    min_severity: int | None = None,
    limit: int = 200,
) -> list[dict]:
    clauses: list[str] = []
    params: list = []

    if text:
        clauses.append("e.payload LIKE ?")
        params.append(f"%{text}%")
    if device:
        clauses.append("d.name = ?")
        params.append(device)
    if event_type:
        clauses.append("e.event_type = ?")
        params.append(event_type)
    if incident_id is not None:
        clauses.append("e.incident_id = ?")
        params.append(incident_id)
    if tag:
        clauses.append(
            "e.id IN (SELECT et.event_id FROM event_tags et "
            "JOIN tags t ON t.id = et.tag_id WHERE t.name = ?)"
        )
        params.append(tag.strip().lower())
    if since:
        clauses.append("e.occurred_at >= ?")
        params.append(since)
    if until:
        clauses.append("e.occurred_at <= ?")
        params.append(until)
    if min_severity is not None:
        clauses.append("e.severity >= ?")
        params.append(min_severity)

    sql = EVENT_SELECT
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY e.occurred_at DESC, e.id DESC LIMIT ?"
    params.append(max(1, min(int(limit), 1000)))

    return [event_to_dict(r) for r in db.query(sql, tuple(params))]


def stats(db: Database) -> dict:
    def one(sql: str, params: tuple = ()):
        row = db.query_one(sql, params)
        return row[0] if row else 0

    by_type = {
        r["event_type"]: r["n"]
        for r in db.query(
            "SELECT event_type, COUNT(*) AS n FROM events GROUP BY event_type ORDER BY n DESC"
        )
    }
    return {
        "events": one("SELECT COUNT(*) FROM events"),
        "devices": one("SELECT COUNT(*) FROM devices"),
        "incidents_open": one("SELECT COUNT(*) FROM incidents WHERE status = 'open'"),
        "incidents_total": one("SELECT COUNT(*) FROM incidents"),
        "cases_open": one("SELECT COUNT(*) FROM cases WHERE status != 'closed'"),
        "cases_total": one("SELECT COUNT(*) FROM cases"),
        "events_by_type": by_type,
    }
