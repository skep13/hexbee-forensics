"""The Explorer — a three-pane evidence browser, in the Autopsy idiom.

Autopsy's layout works because it separates three questions an examiner asks
in order: *what have I got* (a tree of sources and views), *what is in it* (a
result list), *what is this one thing* (a detail pane). Nothing here is new;
it is that arrangement over a hash-chained event log rather than a filesystem.

Two design points worth stating:

**The tree is derived, never stored.** Every node is a saved query over the
events table — a device, an event type, a technique, an IOC hit. Ingest a new
artifact type and the tree grows a branch on its own, with no migration and
nothing to keep in sync.

**Counts come from one grouped query per branch, not per node.** The naive
shape — count each node separately — is a query per device per refresh, which
on a Pi 3B+ with a few hundred thousand events is exactly the sort of thing
that makes a UI feel broken.
"""

from __future__ import annotations

import json

from .db import Database

SEVERITY_LABELS = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}

# The detail pane shows every field, but these read first because they are
# what an examiner scans for when triaging a list.
HEADLINE_KEYS = ("path", "filename", "name", "sha256", "md5", "ip", "domain",
                 "host", "user", "process", "command", "rule", "technique")


def _rows(db: Database, sql: str, params: tuple = ()) -> list[dict]:
    return [dict(r) for r in db.query(sql, params)]


def build_tree(db: Database) -> list[dict]:
    """The navigator: saved queries grouped the way an examiner works."""
    tree: list[dict] = []

    cases = _rows(db, """
        SELECT c.id, c.case_number, c.title, c.status,
               (SELECT COUNT(*) FROM events e
                  JOIN incidents i ON i.id = e.incident_id
                 WHERE i.case_id = c.id) AS n
          FROM cases c ORDER BY c.created_at DESC""")
    tree.append({
        "id": "cases", "label": "Cases", "icon": "case",
        "count": sum(c["n"] for c in cases),
        "children": [{
            "id": f"case:{c['id']}",
            "label": f"{c['case_number']} — {c['title']}",
            "count": c["n"], "badge": c["status"],
            "filter": {"case_id": c["id"]},
        } for c in cases],
    })

    devices = _rows(db, """
        SELECT d.name, d.kind, COUNT(e.id) AS n
          FROM devices d LEFT JOIN events e ON e.device_id = d.id
         GROUP BY d.id ORDER BY n DESC, d.name""")
    tree.append({
        "id": "sources", "label": "Data sources", "icon": "device",
        "count": sum(d["n"] for d in devices),
        "children": [{
            "id": f"device:{d['name']}", "label": d["name"],
            "count": d["n"], "badge": d["kind"] or None,
            "filter": {"device": d["name"]},
        } for d in devices],
    })

    types = _rows(db, """
        SELECT event_type, COUNT(*) AS n FROM events
         GROUP BY event_type ORDER BY n DESC, event_type""")
    tree.append({
        "id": "types", "label": "Artifact types", "icon": "type",
        "count": sum(t["n"] for t in types),
        "children": [{
            "id": f"type:{t['event_type']}", "label": t["event_type"],
            "count": t["n"], "filter": {"event_type": t["event_type"]},
        } for t in types],
    })

    severities = _rows(db, """
        SELECT severity, COUNT(*) AS n FROM events
         GROUP BY severity ORDER BY severity DESC""")
    techniques = _rows(db, """
        SELECT t.technique_id, t.tactic, COUNT(*) AS n
          FROM event_techniques t GROUP BY t.technique_id
         ORDER BY n DESC, t.technique_id""")
    ioc_hits = _rows(db, """
        SELECT i.value, i.kind, COUNT(*) AS n
          FROM ioc_hits h JOIN iocs i ON i.id = h.ioc_id
         GROUP BY i.id ORDER BY n DESC""")
    incidents = _rows(db, """
        SELECT i.id, i.title, i.severity, i.status,
               (SELECT COUNT(*) FROM events e WHERE e.incident_id = i.id) AS n
          FROM incidents i ORDER BY i.opened_at DESC""")

    results: list[dict] = [{
        "id": "severity", "label": "By severity",
        "count": sum(s["n"] for s in severities),
        "children": [{
            "id": f"sev:{s['severity']}",
            "label": SEVERITY_LABELS.get(s["severity"], str(s["severity"])),
            "count": s["n"], "sev": s["severity"],
            "filter": {"severity": s["severity"]},
        } for s in severities],
    }]
    if techniques:
        results.append({
            "id": "techniques", "label": "ATT&CK techniques",
            "count": sum(t["n"] for t in techniques),
            "children": [{
                "id": f"tech:{t['technique_id']}",
                "label": t["technique_id"], "badge": t["tactic"],
                "count": t["n"], "filter": {"technique": t["technique_id"]},
            } for t in techniques],
        })
    if ioc_hits:
        results.append({
            "id": "iocs", "label": "IOC hits",
            "count": sum(h["n"] for h in ioc_hits),
            "children": [{
                "id": f"ioc:{h['value']}", "label": h["value"],
                "badge": h["kind"], "count": h["n"],
                "filter": {"ioc": h["value"]},
            } for h in ioc_hits],
        })
    if incidents:
        results.append({
            "id": "incidents", "label": "Incidents",
            "count": sum(i["n"] for i in incidents),
            "children": [{
                "id": f"inc:{i['id']}", "label": f"#{i['id']} {i['title']}",
                "badge": i["status"], "count": i["n"], "sev": i["severity"],
                "filter": {"incident_id": i["id"]},
            } for i in incidents],
        })
    tree.append({"id": "results", "label": "Results", "icon": "result",
                 "count": None, "children": results})
    return tree


def query_events(db: Database, filters: dict, limit: int = 500,
                 offset: int = 0) -> dict:
    """Run one tree node's saved query.

    Kept separate from `search.search_events` because the Explorer filters on
    things the analyst search box has no concept of — a technique, an IOC hit,
    a case reached through its incidents — and folding those in would make one
    function serve two very different callers badly.
    """
    where: list[str] = []
    params: list = []

    if filters.get("device"):
        where.append("d.name = ?")
        params.append(filters["device"])
    if filters.get("event_type"):
        where.append("e.event_type = ?")
        params.append(filters["event_type"])
    if filters.get("incident_id") is not None:
        where.append("e.incident_id = ?")
        params.append(int(filters["incident_id"]))
    if filters.get("severity") is not None:
        where.append("e.severity = ?")
        params.append(int(filters["severity"]))
    if filters.get("case_id") is not None:
        where.append("e.incident_id IN (SELECT id FROM incidents WHERE case_id = ?)")
        params.append(int(filters["case_id"]))
    if filters.get("technique"):
        where.append("e.id IN (SELECT event_id FROM event_techniques "
                     "WHERE technique_id = ?)")
        params.append(filters["technique"])
    if filters.get("ioc"):
        where.append("e.id IN (SELECT h.event_id FROM ioc_hits h "
                     "JOIN iocs i ON i.id = h.ioc_id WHERE i.value = ?)")
        params.append(filters["ioc"])
    if filters.get("text"):
        where.append("(e.payload LIKE ? OR e.event_type LIKE ?)")
        params.extend([f"%{filters['text']}%"] * 2)

    clause = f"WHERE {' AND '.join(where)}" if where else ""
    total = db.query(
        f"SELECT COUNT(*) AS n FROM events e "
        f"JOIN devices d ON d.id = e.device_id {clause}", tuple(params))[0]["n"]

    rows = _rows(db, f"""
        SELECT e.id, e.occurred_at, e.received_at, e.event_type, e.severity,
               e.payload, e.event_hash, e.incident_id, d.name AS device
          FROM events e JOIN devices d ON d.id = e.device_id
          {clause}
         ORDER BY e.occurred_at DESC, e.id DESC
         LIMIT ? OFFSET ?""", tuple(params) + (limit, offset))

    for r in rows:
        r["summary"] = _summarise(r.pop("payload"))
    return {"total": total, "events": rows, "limit": limit, "offset": offset}


def _summarise(payload_json: str) -> str:
    """One line an examiner can scan a hundred of without opening any."""
    try:
        payload = json.loads(payload_json)
    except (TypeError, ValueError):
        return str(payload_json or "")[:160]
    if not isinstance(payload, dict):
        return str(payload)[:160]
    parts = [f"{k}={payload[k]}" for k in HEADLINE_KEYS
             if payload.get(k) not in (None, "", [], {})]
    if not parts:
        parts = [f"{k}={v}" for k, v in list(payload.items())[:3]]
    return "  ".join(parts)[:200]


def event_detail(db: Database, event_id: int) -> dict | None:
    """Everything known about one artifact, including where it sits in the
    chain — an examiner asked to defend a record needs its neighbours."""
    rows = _rows(db, """
        SELECT e.*, d.name AS device, d.kind AS device_kind
          FROM events e JOIN devices d ON d.id = e.device_id
         WHERE e.id = ?""", (event_id,))
    if not rows:
        return None
    ev = rows[0]
    try:
        ev["payload"] = json.loads(ev["payload"])
    except (TypeError, ValueError):
        pass
    ev["severity_label"] = SEVERITY_LABELS.get(ev["severity"], str(ev["severity"]))
    ev["techniques"] = _rows(
        db, "SELECT technique_id, tactic FROM event_techniques WHERE event_id = ?",
        (event_id,))
    ev["tags"] = [r["name"] for r in _rows(
        db, "SELECT t.name FROM event_tags et JOIN tags t ON t.id = et.tag_id "
            "WHERE et.event_id = ?", (event_id,))]
    ev["ioc_hits"] = _rows(
        db, "SELECT i.kind, i.value, i.note FROM ioc_hits h "
            "JOIN iocs i ON i.id = h.ioc_id WHERE h.event_id = ?", (event_id,))
    neighbours = _rows(db, """
        SELECT id, event_hash FROM events
         WHERE id IN (SELECT MAX(id) FROM events WHERE id < ?
                      UNION SELECT MIN(id) FROM events WHERE id > ?)
         ORDER BY id""", (event_id, event_id))
    ev["chain"] = {
        "prev_hash": ev.get("prev_hash"),
        "event_hash": ev.get("event_hash"),
        "previous_id": next((n["id"] for n in neighbours if n["id"] < event_id), None),
        "next_id": next((n["id"] for n in neighbours if n["id"] > event_id), None),
    }
    return ev
