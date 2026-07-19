"""Timeline reconstruction.

Turns raw event rows into ordered, human-readable narrative entries for an
incident or a case — the "Incident #42: Scout connected → USB storage
attached → Executable discovered" view from the project vision.
"""

from __future__ import annotations

import json

from .db import Database
from .store import EVENT_SELECT

_NARRATIVES = {
    "scout_online": lambda p, d: f"Scout {d} came online",
    "scout_offline": lambda p, d: f"Scout {d} went offline",
    "usb_inserted": lambda p, d: (
        f"USB storage attached to host via {d}"
        + (f" (volume: {p['volume_label']})" if p.get("volume_label") else "")
    ),
    "usb_removed": lambda p, d: f"USB storage detached from {d}",
    "usb_scan": lambda p, d: (
        f"{d} scanned attached storage"
        + (f": {p['file_count']} files" if p.get("file_count") is not None else "")
    ),
    "file_metadata": lambda p, d: f"File observed: {p.get('name', 'unknown')}",
    "executable_found": lambda p, d: f"Executable discovered: {p.get('name', 'unknown')}",
    "script_found": lambda p, d: f"Script discovered: {p.get('name', 'unknown')}",
    "autorun_found": lambda p, d: f"Autorun artifact discovered: {p.get('name', 'unknown')}",
    "process_launched": lambda p, d: f"Process launched: {p.get('name', 'unknown')}",
    "powershell_launched": lambda p, d: "PowerShell launched on host",
    "network_discovered": lambda p, d: (
        f"Network observed: {p.get('ssid') or p.get('network', 'unknown')}"
    ),
    "network_beacon": lambda p, d: (
        f"Network beacon to {p.get('destination', 'unknown destination')}"
    ),
    "host_info": lambda p, d: f"Host information collected by {d}",
    "evidence_uploaded": lambda p, d: f"Evidence package uploaded by {d}",
}


def narrate(event_type: str, payload: dict, device: str) -> str:
    fn = _NARRATIVES.get(event_type)
    if fn:
        try:
            return fn(payload, device)
        except Exception:
            pass
    return f"{event_type.replace('_', ' ').capitalize()} ({device})"


def _entries(rows) -> list[dict]:
    out = []
    for row in rows:
        payload = json.loads(row["payload"])
        out.append(
            {
                "event_id": row["id"],
                "at": row["occurred_at"],
                "device": row["device"],
                "event_type": row["event_type"],
                "severity": row["severity"],
                "narrative": narrate(row["event_type"], payload, row["device"]),
                "payload": payload,
            }
        )
    return out


def incident_timeline(db: Database, incident_id: int) -> list[dict]:
    rows = db.query(
        EVENT_SELECT + " WHERE e.incident_id = ? ORDER BY e.occurred_at, e.id",
        (incident_id,),
    )
    return _entries(rows)


def case_timeline(db: Database, case_id: int) -> list[dict]:
    rows = db.query(
        EVENT_SELECT
        + """ WHERE e.incident_id IN (SELECT id FROM incidents WHERE case_id = ?)
              ORDER BY e.occurred_at, e.id""",
        (case_id,),
    )
    return _entries(rows)
