"""Incident correlation engine.

Groups related events into incidents instead of leaving analysts a flat log.
The model is intentionally simple enough to run per-event on a Pi 3B+:

1. Every event with severity >= TRIGGER_SEVERITY either joins the device's
   currently-open incident (if the last activity on it is within the
   correlation window) or opens a new one.
2. When an incident is opened, recent lower-severity context events from the
   same device inside the window are pulled in retroactively, so the
   "usb_inserted" that preceded an "executable_found" lands in the incident.
3. Later low-severity events from the same device also join while the
   incident stays warm.

Incident severity is the max severity of its member events; the title is
derived from the highest-severity event type seen.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .db import Database

TRIGGER_SEVERITY = 2

TITLES = {
    "executable_found": "Executable discovered on attached storage",
    "script_found": "Script discovered on attached storage",
    "autorun_found": "Autorun persistence artifact discovered",
    "powershell_launched": "PowerShell activity observed",
    "network_beacon": "Suspicious network beacon observed",
}


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class Correlator:
    def __init__(self, db: Database, window_seconds: int = 600):
        self.db = db
        self.window = timedelta(seconds=window_seconds)

    def process_event(self, event_id: int) -> int | None:
        """Correlate one freshly-stored event. Returns incident id if the
        event ended up in an incident, else None."""
        ev = self.db.query_one(
            """SELECT e.id, e.occurred_at, e.event_type, e.severity, e.device_id
               FROM events e WHERE e.id = ?""",
            (event_id,),
        )
        if ev is None:
            return None

        open_incident = self._warm_incident_for_device(ev["device_id"], ev["occurred_at"])

        if open_incident is not None:
            self._attach(ev, open_incident)
            return open_incident
        if ev["severity"] >= TRIGGER_SEVERITY:
            return self._open_incident(ev)
        return None

    # -- internals --------------------------------------------------------

    def _warm_incident_for_device(self, device_id: int, at_iso: str) -> int | None:
        """An open incident for this device whose latest event is within the
        correlation window of `at_iso`."""
        row = self.db.query_one(
            """SELECT i.id, MAX(e.occurred_at) AS last_at
               FROM incidents i JOIN events e ON e.incident_id = i.id
               WHERE i.status = 'open' AND e.device_id = ?
               GROUP BY i.id ORDER BY last_at DESC LIMIT 1""",
            (device_id,),
        )
        if row is None or row["id"] is None:
            return None
        if abs(_parse(at_iso) - _parse(row["last_at"])) <= self.window:
            return row["id"]
        return None

    def _attach(self, ev, incident_id: int) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE events SET incident_id = ? WHERE id = ?", (incident_id, ev["id"])
            )
            conn.execute(
                """UPDATE incidents
                   SET updated_at = ?, severity = MAX(severity, ?)
                   WHERE id = ?""",
                (_fmt(datetime.now(timezone.utc)), ev["severity"], incident_id),
            )

    def _open_incident(self, ev) -> int:
        now = _fmt(datetime.now(timezone.utc))
        title = TITLES.get(ev["event_type"], f"Suspicious activity: {ev['event_type']}")
        window_start = _fmt(_parse(ev["occurred_at"]) - self.window)
        with self.db.transaction() as conn:
            cur = conn.execute(
                """INSERT INTO incidents (opened_at, updated_at, title, severity)
                   VALUES (?, ?, ?, ?)""",
                (now, now, title, ev["severity"]),
            )
            incident_id = cur.lastrowid
            # The trigger event plus recent same-device context events.
            conn.execute(
                """UPDATE events SET incident_id = ?
                   WHERE id = ?
                      OR (device_id = ? AND incident_id IS NULL
                          AND occurred_at >= ? AND occurred_at <= ?)""",
                (incident_id, ev["id"], ev["device_id"], window_start, ev["occurred_at"]),
            )
        return incident_id


def backfill(db: Database, window_seconds: int = 600) -> int:
    """Re-run correlation over all uncorrelated events (oldest first).
    Returns the number of incidents that now exist."""
    correlator = Correlator(db, window_seconds)
    for row in db.query(
        "SELECT id FROM events WHERE incident_id IS NULL ORDER BY occurred_at, id"
    ):
        correlator.process_event(row["id"])
    n = db.query_one("SELECT COUNT(*) AS n FROM incidents")
    return n["n"] if n else 0
