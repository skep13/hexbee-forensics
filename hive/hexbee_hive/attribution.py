"""Was that us?

Every red team engagement eventually has the same argument. An alert fires, a
host falls over, someone finds lateral movement — and nobody can say cleanly
whether it was the testers or a real intruder. The answer usually arrives days
later, assembled by hand from operator notes, a SIEM, and memory.

The reason it is hard is structural, not technical: offensive tooling writes to
one log and defensive telemetry to another. Two systems, two clocks, no shared
integrity guarantee, and each side's record is exactly the record the other
side has reason to doubt.

HexBee is unusual in that both already land in the same hash-chained log — the
scope-gated tools the operator runs, and the telemetry from Forager, Netmon and
the sensors. This module reads that one log and answers the question directly:
for any observed event, was there an authorised action of ours, against the
same target, close enough in time to explain it — and under whose
authorisation.

Three deliberate limits, because a confident wrong answer here is worse than
no answer:

  * It reports *correlation*, never proof of causation. Same target inside a
    time window is grounds for "attributable", not "caused by".
  * "Not ours" is only ever said when we hold a complete record of our own
    activity for that window. Silence is reported as inconclusive.
  * The verdict is only as good as the chain. If verification fails, the
    answer is withheld rather than qualified — a disputed timeline is not
    evidence.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from .db import Database

# Event types that only our own tooling produces. Anything else in the log is
# an observation of the environment rather than an action we took.
ENGAGEMENT_TYPES = {
    "recon_finding",         # scope-gated nmap
    "hid_deployment",        # Stinger BLE keystroke injection
    "credential_capture",    # rogue portal / Responder import
    "portal_started",
    "pivot_cmd",             # drop-box reverse SSH
    "pivot_session",
    "scope_violation",       # an attempt we refused — still our activity
}

# Payload keys that identify what an event concerns, in preference order.
TARGET_KEYS = ("target", "host", "ip", "address", "domain", "hostname",
               "dest_ip", "destination", "bssid", "ssid")

DEFAULT_WINDOW_SECONDS = 300


def classify(event_type: str) -> str:
    """'engagement' for our own actions, 'observed' for everything else."""
    return "engagement" if event_type in ENGAGEMENT_TYPES else "observed"


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def identifiers(payload: dict | str | None) -> set[str]:
    """Everything in a payload that could name a target.

    Compared case-insensitively, because an nmap target of `10.0.0.5` and a
    Netmon alert naming `10.0.0.5` are the same host, while `HOST-A` and
    `host-a` are the same machine written by two different tools.
    """
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (TypeError, ValueError):
            return set()
    if not isinstance(payload, dict):
        return set()
    found: set[str] = set()
    for key in TARGET_KEYS:
        value = payload.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            found.add(str(value).strip().lower())
    return found


def _rows(db: Database, sql: str, params: tuple = ()) -> list[dict]:
    return [dict(r) for r in db.query(sql, params)]


def _event(db: Database, event_id: int) -> dict | None:
    rows = _rows(db, """
        SELECT e.id, e.occurred_at, e.event_type, e.payload, e.severity,
               d.name AS device
          FROM events e JOIN devices d ON d.id = e.device_id
         WHERE e.id = ?""", (event_id,))
    return rows[0] if rows else None


def engagement_activity(db: Database, since: str | None = None,
                        until: str | None = None) -> list[dict]:
    """Our own authorised actions, optionally bounded to a window."""
    clauses = ["e.event_type IN (%s)" %
               ",".join("?" * len(ENGAGEMENT_TYPES))]
    params: list = sorted(ENGAGEMENT_TYPES)
    if since:
        clauses.append("e.occurred_at >= ?")
        params.append(since)
    if until:
        clauses.append("e.occurred_at <= ?")
        params.append(until)
    rows = _rows(db, f"""
        SELECT e.id, e.occurred_at, e.event_type, e.payload, d.name AS device
          FROM events e JOIN devices d ON d.id = e.device_id
         WHERE {' AND '.join(clauses)}
         ORDER BY e.occurred_at""", tuple(params))
    for row in rows:
        row["targets"] = sorted(identifiers(row.pop("payload")))
    return rows


def _authorisation_for(db: Database, targets: set[str]) -> list[dict]:
    """Scope rules whose value names one of these targets.

    A substring match is right here: a rule covering `10.0.0.0/24` should
    answer for `10.0.0.5`, and an exact comparison would miss it.
    """
    if not targets:
        return []
    rules = _rows(db, """SELECT kind, value, auth_ref, note, added_by
                           FROM engagement_scope WHERE active = 1""")
    hits = []
    for rule in rules:
        value = str(rule["value"]).lower()
        network = value.split("/")[0].rsplit(".", 1)[0]      # 10.0.0.0/24 -> 10.0.0
        if any(t == value or t.startswith(network) for t in targets):
            hits.append(rule)
    return hits


def attribute(db: Database, event_id: int,
              window_seconds: int = DEFAULT_WINDOW_SECONDS) -> dict | None:
    """Was this observed event caused by something we did?

    Returns the candidate actions, the authorisation covering them, and a
    verdict that is deliberately conservative.
    """
    event = _event(db, event_id)
    if event is None:
        return None

    kind = classify(event["event_type"])
    targets = identifiers(event["payload"])
    at = _parse_time(event["occurred_at"])

    if kind == "engagement":
        return {
            "event_id": event_id,
            "event_type": event["event_type"],
            "occurred_at": event["occurred_at"],
            "classification": "engagement",
            "verdict": "ours",
            "confidence": "certain",
            "explanation": (
                "This event is our own tooling reporting an action it took. "
                "It is not an observation of the environment."),
            "targets": sorted(targets),
            "candidates": [],
            "authorisation": _authorisation_for(db, targets),
        }

    candidates: list[dict] = []
    if at is not None:
        low = (at - timedelta(seconds=window_seconds)).isoformat().replace("+00:00", "Z")
        high = (at + timedelta(seconds=window_seconds)).isoformat().replace("+00:00", "Z")
        for action in engagement_activity(db, since=low, until=high):
            shared = targets & set(action["targets"])
            action_time = _parse_time(action["occurred_at"])
            action["shared_targets"] = sorted(shared)
            action["seconds_apart"] = (
                abs(int((action_time - at).total_seconds())) if action_time else None)
            action["matches_target"] = bool(shared)
            candidates.append(action)

    on_target = [c for c in candidates if c["matches_target"]]
    have_record = bool(engagement_activity(db))

    if on_target:
        verdict, confidence = "attributable", "likely"
        explanation = (
            f"{len(on_target)} authorised action(s) of ours hit the same target "
            f"within {window_seconds}s of this event. That is correlation, not "
            f"proof of causation — but it is the record you would show when asked.")
    elif candidates:
        verdict, confidence = "inconclusive", "low"
        explanation = (
            f"We were active in this window but against different targets. "
            f"Nothing here explains this event; nothing rules us out either.")
    elif have_record:
        verdict, confidence = "not_ours", "good"
        explanation = (
            "We hold a complete record of our own activity and it contains "
            f"nothing within {window_seconds}s of this event. On this record, "
            "this was not us.")
    else:
        verdict, confidence = "inconclusive", "none"
        explanation = (
            "No engagement activity has ever been recorded, so this log cannot "
            "distinguish 'we did nothing' from 'nothing was logged'.")

    return {
        "event_id": event_id,
        "event_type": event["event_type"],
        "occurred_at": event["occurred_at"],
        "device": event["device"],
        "classification": "observed",
        "verdict": verdict,
        "confidence": confidence,
        "explanation": explanation,
        "targets": sorted(targets),
        "window_seconds": window_seconds,
        "candidates": sorted(candidates,
                             key=lambda c: (not c["matches_target"],
                                            c["seconds_apart"] or 0)),
        "authorisation": _authorisation_for(db, targets),
    }


def summary(db: Database) -> dict:
    """Counts for the header: how much of this log is us, and how much is
    the environment."""
    rows = _rows(db, "SELECT event_type, COUNT(*) AS n FROM events GROUP BY event_type")
    ours = sum(r["n"] for r in rows if classify(r["event_type"]) == "engagement")
    observed = sum(r["n"] for r in rows if classify(r["event_type"]) == "observed")
    scope_rules = db.query(
        "SELECT COUNT(*) AS n FROM engagement_scope WHERE active = 1")[0]["n"]
    return {
        "engagement_events": ours,
        "observed_events": observed,
        "total": ours + observed,
        "active_scope_rules": scope_rules,
        # Without scope rules there is no authorisation to point at, which is
        # the difference between "we did this, here is the sign-off" and
        # "we did this".
        "attributable": scope_rules > 0 and ours > 0,
    }
