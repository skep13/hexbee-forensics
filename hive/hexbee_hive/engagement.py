"""Engagement report data assembly.

The Hive owns this because the Hive owns the data. Grouping five thousand
events into finding groups is a couple of SQLite reads here; doing it on the
Queen would mean pulling every event across the API first.

Both consumers use the same structure:

  * the dashboard's report preview (`/cases/<id>/preview`), and
  * `hexbee-queen engagement report`, which adds Hive Mind narration and the
    client-facing HTML/PDF rendering.

Keeping assembly in one place is what stops the preview and the deliverable
from drifting apart.
"""

from __future__ import annotations

from collections import defaultdict

from . import attack
from .cases import MODE_LABELS, get_case
from .integrity import verify_chain
from .scope import list_rules
from .store import EVENT_SELECT, event_to_dict
from .timeline import case_timeline

SEVERITY_LABELS = {0: "Informational", 1: "Low", 2: "Medium", 3: "High"}

# Event types that carry a reportable finding. Housekeeping events
# (heartbeats, collection markers) are counted but not written up.
FINDING_TYPES = {
    "recon_finding", "credential_capture", "ad_recon_finding", "yara_match",
    "network_alert", "log_anomaly", "hid_deployment", "executable_found",
    "autorun_found", "persistence_item", "artifact_mismatch", "carved_file",
    "network_beacon", "powershell_launched", "memory_acquired",
    "scope_violation", "wireless_sighting", "script_found", "usb_inserted",
    "diagnostic_alert",
}


def case_events(db, case_id: int, limit: int = 5000) -> list[dict]:
    rows = db.query(
        EVENT_SELECT + """ WHERE e.incident_id IN
            (SELECT id FROM incidents WHERE case_id = ?)
            ORDER BY e.occurred_at, e.id LIMIT ?""",
        (case_id, limit),
    )
    return [event_to_dict(r) for r in rows]


def group_findings(events: list[dict]) -> list[dict]:
    """Group finding-bearing events by (type, discriminator).

    The discriminator is whatever key the producing tool used to say *what
    kind* of finding this is — `rule` for detections, `finding` for recon.
    That is also the key the ATT&CK tagger maps on, so groups and technique
    attributions line up.
    """
    buckets: dict[tuple, list[dict]] = defaultdict(list)
    for ev in events:
        if ev["event_type"] not in FINDING_TYPES:
            continue
        payload = ev.get("payload") or {}
        discriminator = (payload.get("rule") or payload.get("finding")
                         or payload.get("credential_format")
                         or payload.get("type") or "")
        buckets[(ev["event_type"], str(discriminator))].append(ev)

    groups = []
    for (event_type, kind), items in buckets.items():
        worst = max((e["severity"] for e in items), default=0)
        groups.append({
            "event_type": event_type,
            "kind": kind,
            "title": event_type.replace("_", " ").title() + (f" — {kind}" if kind else ""),
            "count": len(items),
            "severity": worst,
            "severity_label": SEVERITY_LABELS[worst],
            "devices": sorted({e["device"] for e in items}),
            "first_seen": min((e["occurred_at"] for e in items), default=""),
            "last_seen": max((e["occurred_at"] for e in items), default=""),
            "events": items[:50],
            "truncated": max(0, len(items) - 50),
        })
    groups.sort(key=lambda g: (-g["severity"], -g["count"]))
    return groups


def report_data(db, cfg, case_id: int, *, limit: int = 5000) -> dict | None:
    """Everything a report (or its preview) needs, in one assembly pass."""
    case = get_case(db, case_id)
    if case is None:
        return None
    events = case_events(db, case_id, limit)
    groups = group_findings(events)
    severities = [e["severity"] for e in events]

    from .evidence_export import chain_anchor
    try:
        anchor = chain_anchor(db, cfg.signing_key)
    except Exception:
        anchor = {}

    return {
        "case": case,
        "mode": case.get("mode", "ir"),
        "mode_label": MODE_LABELS.get(case.get("mode", "ir"), "Incident Response"),
        "generated_at": _now(),
        "stats": {
            "events": len(events),
            "devices": len({e["device"] for e in events}),
            "incidents": len(case.get("incidents", [])),
            "groups": len(groups),
            "high": sum(1 for s in severities if s >= 3),
            "medium": sum(1 for s in severities if s == 2),
            "low": sum(1 for s in severities if s == 1),
            "truncated": len(events) >= limit,
        },
        "groups": groups,
        "coverage": attack.case_coverage(db, case_id),
        "scope": list_rules(db, case_id),
        "timeline": case_timeline(db, case_id)[:200],
        "verify": verify_chain(db),
        "anchor": {k: anchor.get(k) for k in ("head_hash", "signature", "events",
                                              "generated_at") if k in anchor},
        "summary": _fallback_summary(case, groups, severities),
    }


def _fallback_summary(case: dict, groups: list[dict], severities: list[int]) -> str:
    """Deterministic executive summary.

    Always produced from the data alone, so a report exists whether or not a
    local model is running. Hive Mind, when available, replaces this rather
    than being required for it.
    """
    high = sum(1 for s in severities if s >= 3)
    medium = sum(1 for s in severities if s == 2)
    top = ", ".join(g["title"] for g in groups[:3]) or "no reportable findings"
    return (
        f"{case['case_number']} — {case['title']}. "
        f"{len(severities)} evidence record(s) produced {len(groups)} finding "
        f"group(s): {high} at high severity and {medium} at medium. "
        f"The most significant findings were: {top}."
    )


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
