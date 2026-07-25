"""Engagement scope enforcement.

Every active (traffic-generating) HexBee tool asks this module whether a
target is inside the authorised engagement before it fires. Passive forensic
collection is unaffected — only tooling that touches somebody else's network
is gated.

The design goal is legal defensibility, so the default is **fail-closed**:

  * No scope rules at all               -> everything is denied.
  * Scope rules exist, target matches   -> allowed, and the matching rule
                                           (including its authorisation
                                           reference) is returned for the
                                           report.
  * Scope rules exist, no match         -> denied, and a `scope_violation`
                                           event is written into the evidence
                                           chain with the caller's context.

`HEXBEE_SCOPE_MODE=permissive` relaxes only the first case (an empty scope
table allows everything) — useful on a home lab, wrong on a client site.

There is deliberately no RAM cost here: three small SQLite reads and stdlib
`ipaddress` arithmetic per check.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from .db import Database
from .store import audit

KINDS = ("cidr", "host", "domain")

_HOST_RE = re.compile(r"^[A-Za-z0-9_.:\-\[\]]{1,255}$")
_DOMAIN_RE = re.compile(r"^\*?\.?[A-Za-z0-9][A-Za-z0-9.\-]{0,253}$")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Decision:
    """Result of a scope check. Falsy when the target is out of scope."""

    allowed: bool
    reason: str
    rule: dict | None = None
    auth_ref: str = ""

    def __bool__(self) -> bool:
        return self.allowed


# -- rule management ------------------------------------------------------

def add_rule(db: Database, kind: str, value: str, actor: str, *,
             auth_ref: str = "", starts_at: str | None = None,
             ends_at: str | None = None, case_id: int | None = None,
             note: str = "") -> int:
    """Add one scope rule. Raises ValueError on a malformed value."""
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    value = (value or "").strip().lower()
    if not value:
        raise ValueError("empty scope value")
    if kind == "cidr":
        # strict=False so 10.0.0.5/24 is accepted and normalised to 10.0.0.0/24.
        try:
            value = str(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ValueError(f"not a valid CIDR range: {exc}") from exc
    elif kind == "host":
        if not _HOST_RE.match(value):
            raise ValueError("not a valid host or IP address")
    elif kind == "domain":
        if not _DOMAIN_RE.match(value):
            raise ValueError("not a valid domain pattern")
        value = value.lstrip("*").lstrip(".")
    for label, stamp in (("starts_at", starts_at), ("ends_at", ends_at)):
        if stamp:
            try:
                datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ")
            except ValueError as exc:
                raise ValueError(f"{label} must be UTC ISO-8601 "
                                 f"(YYYY-MM-DDTHH:MM:SSZ)") from exc
    cur = db.execute(
        """INSERT INTO engagement_scope
           (kind, value, auth_ref, starts_at, ends_at, case_id, note,
            added_by, added_at, active)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
        (kind, value, auth_ref, starts_at, ends_at, case_id, note, actor, _now()),
    )
    audit(db, actor, "scope_added",
          f"{kind}:{value} auth={auth_ref or '(none)'} "
          f"window={starts_at or '-'}..{ends_at or '-'}")
    return cur.lastrowid


def remove_rule(db: Database, rule_id: int, actor: str) -> bool:
    row = db.query_one("SELECT kind, value FROM engagement_scope WHERE id = ?", (rule_id,))
    if row is None:
        return False
    db.execute("DELETE FROM engagement_scope WHERE id = ?", (rule_id,))
    audit(db, actor, "scope_removed", f"{row['kind']}:{row['value']}")
    return True


def set_active(db: Database, rule_id: int, active: bool, actor: str) -> bool:
    row = db.query_one("SELECT kind, value FROM engagement_scope WHERE id = ?", (rule_id,))
    if row is None:
        return False
    db.execute("UPDATE engagement_scope SET active = ? WHERE id = ?",
               (1 if active else 0, rule_id))
    audit(db, actor, "scope_updated",
          f"{row['kind']}:{row['value']} -> {'active' if active else 'inactive'}")
    return True


def list_rules(db: Database, case_id: int | None = None) -> list[dict]:
    if case_id is None:
        rows = db.query("SELECT * FROM engagement_scope ORDER BY id DESC")
    else:
        rows = db.query(
            "SELECT * FROM engagement_scope WHERE case_id IS NULL OR case_id = ? "
            "ORDER BY id DESC", (case_id,))
    return [dict(r) for r in rows]


# -- the check itself -----------------------------------------------------

def _in_window(rule, now_iso: str) -> bool:
    if rule["starts_at"] and now_iso < rule["starts_at"]:
        return False
    if rule["ends_at"] and now_iso > rule["ends_at"]:
        return False
    return True


def _matches(rule, target: str) -> bool:
    kind, value = rule["kind"], rule["value"]
    if kind == "host":
        return target == value
    if kind == "domain":
        return target == value or target.endswith("." + value)
    if kind == "cidr":
        try:
            return ipaddress.ip_address(target) in ipaddress.ip_network(value)
        except ValueError:
            return False  # target is a hostname; a CIDR rule cannot authorise it
    return False


def check(db: Database, target: str, *, case_id: int | None = None,
          mode: str = "enforce", now_iso: str | None = None) -> Decision:
    """Is `target` (an IP, hostname, or domain) inside the authorised scope?

    Resolution is deliberately *not* performed: a hostname is matched against
    host/domain rules only. Letting DNS decide what is in scope would hand an
    attacker-controlled record the power to expand the engagement.
    """
    target = (target or "").strip().lower().rstrip(".")
    if not target:
        return Decision(False, "empty target")
    now_iso = now_iso or _now()

    rules = [r for r in list_rules(db, case_id) if r["active"]]
    if not rules:
        if mode == "permissive":
            return Decision(True, "no scope defined (permissive mode)")
        return Decision(
            False,
            "no engagement scope is defined — add an authorised CIDR/host/"
            "domain before running active tooling",
        )

    expired = False
    for rule in rules:
        if not _matches(rule, target):
            continue
        if not _in_window(rule, now_iso):
            expired = True
            continue
        return Decision(True, f"authorised by scope rule #{rule['id']} "
                              f"({rule['kind']}:{rule['value']})",
                        rule=rule, auth_ref=rule["auth_ref"])
    if expired:
        return Decision(False, f"{target} matches a scope rule, but the "
                               f"authorised time window is not open")
    return Decision(False, f"{target} is not inside the authorised engagement scope")


def record_violation(db: Database, correlator, target: str, tool: str,
                     actor: str, decision: Decision, extra: dict | None = None) -> int | None:
    """Write a refused action into the evidence chain.

    Blocked attempts are themselves evidence: they prove the operator stayed
    inside the authorisation, which is exactly what a client or a court wants
    to see. Returns the stored event id (None if the event was rejected).
    """
    from .ingest import process_raw_event
    from .normalize import NormalizationError

    payload = {
        "target": target,
        "tool": tool,
        "operator": actor,
        "reason": decision.reason,
        "blocked": True,
    }
    if extra:
        payload.update(extra)
    try:
        result = process_raw_event(
            db, correlator,
            {"device": "Scope-Enforcer", "event_type": "scope_violation",
             "payload": payload},
            source=f"scope:{actor}",
        )
    except NormalizationError:
        return None
    audit(db, actor, "scope_violation", f"{tool} -> {target}: {decision.reason}")
    return result["event_id"]


def scope_summary(db: Database) -> dict:
    """Compact posture used by the Admin page and the security report."""
    rules = list_rules(db)
    active = [r for r in rules if r["active"]]
    now_iso = _now()
    live = [r for r in active if _in_window(r, now_iso)]
    return {
        "total": len(rules),
        "active": len(active),
        "in_window": len(live),
        "auth_refs": sorted({r["auth_ref"] for r in live if r["auth_ref"]}),
        "rules": rules,
    }
