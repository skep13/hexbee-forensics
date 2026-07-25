"""Queen-side scope gate.

Every active tool imports this and calls `guard()` before it fires:

    from hexbee_queen.scope import guard
    decision = guard(client, target, tool="hexbee-recon", case_id=case)
    if not decision:
        return 2

The authority lives in the Hive, not here, so one scope definition covers
every operator and every tool, and the refusal is recorded in the evidence
chain rather than only on somebody's terminal.

The gate **fails closed**. If the Hive is unreachable, the answer is no. An
unreachable authorisation server is not permission; it is the absence of it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .client import HiveError

# Escape hatch for lab work. Deliberately awkward to set by accident, and
# every allowed action still says out loud that the gate was bypassed.
OVERRIDE_ENV = "HEXBEE_SCOPE_OVERRIDE"
OVERRIDE_VALUE = "i-accept-responsibility"


@dataclass
class Decision:
    allowed: bool
    reason: str
    auth_ref: str = ""
    rule: dict | None = None
    recorded_event: int | None = None

    def __bool__(self) -> bool:
        return self.allowed


def check(client, target: str, case_id: int | None = None) -> Decision:
    """Ask the Hive whether `target` is in scope. Never records anything."""
    try:
        result = client.scope_check(target, case_id)
    except HiveError as exc:
        return Decision(False, f"scope check failed ({exc}) — refusing to act")
    except Exception as exc:
        return Decision(False, f"Hive unreachable ({exc}) — refusing to act")
    return Decision(bool(result.get("allowed")), result.get("reason", ""),
                    result.get("auth_ref", ""), result.get("rule"))


def guard(client, target: str, *, tool: str, case_id: int | None = None,
          extra: dict | None = None, quiet: bool = False) -> Decision:
    """Check scope and, on refusal, record a `scope_violation` in the Hive.

    Returns a falsy Decision when the caller must not proceed.
    """
    import sys

    if os.environ.get(OVERRIDE_ENV) == OVERRIDE_VALUE:
        if not quiet:
            print(f"[scope] OVERRIDDEN for {target} — {OVERRIDE_ENV} is set. "
                  f"You are responsible for this being authorised.",
                  file=sys.stderr)
        return Decision(True, "scope gate overridden by operator")

    decision = check(client, target, case_id)
    if decision:
        if not quiet:
            ref = f" [auth: {decision.auth_ref}]" if decision.auth_ref else ""
            print(f"[scope] {target} authorised — {decision.reason}{ref}",
                  file=sys.stderr)
        return decision

    try:
        result = client.scope_violation(target, tool, decision.reason, extra or {})
        decision.recorded_event = result.get("event_id")
    except Exception:
        pass  # the refusal stands even if we could not log it
    if not quiet:
        print(f"[scope] REFUSED {target} — {decision.reason}", file=sys.stderr)
        print(f"[scope] Authorise it first:\n"
              f"    hexbee-queen scope add cidr {target}/32 "
              f"--auth-ref <client reference>", file=sys.stderr)
    return decision


def guard_all(client, targets: list[str], *, tool: str,
              case_id: int | None = None) -> tuple[list[str], list[Decision]]:
    """Partition targets into allowed and refused. Refusals are recorded."""
    allowed, refused = [], []
    for target in targets:
        decision = guard(client, target, tool=tool, case_id=case_id)
        (allowed if decision else refused).append(
            target if decision else decision)
    return allowed, refused
