"""Sealing a case.

Sealing records that an investigator declared a case complete at a stated
moment, in front of a stated witness, and pins that declaration to the state
of the evidence log at that instant by taking a signed chain anchor.

That anchor is what gives the seal force. Anyone holding it can later show
the log has not been rewritten since — including you, which is the point when
somebody asks whether the evidence could have been edited after the fact.

An earlier design put a hardware token in this path: a microcontroller
holding its own key, so a seal was attributable to a specific physical object
you could hand to a witness. That is gone with the Pico. What remains is a
software declaration plus a cryptographic anchor over the evidence — weaker
on *who* sealed it, exactly as strong on *what was sealed*.
"""

from __future__ import annotations

from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def seal_event(case_id: int, operator: str, witness: str = "",
               note: str = "", chain_head: str = "",
               device: str = "Queen-Seal") -> dict:
    return {
        "device": device,
        "event_type": "case_seal",
        "occurred_at": _now(),
        "payload": {
            "seal_kind": "case_seal",
            "case_id": case_id,
            "operator": operator,
            "witness": witness,
            "note": note[:300],
            "chain_head_at_seal": chain_head,
            # Said plainly, because the difference matters if this is ever
            # challenged: the anchor proves what the log contained, not who
            # was standing there.
            "attestation": "software declaration by the operator",
            "signature_verified": False,
        },
    }


def seal_case(client, case_id: int, *, operator: str, ingest_key: str,
              witness: str = "", note: str = "") -> dict:
    """Record the seal and anchor the chain. Returns a summary."""
    verify = client.verify()
    anchor_before = client.anchor()
    head = anchor_before.get("head_hash", "")

    event = seal_event(case_id, operator, witness, note, head)
    stored = client.ingest([event], ingest_key)

    # Anchor *after* the seal event is chained, so the receipt covers it.
    anchor = client.anchor()
    return {
        "case_id": case_id,
        "chain_ok": verify.get("ok", False),
        "records": verify.get("checked", 0),
        "events_written": stored.get("stored", 0),
        "head_hash": anchor.get("head_hash", ""),
        "signature": anchor.get("signature", ""),
        "anchor": anchor,
        "operator": operator,
        "witness": witness,
    }
