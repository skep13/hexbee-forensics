"""Ingest pipeline: MQTT subscriber feeding the normalize → store →
correlate chain.

The same `process_raw_event` function backs the REST ingest endpoint, so the
transport never changes what the evidence log contains.
"""

from __future__ import annotations

import json
import logging

from . import attack
from .config import HiveConfig
from .correlate import Correlator
from .db import Database
from .ioc import match_iocs, record_hits
from .normalize import NormalizationError, normalize
from .store import audit, store_event

log = logging.getLogger("hexbee.ingest")

# Optional offline threat-intel database, installed once at startup by the web
# app / engine. Kept as a module-level hook so every existing call site of
# `process_raw_event` picks intel matching up without a signature change.
_INTEL = None


def set_intel_store(store) -> None:
    """Attach an `intel.IntelStore` (or None to disable intel matching)."""
    global _INTEL
    _INTEL = store


def _intel_matches(payload: dict) -> list[dict]:
    if _INTEL is None:
        return []
    try:
        from .intel import match_intel
        return match_intel(_INTEL, payload)
    except Exception:
        log.exception("intel lookup failed")
        return []


_INTEL_KIND_TO_IOC = {"sha256": "sha256", "md5": "substring", "sha1": "substring",
                      "ip": "ip", "domain": "domain", "url": "substring"}


def _promote_intel(db: Database, hits: list[dict]) -> list[dict]:
    """Record threat-feed hits as IOC rows so they get the full treatment —
    ioc_hits, the `ioc` tag, the audit trail, and a place on the IOC page
    with their provenance.

    These rows are tagged with the `intel-sync` actor and are deliberately
    excluded from `match_iocs`'s linear substring scan: the intel store
    already found them by indexed lookup, and rescanning them on every
    subsequent event is how a long deployment slows to a crawl.
    """
    from .ioc import INTEL_ACTOR, add_ioc

    promoted = []
    for hit in hits:
        kind = _INTEL_KIND_TO_IOC.get(hit["kind"], "substring")
        value = hit["value"].lower()
        row = db.query_one("SELECT * FROM iocs WHERE kind = ? AND value = ?",
                           (kind, value))
        if row is None:
            try:
                add_ioc(db, kind, hit["value"],
                        f"threat intel: {hit['source']}"
                        + (f" ({hit['tag']})" if hit.get("tag") else ""),
                        actor=INTEL_ACTOR)
            except Exception:
                continue
            row = db.query_one("SELECT * FROM iocs WHERE kind = ? AND value = ?",
                               (kind, value))
        if row is not None:
            promoted.append(dict(row))
    return promoted


def process_raw_event(db: Database, correlator: Correlator, raw: dict, source: str) -> dict:
    """Normalize, persist, and correlate one raw event dict.

    Returns {"ok": True, "event_id": ..., "incident_id": ...} or raises
    NormalizationError (already audit-logged) for the caller to report.
    """
    try:
        normalized = normalize(raw)
    except NormalizationError as exc:
        audit(db, source, "event_rejected", str(exc))
        raise
    # Known-bad indicator? Escalate to critical so correlation must trigger.
    # (Severity is Hive-side triage metadata, deliberately outside the hash
    # chain, so this never alters the evidence record itself.)
    matches = match_iocs(db, normalized["payload"])
    # Pre-synced threat intel is checked the same way, but by indexed exact
    # match rather than substring scan (the feed tables are far too large for
    # a linear pass on a Pi). A feed hit is auto-promoted into the analyst
    # watchlist so it appears on /iocs with its provenance.
    intel_hits = _intel_matches(normalized["payload"])
    if intel_hits:
        matches.extend(_promote_intel(db, intel_hits))
    if matches:
        normalized["severity"] = 3
    event_id = store_event(db, normalized)
    if matches:
        record_hits(db, event_id, matches)
    # ATT&CK attribution: pure dict lookup, stored alongside (never inside)
    # the evidence record. A tagging failure must not lose the event.
    try:
        techniques = attack.tag_event(db, event_id, normalized["event_type"],
                                      normalized["payload"])
    except Exception:
        log.exception("ATT&CK tagging failed for event %d", event_id)
        techniques = []
    incident_id = correlator.process_event(event_id)
    log.info(
        "event %d stored (%s from %s)%s",
        event_id,
        normalized["event_type"],
        normalized["device"],
        f" -> incident {incident_id}" if incident_id else "",
    )
    return {"ok": True, "event_id": event_id, "incident_id": incident_id,
            "techniques": techniques}


class MqttIngest:
    """Blocking MQTT subscriber. Run in its own thread or as the engine
    process's main loop. Requires paho-mqtt."""

    def __init__(self, cfg: HiveConfig, db: Database, correlator: Correlator):
        self.cfg = cfg
        self.db = db
        self.correlator = correlator

    def run_forever(self) -> None:
        import paho.mqtt.client as mqtt

        client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id="hexbee-hive",
        )
        if self.cfg.mqtt_username:
            client.username_pw_set(self.cfg.mqtt_username, self.cfg.mqtt_password)
        if self.cfg.mqtt_tls_ca:
            client.tls_set(ca_certs=self.cfg.mqtt_tls_ca)

        client.on_connect = self._on_connect
        client.on_message = self._on_message
        # Automatic reconnect with backoff: Scouts and the broker come and go
        # on field Wi-Fi.
        client.reconnect_delay_set(min_delay=1, max_delay=60)
        client.connect(self.cfg.mqtt_host, self.cfg.mqtt_port, keepalive=60)
        log.info("MQTT ingest connected to %s:%d", self.cfg.mqtt_host, self.cfg.mqtt_port)
        client.loop_forever(retry_first_connection=True)

    def _on_connect(self, client, userdata, flags, reason_code, properties):
        client.subscribe(self.cfg.mqtt_topic, qos=1)
        log.info("subscribed to %s", self.cfg.mqtt_topic)

    def _on_message(self, client, userdata, msg):
        try:
            raw = json.loads(msg.payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            audit(self.db, f"mqtt:{msg.topic}", "event_rejected", f"bad JSON: {exc}")
            return
        try:
            process_raw_event(self.db, self.correlator, raw, source=f"mqtt:{msg.topic}")
        except NormalizationError as exc:
            log.warning("rejected event on %s: %s", msg.topic, exc)
        except Exception:
            log.exception("ingest failure on %s", msg.topic)
