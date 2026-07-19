"""Ingest pipeline: MQTT subscriber feeding the normalize → store →
correlate chain.

The same `process_raw_event` function backs the REST ingest endpoint, so the
transport never changes what the evidence log contains.
"""

from __future__ import annotations

import json
import logging

from .config import HiveConfig
from .correlate import Correlator
from .db import Database
from .ioc import match_iocs, record_hits
from .normalize import NormalizationError, normalize
from .store import audit, store_event

log = logging.getLogger("hexbee.ingest")


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
    if matches:
        normalized["severity"] = 3
    event_id = store_event(db, normalized)
    if matches:
        record_hits(db, event_id, matches)
    incident_id = correlator.process_event(event_id)
    log.info(
        "event %d stored (%s from %s)%s",
        event_id,
        normalized["event_type"],
        normalized["device"],
        f" -> incident {incident_id}" if incident_id else "",
    )
    return {"ok": True, "event_id": event_id, "incident_id": incident_id}


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
