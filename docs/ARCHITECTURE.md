# HexBee Architecture

## Data flow

```
Scout (ESP32-S3)                     Hive (Pi 3B+)                    Queen (T470)
────────────────                     ─────────────                    ────────────
usb_watch ─┐                         Mosquitto (MQTT broker)
heartbeat ─┼─> emit_event ──MQTT──>  MqttIngest ─┐
wifi/sntp ─┘   (offline ring         REST /ingest┴─> process_raw_event
                buffer)                               │ normalize()      hexbee-queen CLI
                                                      │ store_event()  ──REST──> cases,
                                                      │   (hash chain)           timelines,
                                                      └ Correlator               reports,
                                                          │                      search
                                                          ▼
                                     SQLite: events / incidents / cases /
                                             users / tags / audit_log
                                                          │
                                     Flask: dashboard + /api/v1
```

## Design decisions

**One write path.** Both transports (MQTT, REST) funnel into
`ingest.process_raw_event` → `store.store_event`. Nothing else inserts into
`events`, which is what makes the hash chain meaningful.

**Hash chain over per-event hashes.** A per-event SHA-256 proves an event
wasn't corrupted; it doesn't prove events weren't deleted or reordered.
Chaining (`sha256(prev_hash ‖ canonical_record)`) commits each event to the
entire history before it. `received_at` is excluded from the hashed record so
a Scout's own logs can independently re-derive the chain.

**Correlation is event-driven and cheap.** Each stored event does at most
two indexed queries: "is there a warm open incident for this device?" and, on
a severity ≥ 2 trigger, one UPDATE to sweep recent same-device context events
into the new incident. No batch jobs, safe on 1 GB of RAM.

**SQLite, WAL mode, one process-wide lock.** Event rates are tens per
minute, not thousands per second; a Pi 3B+ with a USB SSD handles this with
huge margin, and backup is a file copy (plus `hexbee-hive verify` after
restore).

**Auth is stdlib-only.** PBKDF2-HMAC-SHA256 (600k iterations) passwords,
random URL-safe bearer tokens with TTL, three ranked roles. The dashboard
cookie and the API bearer token are the same token — one auth path.

**Timeline is derived, not stored.** Narratives are rendered from the
canonical events at read time, so improving the narrator never touches
evidence.

## Event contract (Scout → Hive)

```json
{
  "device": "Scout01",
  "event_type": "usb_inserted",
  "occurred_at": "2026-07-18T14:22:10Z",
  "payload": {"volume_label": "KINGSTON32", "fs": "FAT32"}
}
```

- `occurred_at` may be ISO-8601 or unix epoch (firmware sends epoch; no RTC
  needed before SNTP sync).
- Unknown `event_type`s are accepted at severity 0 — new Scout capabilities
  don't require a Hive upgrade first.
- Known types and severities live in `hexbee_hive/normalize.py`
  (0 info, 1 notice, 2 warning, 3 critical; severity ≥ 2 triggers incident
  correlation).

## Security roadmap (in dependency order)

1. Per-Scout Mosquitto credentials (replace `allow_anonymous true`)
2. TLS for MQTT (`HEXBEE_MQTT_TLS_CA`) and HTTPS for the dashboard via a
   reverse proxy
3. Cryptographic device identity: per-Scout keypair, event signing on the
   ESP32-S3, signature verification in ingest
4. Signed export bundles for court-ready evidence hand-off
