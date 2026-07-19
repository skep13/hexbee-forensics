#!/usr/bin/env python3
"""HexBee Scout simulator.

Emits the same JSON events a real ESP32-S3 Scout will send, so the Hive
pipeline (ingest -> normalize -> hash chain -> correlation -> timeline) can
be developed and demonstrated without hardware.

Transports:
    --rest  http://hive:8080  --key <ingest-key>     (REST ingest endpoint)
    --mqtt  hive-host[:port]                          (requires paho-mqtt)

Scenarios:
    quiet      heartbeat traffic only
    usb        USB stick inserted, files catalogued, nothing suspicious
    incident   the full demo: USB inserted -> executable found ->
               PowerShell launched -> network beacon  (opens an incident)

Example:
    py scout_sim.py --rest http://127.0.0.1:8080 --key devkey \
        --device Scout01 --scenario incident
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from datetime import datetime, timezone


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_events(device: str, scenario: str) -> list[dict]:
    def ev(event_type: str, payload: dict | None = None) -> dict:
        return {
            "device": device,
            "event_type": event_type,
            "occurred_at": now_iso(),
            "payload": payload or {},
        }

    events = [ev("scout_online", {"fw": "sim-0.1.0", "ip": "192.168.4.23"})]

    if scenario == "quiet":
        events += [ev("heartbeat", {"uptime_s": 60 * i}) for i in range(1, 4)]
        return events

    events.append(ev("usb_inserted", {"volume_label": "KINGSTON32", "fs": "FAT32",
                                      "capacity_mb": 30736}))
    events.append(ev("usb_scan", {"file_count": 184, "duration_ms": 5210}))
    events.append(ev("file_metadata", {"name": "report_q2.docx", "size": 88412,
                                       "modified": "2026-06-30T14:22:10Z"}))
    events.append(ev("file_metadata", {"name": "photos/IMG_2214.jpg", "size": 3145728,
                                       "modified": "2026-05-11T09:02:44Z"}))

    if scenario == "usb":
        events.append(ev("usb_removed"))
        return events

    # scenario == "incident"
    events.append(ev("executable_found", {
        "name": "invoice_viewer.exe",
        "path": "/docs/invoice_viewer.exe",
        "size": 421376,
        "sha256": "9f2c8b1a" + "".join(random.choices("0123456789abcdef", k=56)),
    }))
    events.append(ev("autorun_found", {"name": "autorun.inf",
                                       "target": "invoice_viewer.exe"}))
    events.append(ev("powershell_launched", {
        "cmdline": "powershell -w hidden -enc <redacted>", "parent": "explorer.exe"}))
    events.append(ev("network_beacon", {"destination": "185.203.116.42:443",
                                        "interval_s": 30, "protocol": "https"}))
    events.append(ev("evidence_uploaded", {"package": "scout01-triage-001.tgz",
                                           "sha256": "".join(random.choices("0123456789abcdef", k=64))}))
    return events


def send_rest(base_url: str, key: str, events: list[dict], delay: float) -> None:
    import urllib.request

    for event in events:
        req = urllib.request.Request(
            f"{base_url.rstrip('/')}/api/v1/ingest",
            data=json.dumps(event).encode(),
            method="POST",
            headers={"Content-Type": "application/json", "X-HexBee-Ingest-Key": key},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
        result = body["results"][0] if body.get("results") else body
        incident = result.get("incident_id")
        print(f"sent {event['event_type']:<20} -> event {result.get('event_id')}"
              + (f" (incident {incident})" if incident else ""))
        time.sleep(delay)


def send_mqtt(host: str, port: int, events: list[dict], delay: float,
              username: str, password: str) -> None:
    import paho.mqtt.client as mqtt

    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    if username:
        client.username_pw_set(username, password)
    client.connect(host, port, keepalive=30)
    client.loop_start()
    for event in events:
        topic = f"hexbee/events/{event['device']}"
        client.publish(topic, json.dumps(event), qos=1).wait_for_publish()
        print(f"published {event['event_type']:<20} to {topic}")
        time.sleep(delay)
    client.loop_stop()
    client.disconnect()


def main() -> int:
    p = argparse.ArgumentParser(description="HexBee Scout simulator")
    p.add_argument("--device", default="Scout01")
    p.add_argument("--scenario", choices=("quiet", "usb", "incident"), default="incident")
    p.add_argument("--delay", type=float, default=0.5, help="seconds between events")
    transport = p.add_mutually_exclusive_group(required=True)
    transport.add_argument("--rest", metavar="URL", help="Hive base URL for REST ingest")
    transport.add_argument("--mqtt", metavar="HOST[:PORT]", help="MQTT broker")
    p.add_argument("--key", default="", help="ingest key (REST mode)")
    p.add_argument("--mqtt-user", default="")
    p.add_argument("--mqtt-pass", default="")
    args = p.parse_args()

    events = make_events(args.device, args.scenario)
    print(f"Scenario '{args.scenario}': {len(events)} events from {args.device}")

    if args.rest:
        if not args.key:
            print("REST mode requires --key", file=sys.stderr)
            return 1
        send_rest(args.rest, args.key, events, args.delay)
    else:
        host, _, port = args.mqtt.partition(":")
        send_mqtt(host, int(port or 1883), events, args.delay,
                  args.mqtt_user, args.mqtt_pass)
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
