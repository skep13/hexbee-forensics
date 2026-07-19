"""The Forager agent: orchestrates collection, ships to the Hive, buffers
offline, and (in watch mode) monitors the host continuously — all with no
interactive input.

Autonomy comes from three things:
  1. The Hive location is auto-discovered (explicit args -> environment ->
     config file), so the agent needs no prompts.
  2. Every registered collector runs automatically.
  3. If the Hive is unreachable, events are spooled locally and flushed on the
     next successful contact — collection never blocks on the network.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .collectors import ALL_COLLECTORS

log = logging.getLogger("hexbee.forager")

CONFIG_PATHS = [
    Path.home() / ".hexbee-forager.json",
    Path("/etc/hexbee/forager.json"),
]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def discover_config(hive_url: str | None = None, ingest_key: str | None = None) -> dict:
    """Resolve Hive URL + ingest key: explicit args -> env -> config file."""
    import os

    cfg = {"hive_url": hive_url, "ingest_key": ingest_key}
    if not cfg["hive_url"]:
        cfg["hive_url"] = os.environ.get("HEXBEE_HIVE_URL")
    if not cfg["ingest_key"]:
        cfg["ingest_key"] = os.environ.get("HEXBEE_INGEST_KEY")
    if not (cfg["hive_url"] and cfg["ingest_key"]):
        for path in CONFIG_PATHS:
            if path.is_file():
                try:
                    data = json.loads(path.read_text())
                    cfg["hive_url"] = cfg["hive_url"] or data.get("hive_url")
                    cfg["ingest_key"] = cfg["ingest_key"] or data.get("ingest_key")
                except (OSError, json.JSONDecodeError):
                    continue
    return cfg


class Forager:
    def __init__(self, hive_url: str | None, ingest_key: str | None,
                 spool_dir: Path | None = None, device: str | None = None):
        import socket
        self.hive_url = (hive_url or "").rstrip("/")
        self.ingest_key = ingest_key or ""
        self.device = device or f"Forager-{socket.gethostname()}"
        self.spool_dir = spool_dir or (Path.home() / ".hexbee-forager" / "spool")
        self.spool_dir.mkdir(parents=True, exist_ok=True)

    # -- collection -------------------------------------------------------

    def collect(self, volatile_only: bool = False) -> list[dict]:
        """Run every collector (or just the volatile ones) and return a
        device-stamped, framed event list."""
        run_id = uuid.uuid4().hex[:12]
        events: list[dict] = [self._stamp({
            "event_type": "collection_started",
            "occurred_at": _now(),
            "payload": {"run_id": run_id, "forager": __version__,
                        "mode": "volatile" if volatile_only else "full"},
        })]
        counts: dict[str, int] = {}
        for name, fn, volatile in ALL_COLLECTORS:
            if volatile_only and not volatile:
                continue
            try:
                produced = fn()
            except Exception as exc:  # one collector failing never aborts the run
                log.warning("collector %s failed: %s", name, exc)
                produced = []
            counts[name] = len(produced)
            for ev in produced:
                events.append(self._stamp(ev))
            log.info("collected %s: %d", name, len(produced))

        digest = hashlib.sha256(
            json.dumps([e["payload"] for e in events], sort_keys=True).encode()).hexdigest()
        events.append(self._stamp({
            "event_type": "collection_completed",
            "occurred_at": _now(),
            "payload": {"run_id": run_id, "counts": counts,
                        "events": len(events) + 1,  # inclusive of this marker
                        "manifest_sha256": digest},
        }))
        return events

    def _stamp(self, ev: dict) -> dict:
        ev = dict(ev)
        ev["device"] = self.device
        ev.setdefault("occurred_at", _now())
        return ev

    # -- shipping ---------------------------------------------------------

    def ship(self, events: list[dict], batch: int = 500) -> dict:
        """Upload events to the Hive; spool locally on any failure."""
        if not (self.hive_url and self.ingest_key):
            path = self._spool(events)
            return {"shipped": 0, "spooled": len(events), "spool_file": str(path),
                    "reason": "no Hive configured"}
        sent, failed = 0, []
        for i in range(0, len(events), batch):
            chunk = events[i:i + batch]
            if self._post(chunk):
                sent += len(chunk)
            else:
                failed.extend(chunk)
        result = {"shipped": sent, "spooled": 0}
        if failed:
            path = self._spool(failed)
            result["spooled"] = len(failed)
            result["spool_file"] = str(path)
        return result

    def _post(self, chunk: list[dict]) -> bool:
        req = urllib.request.Request(
            f"{self.hive_url}/api/v1/ingest",
            data=json.dumps(chunk).encode(),
            method="POST",
            headers={"Content-Type": "application/json",
                     "X-HexBee-Ingest-Key": self.ingest_key},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status == 200
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log.warning("ship failed (%s) — spooling", exc)
            return False

    def _spool(self, events: list[dict]) -> Path:
        name = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}_{uuid.uuid4().hex[:6]}.jsonl"
        path = self.spool_dir / name
        with open(path, "w", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")
        return path

    def flush_spool(self) -> int:
        """Try to ship every spooled file; delete each on success. Returns the
        number of events flushed."""
        if not (self.hive_url and self.ingest_key):
            return 0
        flushed = 0
        for path in sorted(self.spool_dir.glob("*.jsonl")):
            try:
                events = [json.loads(line) for line in path.read_text().splitlines() if line]
            except (OSError, json.JSONDecodeError):
                continue
            if self._post(events):
                flushed += len(events)
                path.unlink(missing_ok=True)
                log.info("flushed spool file %s (%d events)", path.name, len(events))
            else:
                break  # Hive still unreachable; stop and keep the rest
        return flushed

    # -- run modes --------------------------------------------------------

    def run_once(self) -> dict:
        flushed = self.flush_spool()
        events = self.collect(volatile_only=False)
        result = self.ship(events)
        result["flushed_from_spool"] = flushed
        result["collected"] = len(events)
        return result

    def watch(self, interval: int = 60, full_every: int = 30) -> None:
        """Continuously monitor the host. Emits `*_new` events when a process,
        connection, logon, or USB device appears that wasn't there before.
        Runs until interrupted."""
        log.info("watch mode: interval=%ds, full sweep every %d cycles", interval, full_every)
        self.flush_spool()
        baseline = self._volatile_keys(self.collect(volatile_only=True))
        # Ship the initial full snapshot once.
        self.ship(self.collect(volatile_only=False))
        cycle = 0
        try:
            while True:
                time.sleep(interval)
                cycle += 1
                self.flush_spool()
                sample = self.collect(volatile_only=True)
                new_events = self._diff_new(baseline, sample)
                baseline = self._volatile_keys(sample)
                if cycle % full_every == 0:
                    new_events = self.collect(volatile_only=False)  # periodic full sweep
                if new_events:
                    res = self.ship(new_events)
                    log.info("cycle %d: %d event(s) shipped=%d spooled=%d",
                             cycle, len(new_events), res["shipped"], res["spooled"])
        except KeyboardInterrupt:
            log.info("watch stopped")

    # change detection ----------------------------------------------------

    _NEW_TYPE = {
        "process_snapshot": "process_new",
        "network_connection": "network_new",
        "logon_session": "logon_new",
        "usb_device": "usb_new",
    }

    @staticmethod
    def _key(ev: dict) -> str:
        p = ev["payload"]
        t = ev["event_type"]
        if t == "process_snapshot":
            return f"proc:{p.get('pid')}:{p.get('name')}"
        if t == "network_connection":
            return f"net:{p.get('proto')}:{p.get('local')}:{p.get('remote')}"
        if t == "logon_session":
            return f"logon:{p.get('user')}:{p.get('terminal')}"
        if t == "usb_device":
            return f"usb:{p.get('device') or p.get('raw')}"
        return f"{t}:{id(ev)}"

    def _volatile_keys(self, events: list[dict]) -> set[str]:
        return {self._key(e) for e in events if e["event_type"] in self._NEW_TYPE}

    def _diff_new(self, baseline: set[str], sample: list[dict]) -> list[dict]:
        out = []
        for ev in sample:
            if ev["event_type"] in self._NEW_TYPE and self._key(ev) not in baseline:
                new_ev = dict(ev)
                new_ev["event_type"] = self._NEW_TYPE[ev["event_type"]]
                out.append(new_ev)
        return out
