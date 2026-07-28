"""The Netmon agent: capture loop, batching, and delivery to the Hive.

Delivery follows the same contract as the Forager — POST to
`/api/v1/ingest` with the shared key, spool to disk when the Hive is
unreachable, flush on the next success — so a Netmon running on the Pi
survives a Hive restart without losing findings.
"""

from __future__ import annotations

import json
import logging
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .capture import CaptureError, make_capture
from .rules import RuleEngine

log = logging.getLogger("hexbee.netmon")

MODES = ("ids", "recon", "diagnostics")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")



def device_name(prefix: str, given: str | None = None) -> str:
    """A device name the Hive will actually accept.

    Hive device names are `[A-Za-z0-9_-]{1,64}`; hostnames frequently are not.
    macOS reports `Jacobs-MacBook-Air.local` and many Linux hosts report an
    FQDN, so the dotted default was rejected by the normalizer on every single
    event — the agent collected hundreds of artifacts, shipped none of them,
    and spooled the lot. That reads like a network fault and is not one.
    """
    import re
    import socket

    raw = given or socket.gethostname().split(".")[0]
    cleaned = re.sub(r"[^A-Za-z0-9_-]", "-", raw).strip("-") or "unknown"
    return f"{prefix}-{cleaned}"[:64] if not given else cleaned[:64]


class NetMon:
    def __init__(self, hive_url: str | None, ingest_key: str | None, *,
                 mode: str = "ids", iface: str | None = None,
                 device: str | None = None, backend: str = "raw",
                 monitor: bool = False, pcap: str | None = None,
                 spool_dir: Path | None = None,
                 flush_interval: int = 30):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.hive_url = (hive_url or "").rstrip("/")
        self.ingest_key = ingest_key or ""
        self.mode = mode
        self.iface = iface
        self.backend = backend
        self.monitor = monitor
        self.pcap = pcap
        self.device = device_name("Netmon", device)
        self.flush_interval = flush_interval
        self.spool_dir = spool_dir or (Path.home() / ".hexbee-netmon" / "spool")
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self.engine = RuleEngine()
        self.run_id = uuid.uuid4().hex[:12]
        self._stop = threading.Event()
        self.alerts = 0

    def stop(self) -> None:
        self._stop.set()

    # -- delivery ---------------------------------------------------------

    def _event(self, event_type: str, payload: dict, severity_hint: int = 0) -> dict:
        return {"device": self.device, "event_type": event_type,
                "occurred_at": _now(),
                "payload": payload | {"run_id": self.run_id, "mode": self.mode,
                                      "netmon": __version__}}

    def ship(self, events: list[dict], batch: int = 200) -> dict:
        if not events:
            return {"shipped": 0, "spooled": 0}
        if not (self.hive_url and self.ingest_key):
            return {"shipped": 0, "spooled": len(self._spool(events))}
        sent, failed = 0, []
        for i in range(0, len(events), batch):
            chunk = events[i:i + batch]
            if self._post(chunk):
                sent += len(chunk)
            else:
                failed.extend(chunk)
        if failed:
            self._spool(failed)
        return {"shipped": sent, "spooled": len(failed)}

    def _post(self, chunk: list[dict]) -> bool:
        req = urllib.request.Request(
            f"{self.hive_url}/api/v1/ingest",
            data=json.dumps(chunk).encode(), method="POST",
            headers={"Content-Type": "application/json",
                     "X-HexBee-Ingest-Key": self.ingest_key})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status == 200
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log.warning("ship failed (%s) — spooling", exc)
            return False

    def _spool(self, events: list[dict]) -> list[dict]:
        name = (f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}_"
                f"{uuid.uuid4().hex[:6]}.jsonl")
        with open(self.spool_dir / name, "w", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")
        return events

    def flush_spool(self) -> int:
        if not (self.hive_url and self.ingest_key):
            return 0
        flushed = 0
        for path in sorted(self.spool_dir.glob("*.jsonl")):
            try:
                events = [json.loads(line) for line in
                          path.read_text(encoding="utf-8").splitlines() if line]
            except (OSError, json.JSONDecodeError):
                continue
            if self._post(events):
                flushed += len(events)
                path.unlink(missing_ok=True)
            else:
                break
        return flushed

    # -- modes ------------------------------------------------------------

    def run(self, duration: int | None = None) -> dict:
        if self.mode == "diagnostics":
            return self.run_diagnostics(duration)
        return self.run_capture(duration)

    def run_capture(self, duration: int | None = None) -> dict:
        """ids / recon: one capture loop, different outputs."""
        cap = make_capture(self.backend, self.iface, self.monitor, self.pcap)
        self.flush_spool()
        self.ship([self._event("netmon_started", {
            "interface": self.iface or "any", "backend": self.backend,
            "monitor": self.monitor, "pcap": bool(self.pcap)})])

        pending: list[dict] = []
        last_flush = time.time()
        deadline = time.time() + duration if duration else None
        started = time.time()
        try:
            for pkt in cap.packets(self._stop):
                for finding in self.engine.feed(pkt):
                    self.alerts += 1
                    pending.append(self._event("network_alert", {
                        "rule": finding.rule,
                        "severity_hint": finding.severity,
                        "summary": finding.summary,
                        **finding.detail}))
                now = time.time()
                if pending and (now - last_flush >= self.flush_interval
                                or len(pending) >= 200):
                    self.ship(pending)
                    pending.clear()
                    last_flush = now
                if deadline and now >= deadline:
                    break
        except CaptureError:
            raise
        except KeyboardInterrupt:
            pass
        finally:
            cap.close()

        if self.mode == "recon":
            pending.extend(self._recon_events())
        pending.append(self._event("netmon_stopped", {
            "packets": self.engine.packets,
            "alerts": self.alerts,
            "hosts_seen": len(self.engine.hosts),
            "duration_seconds": round(time.time() - started, 1)}))
        result = self.ship(pending)
        return {"packets": self.engine.packets, "alerts": self.alerts,
                "hosts": len(self.engine.hosts), **result}

    # A busy or spoofed network can present thousands of apparent hosts. One
    # event each would be a single enormous batch for a Pi to serialise and a
    # Hive to chain, so the sweep reports the most-seen hosts and says how
    # many it left out rather than silently truncating.
    MAX_RECON_HOSTS = 512

    def _recon_events(self) -> list[dict]:
        """Recon mode output: one event per host, plus a rollup.

        One event per host (not per packet) is what keeps a recon sweep from
        flooding the evidence log — a /24 produces at most 254 records.
        """
        events = []
        inventory = sorted(self.engine.inventory(),
                           key=lambda h: h["packets"], reverse=True)
        omitted = max(0, len(inventory) - self.MAX_RECON_HOSTS)
        for host in inventory[:self.MAX_RECON_HOSTS]:
            events.append(self._event("recon_finding", {
                "finding": "host_observed",
                "ip": host["ip"], "mac": host["mac"],
                "open_ports": host["ports"],
                "randomised_mac": host["randomised_mac"],
                "packets": host["packets"],
                "method": "passive"}))
        events.append(self._event("recon_finding", {
            "finding": "sweep_summary",
            "hosts": len(self.engine.hosts),
            "hosts_reported": len(inventory) - omitted,
            "hosts_omitted": omitted,
            "truncated": bool(omitted),
            "services": sum(len(p) for p in self.engine.services.values()),
            "method": "passive"}))
        return events

    def run_diagnostics(self, duration: int | None = None,
                        interval: int = 300,
                        targets: tuple[str, ...] = ()) -> dict:
        """Repeatedly snapshot network health until stopped."""
        from .diagnostics import snapshot

        self.flush_spool()
        deadline = time.time() + duration if duration else None
        cycles, alerts = 0, 0
        while not self._stop.is_set():
            payload, found = snapshot(targets)
            events = [self._event("diagnostic_snapshot", payload)]
            for alert in found:
                alerts += 1
                events.append(self._event("network_alert", alert))
            self.ship(events)
            cycles += 1
            if deadline and time.time() >= deadline:
                break
            if self._stop.wait(interval):
                break
        return {"cycles": cycles, "alerts": alerts}
