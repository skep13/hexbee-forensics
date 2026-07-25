"""Responder → Hive bridge.

Responder writes each capture to its own file under `Logs/`. This watcher
tails that directory and turns every new NTLMv2 hash or cleartext credential
into a `credential_capture` event, so captured credentials enter the
chain-of-custody automatically instead of living in a scratch file that gets
lost between engagements.

Two things this deliberately does:

  * **It does not send the secret.** The hash or password is fingerprinted
    (SHA-256 of the material) and the *structure* is recorded — account,
    domain, source host, capture method, hash format. Shipping harvested
    credentials into a database on an SD card, in an evidence log you will
    later hand to a client, is not something a tool should do quietly. Pass
    `--include-material` if your rules of engagement require the full hash in
    the report, and it is recorded that you chose to.
  * **It only reads.** Responder's own files are never modified or removed.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("hexbee.queen.responder")

DEFAULT_LOG_DIRS = [
    Path("/usr/share/responder/logs"),
    Path("/opt/Responder/logs"),
    Path("/usr/share/Responder/logs"),
    Path.home() / "Responder" / "logs",
]

# Responder file naming: <Proto>-<Type>-<ClientIP>.txt
FILENAME_RE = re.compile(
    r"^(?P<proto>[A-Za-z0-9]+)-(?P<kind>NTLMv2|NTLMv1|Clear-Text|Plaintext)"
    r"(?:-SSP)?-(?P<client>[0-9a-fA-F.:]+)\.txt$", re.I)

# NTLMv2:  user::DOMAIN:challenge:HMAC:blob
NTLMV2_RE = re.compile(
    r"^(?P<user>[^:]{1,104})::(?P<domain>[^:]{0,104}):"
    r"(?P<challenge>[0-9a-fA-F]{16}):(?P<hmac>[0-9a-fA-F]{32}):(?P<blob>[0-9a-fA-F]+)$")
# NTLMv1:  user::DOMAIN:LMresp:NTresp:challenge
NTLMV1_RE = re.compile(
    r"^(?P<user>[^:]{1,104})::(?P<domain>[^:]{0,104}):"
    r"(?P<lm>[0-9a-fA-F]{48}):(?P<nt>[0-9a-fA-F]{48}):(?P<challenge>[0-9a-fA-F]{16})$")
CLEARTEXT_RE = re.compile(r"^(?P<user>[^:]{1,104}):(?P<password>.+)$")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_log_dir(explicit: str | Path | None = None) -> Path | None:
    for candidate in ([Path(explicit)] if explicit else []) + DEFAULT_LOG_DIRS:
        if candidate.is_dir():
            return candidate
    return None


def _fingerprint(material: str) -> str:
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()


def parse_line(line: str, proto: str, kind: str, client: str) -> dict | None:
    """One Responder log line -> a structured capture, or None."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    m = NTLMV2_RE.match(line)
    if m:
        return {"format": "NTLMv2-SSP", "user": m.group("user"),
                "domain": m.group("domain"), "protocol": proto,
                "source_host": client, "crackable": True,
                "fingerprint": _fingerprint(line), "material": line}
    m = NTLMV1_RE.match(line)
    if m:
        return {"format": "NTLMv1", "user": m.group("user"),
                "domain": m.group("domain"), "protocol": proto,
                "source_host": client, "crackable": True,
                "fingerprint": _fingerprint(line), "material": line}
    if kind.lower().startswith(("clear", "plain")):
        m = CLEARTEXT_RE.match(line)
        if m:
            return {"format": "cleartext", "user": m.group("user"),
                    "domain": "", "protocol": proto, "source_host": client,
                    "crackable": False, "fingerprint": _fingerprint(line),
                    "material": line}
    return None


def parse_file(path: Path) -> list[dict]:
    name = FILENAME_RE.match(path.name)
    proto = name.group("proto") if name else path.stem.split("-")[0]
    kind = name.group("kind") if name else "unknown"
    client = name.group("client") if name else ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out = []
    for line in text.splitlines():
        parsed = parse_line(line, proto, kind, client)
        if parsed:
            parsed["log_file"] = path.name
            out.append(parsed)
    return out


def to_events(captures: list[dict], device: str, case_id: int | None,
              include_material: bool, auth_ref: str = "") -> list[dict]:
    events = []
    for cap in captures:
        payload = {
            "credential_format": cap["format"],
            "account": cap["user"],
            "domain": cap["domain"],
            "protocol": cap["protocol"],
            "source_host": cap["source_host"],
            "capture_method": "responder",
            "crackable": cap["crackable"],
            "fingerprint": cap["fingerprint"],
            "log_file": cap.get("log_file", ""),
            "case_id": case_id,
            "authorisation": auth_ref,
            "material_included": include_material,
        }
        if include_material:
            payload["material"] = cap["material"]
        events.append({"device": device, "event_type": "credential_capture",
                       "occurred_at": _now(), "payload": payload})
    return events


class ResponderBridge:
    """Tail Responder's log directory and forward new captures."""

    def __init__(self, client, log_dir: Path, *, device: str = "Queen-Responder",
                 case_id: int | None = None, ingest_key: str | None = None,
                 include_material: bool = False):
        self.client = client
        self.log_dir = Path(log_dir)
        self.device = device
        self.case_id = case_id
        self.ingest_key = ingest_key
        self.include_material = include_material
        # Fingerprints already forwarded — the same hash reappears every time
        # a host retries, and one capture should be one evidence record.
        self._seen: set[str] = set()
        self.forwarded = 0

    def sweep(self) -> list[dict]:
        """Parse every log file, returning only captures not seen before."""
        fresh = []
        for path in sorted(self.log_dir.glob("*.txt")):
            for cap in parse_file(path):
                if cap["fingerprint"] in self._seen:
                    continue
                self._seen.add(cap["fingerprint"])
                fresh.append(cap)
        return fresh

    def ship(self, captures: list[dict]) -> int:
        if not captures:
            return 0
        events = to_events(captures, self.device, self.case_id,
                           self.include_material)
        if not self.ingest_key:
            return 0
        stored = self.client.ingest(events, self.ingest_key).get("stored", 0)
        self.forwarded += stored
        return stored

    def prime(self) -> int:
        """Mark everything currently on disk as already seen.

        Default behaviour for `watch`: an engagement should capture what
        happens from now on, not re-import last month's log directory.
        """
        return len(self.sweep())

    def watch(self, interval: int = 5, on_capture=None) -> None:
        log.info("watching %s every %ds", self.log_dir, interval)
        try:
            while True:
                fresh = self.sweep()
                if fresh:
                    stored = self.ship(fresh)
                    for cap in fresh:
                        log.info("captured %s %s\\%s from %s",
                                 cap["format"], cap["domain"] or ".",
                                 cap["user"], cap["source_host"])
                        if on_capture:
                            on_capture(cap)
                    log.info("forwarded %d capture(s) to the Hive", stored)
                time.sleep(interval)
        except KeyboardInterrupt:
            log.info("stopped after forwarding %d capture(s)", self.forwarded)
