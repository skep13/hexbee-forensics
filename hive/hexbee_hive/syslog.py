"""Syslog collection and log anomaly detection — the Hive's lightweight SIEM.

Two input paths, one rule engine:

  * `SyslogListener` binds a UDP socket (RFC 3164 and RFC 5424 both parse) and
    handles one datagram at a time. Nothing is buffered and raw lines are
    never written to the database, so a chatty network cannot fill the Pi's SD
    card or its 1 GB of RAM. Only *findings* become events.
  * `ingest_records()` takes already-structured log records — the path used by
    a Windows Event Log forwarder (NXLog `om_http` / winlogbeat) posting JSON
    to `/api/v1/logs`.

Rules are plain regex plus a small counter for threshold detections
(brute force). Matching cost is a few microseconds per line on a Pi 3B+.
"""

from __future__ import annotations

import logging
import re
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

log = logging.getLogger("hexbee.syslog")

# RFC 3164:  <134>Oct 11 22:14:15 host tag[pid]: message
# RFC 5424:  <134>1 2026-07-25T22:14:15Z host app pid msgid - message
_PRI_RE = re.compile(r"^<(\d{1,3})>(\d\s)?")
_RFC3164_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^:\[\s]{1,48})(\[\d+\])?:?\s*(?P<msg>.*)$"
)
_RFC5424_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<tag>\S+)\s+(?P<pid>\S+)\s+"
    r"(?P<msgid>\S+)\s+(?P<sd>\[.*?\]|-)\s*(?P<msg>.*)$"
)

SEVERITY_NAMES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class LogRecord:
    host: str = ""
    tag: str = ""
    message: str = ""
    severity: str = "info"
    facility: int = 1
    received_at: str = field(default_factory=_now)
    source_ip: str = ""

    @property
    def text(self) -> str:
        return f"{self.tag} {self.message}"


def parse_syslog(line: str, source_ip: str = "") -> LogRecord:
    """Best-effort parse. An unparseable line still yields a usable record —
    the rules run against the raw text rather than dropping the line."""
    rec = LogRecord(source_ip=source_ip, host=source_ip)
    body = line.strip()
    pri = _PRI_RE.match(body)
    if pri:
        value = int(pri.group(1))
        rec.facility, sev = divmod(value, 8)
        rec.severity = SEVERITY_NAMES[sev] if sev < len(SEVERITY_NAMES) else "info"
        body = body[pri.end():]
    m = _RFC5424_RE.match(body) or _RFC3164_RE.match(body)
    if m:
        rec.host = m.group("host") or rec.host
        rec.tag = m.group("tag")
        rec.message = m.group("msg")
    else:
        rec.message = body
    return rec


def record_from_json(item: dict, source_ip: str = "") -> LogRecord:
    """Normalize a JSON log record from a Windows forwarder (NXLog/winlogbeat).

    Windows Event Log fields vary by shipper, so several spellings are
    accepted. The Event ID is folded into the message text, which is what the
    rules match on.
    """
    host = str(item.get("Hostname") or item.get("host") or item.get("computer_name")
               or item.get("Computer") or source_ip or "")
    channel = str(item.get("Channel") or item.get("log_name")
                  or item.get("SourceName") or item.get("tag") or "eventlog")
    event_id = item.get("EventID") or item.get("event_id") or item.get("EventCode")
    message = str(item.get("Message") or item.get("message")
                  or item.get("EventData") or "")
    if event_id is not None:
        message = f"EventID={event_id} {message}"
    return LogRecord(
        host=host,
        tag=channel,
        message=message[:4000],
        severity=str(item.get("Severity") or item.get("level") or "info").lower(),
        received_at=_now(),
        source_ip=source_ip,
    )


# -- rules ----------------------------------------------------------------

@dataclass
class Rule:
    name: str
    pattern: re.Pattern
    severity: int          # Hive severity for the resulting event
    summary: str
    threshold: int = 1     # occurrences needed inside `window` seconds
    window: int = 300


RULES: list[Rule] = [
    Rule("auth_bruteforce",
         re.compile(r"(Failed password|authentication failure|Invalid user|"
                    r"FAILED LOGIN|EventID=4625)", re.I),
         3, "Repeated authentication failures — possible brute force",
         threshold=5, window=300),
    Rule("privilege_escalation",
         re.compile(r"(sudo:.*COMMAND=|session opened for user root|"
                    r"su(do)?: pam_unix.*session opened|EventID=4672|"
                    r"Special privileges assigned)", re.I),
         2, "Privilege escalation observed"),
    Rule("account_created",
         re.compile(r"(useradd\[|new user: name=|EventID=4720|"
                    r"A user account was created)", re.I),
         3, "New account created"),
    Rule("account_modified",
         re.compile(r"(usermod\[|added .* to group|EventID=4728|EventID=4732|"
                    r"member was added to a security-enabled)", re.I),
         2, "Account or group membership modified"),
    Rule("service_installed",
         re.compile(r"(systemd.*: Installed|EventID=7045|"
                    r"A service was installed in the system)", re.I),
         2, "New service installed"),
    Rule("cron_added",
         re.compile(r"(crontab\[.*\]\s*\((.*)\)\s*(REPLACE|BEGIN EDIT)|"
                    r"\(root\) CMD|EventID=4698)", re.I),
         2, "Scheduled task / cron entry created"),
    Rule("log_cleared",
         re.compile(r"(EventID=1102|EventID=104|audit log.*clear|"
                    r"The audit log was cleared)", re.I),
         3, "Audit or security log cleared"),
    Rule("security_tool_stopped",
         re.compile(r"(Stopping.*(clamav|falco|auditd|wazuh|defender)|"
                    r"Real-time protection.*disabled|EventID=5001)", re.I),
         3, "Security tooling stopped or disabled"),
]


class RuleEngine:
    """Stateful matcher. Threshold rules keep a bounded deque of hit times per
    (rule, host) so memory stays flat regardless of log volume."""

    MAX_TRACKED = 2000

    def __init__(self, rules: list[Rule] | None = None):
        self.rules = rules if rules is not None else RULES
        self._hits: dict[tuple[str, str], deque] = {}
        self._lock = threading.Lock()
        self.seen = 0

    def evaluate(self, rec: LogRecord) -> list[dict]:
        """Return Hive event dicts for every rule that fires on this record."""
        self.seen += 1
        text = rec.text
        events = []
        now = time.time()
        for rule in self.rules:
            if not rule.pattern.search(text):
                continue
            if rule.threshold > 1:
                count = self._count(rule, rec.host or rec.source_ip, now)
                if count < rule.threshold:
                    continue
            else:
                count = 1
            events.append({
                "device": f"Syslog-{(rec.host or rec.source_ip or 'unknown')[:48]}",
                "event_type": "log_anomaly",
                "occurred_at": rec.received_at,
                "payload": {
                    "rule": rule.name,
                    "summary": rule.summary,
                    "host": rec.host,
                    "source_ip": rec.source_ip,
                    "facility": rule.name,
                    "log_tag": rec.tag,
                    "log_severity": rec.severity,
                    # Truncated: the finding is evidence, the whole log is not.
                    "message": rec.message[:500],
                    "occurrences": count,
                    "window_seconds": rule.window if rule.threshold > 1 else 0,
                },
            })
        return events

    def _count(self, rule: Rule, key_host: str, now: float) -> int:
        key = (rule.name, key_host)
        with self._lock:
            if len(self._hits) > self.MAX_TRACKED:
                self._hits.clear()  # cheap bound; a reset costs one missed window
            dq = self._hits.setdefault(key, deque(maxlen=rule.threshold * 4))
            dq.append(now)
            cutoff = now - rule.window
            while dq and dq[0] < cutoff:
                dq.popleft()
            count = len(dq)
            if count >= rule.threshold:
                dq.clear()  # fire once per window, not once per line thereafter
            return count


# -- ingest paths ---------------------------------------------------------

def ingest_records(db, correlator, records: list[LogRecord],
                   engine: RuleEngine) -> dict:
    """Run the rules over parsed records and store any findings."""
    from .ingest import process_raw_event
    from .normalize import NormalizationError

    stored, findings = 0, []
    for rec in records:
        for ev in engine.evaluate(rec):
            try:
                result = process_raw_event(db, correlator, ev, source="syslog")
            except NormalizationError as exc:
                log.warning("log anomaly rejected: %s", exc)
                continue
            stored += 1
            findings.append({"rule": ev["payload"]["rule"],
                             "event_id": result["event_id"],
                             "incident_id": result["incident_id"]})
    return {"received": len(records), "anomalies": stored, "findings": findings}


class SyslogListener:
    """Blocking UDP syslog receiver. Run in its own thread or process.

    Port 514 is privileged; on the Pi either grant the capability
    (`setcap cap_net_bind_service=+ep`) or run on 5514 and redirect with
    iptables. `hexbee-hive syslog --port 5514` needs no privileges at all.
    """

    def __init__(self, cfg, db, correlator, host: str = "0.0.0.0", port: int = 514):
        self.cfg = cfg
        self.db = db
        self.correlator = correlator
        self.host = host
        self.port = port
        self.engine = RuleEngine()
        self._stop = threading.Event()
        self.received = 0
        self.anomalies = 0

    def stop(self) -> None:
        self._stop.set()

    def run_forever(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # A small receive buffer is intentional: dropping datagrams under a
        # flood is better than growing the kernel queue on a 1 GB host.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256 * 1024)
        sock.settimeout(1.0)
        sock.bind((self.host, self.port))
        log.info("syslog listener on udp/%d", self.port)
        self._announce("log_received", {"listener": f"udp/{self.port}",
                                        "state": "listening"})
        try:
            while not self._stop.is_set():
                try:
                    data, addr = sock.recvfrom(8192)
                except socket.timeout:
                    continue
                except OSError as exc:
                    log.warning("syslog socket error: %s", exc)
                    continue
                self.received += 1
                rec = parse_syslog(data.decode("utf-8", errors="replace"), addr[0])
                result = ingest_records(self.db, self.correlator, [rec], self.engine)
                self.anomalies += result["anomalies"]
        except KeyboardInterrupt:
            pass
        finally:
            sock.close()
            log.info("syslog listener stopped (%d lines, %d anomalies)",
                     self.received, self.anomalies)

    def _announce(self, event_type: str, payload: dict) -> None:
        from .ingest import process_raw_event
        from .normalize import NormalizationError
        try:
            process_raw_event(self.db, self.correlator,
                              {"device": "Hive-Syslog", "event_type": event_type,
                               "payload": payload}, source="syslog")
        except (NormalizationError, Exception):
            pass
