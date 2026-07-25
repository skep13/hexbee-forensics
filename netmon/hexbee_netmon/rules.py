"""Detection rules and the passive inventory.

Every rule is header-only and bounded: each keeps a small dict of counters
that is trimmed on a timer, so a long-running capture on a Pi 3B+ holds a
constant amount of state no matter how much traffic passes.

Rules produce Hive event payloads with a `rule` key, which the Hive's ATT&CK
tagger maps to a technique (port_scan -> T1046, arp_spoof -> T1557.002, and
so on).
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field

# Ports that are interesting when they appear as a destination.
SUSPICIOUS_PORTS = {
    4444: "metasploit default handler",
    5555: "adb / remote shell",
    1337: "common backdoor port",
    31337: "common backdoor port",
    6667: "irc (legacy c2)",
    23: "telnet (cleartext)",
    2323: "telnet (iot botnet)",
    3389: "rdp",
    5900: "vnc",
}

RELAY_PORTS = {445, 139}


@dataclass
class Finding:
    rule: str
    severity: int
    summary: str
    detail: dict = field(default_factory=dict)


class RuleEngine:
    """Stateful detector shared by ids and recon modes."""

    # Bounds — chosen so worst-case state stays in single-digit MB.
    MAX_TRACKED_SOURCES = 4096
    MAX_TRACKED_HOSTS = 8192

    def __init__(self, *,
                 scan_ports: int = 20, scan_window: int = 60,
                 relay_sources: int = 3, relay_window: int = 120,
                 dns_queries: int = 40, dns_window: int = 60,
                 dns_min_label: int = 30,
                 deauth_count: int = 20, deauth_window: int = 30,
                 known_hosts: set[str] | None = None):
        self.scan_ports, self.scan_window = scan_ports, scan_window
        self.relay_sources, self.relay_window = relay_sources, relay_window
        self.dns_queries, self.dns_window = dns_queries, dns_window
        self.dns_min_label = dns_min_label
        self.deauth_count, self.deauth_window = deauth_count, deauth_window

        self._scan: dict[str, dict[int, float]] = defaultdict(dict)
        self._relay: dict[str, dict[str, float]] = defaultdict(dict)
        self._dns: dict[str, list[float]] = defaultdict(list)
        self._deauth: dict[str, list[float]] = defaultdict(list)
        self._arp: dict[str, str] = {}
        self._fired: dict[tuple, float] = {}
        self._last_trim = time.time()

        # Passive inventory (recon mode, also used for new-host alerts).
        self.hosts: dict[str, dict] = {}
        self.services: dict[str, set[int]] = defaultdict(set)
        self.known_hosts = known_hosts or set()
        self.packets = 0

    # -- entry point ------------------------------------------------------

    def feed(self, pkt) -> list[Finding]:
        self.packets += 1
        now = time.time()
        if now - self._last_trim > 30:
            self._trim(now)
        findings: list[Finding] = []
        self._inventory(pkt, now)

        if pkt.proto == "arp":
            findings.extend(self._arp_rules(pkt, now))
            return findings
        if pkt.proto == "dot11":
            findings.extend(self._deauth_rule(pkt, now))
            return findings
        if pkt.proto == "tcp":
            findings.extend(self._scan_rule(pkt, now))
            findings.extend(self._relay_rule(pkt, now))
            findings.extend(self._port_rule(pkt))
        if pkt.dns_qname:
            findings.extend(self._dns_rule(pkt, now))
        return [f for f in findings if self._once(f, now)]

    # -- inventory --------------------------------------------------------

    def _inventory(self, pkt, now: float) -> None:
        ip = pkt.src_ip
        if not ip or ip == "0.0.0.0":
            return
        if ip not in self.hosts and len(self.hosts) >= self.MAX_TRACKED_HOSTS:
            return
        host = self.hosts.setdefault(ip, {
            "ip": ip, "mac": pkt.src_mac, "first_seen": now, "packets": 0,
            "ports": set(), "hostnames": set(),
        })
        host["packets"] += 1
        host["last_seen"] = now
        if pkt.src_mac:
            host["mac"] = pkt.src_mac
        # A SYN-ACK from a host proves it is listening on that port.
        if pkt.proto == "tcp" and (pkt.flags & 0x12) == 0x12 and len(host["ports"]) < 64:
            host["ports"].add(pkt.src_port)
            self.services[ip].add(pkt.src_port)

    def new_hosts(self) -> list[dict]:
        """Hosts observed that were not in the known set at start-up."""
        return [h for ip, h in self.hosts.items() if ip not in self.known_hosts]

    def inventory(self) -> list[dict]:
        return [{
            "ip": h["ip"], "mac": h["mac"], "packets": h["packets"],
            "ports": sorted(h["ports"]),
            "randomised_mac": _is_random_mac(h["mac"]),
        } for h in self.hosts.values()]

    # -- individual rules -------------------------------------------------

    def _scan_rule(self, pkt, now: float) -> list[Finding]:
        if not pkt.is_syn or not pkt.src_ip:
            return []
        ports = self._scan[pkt.src_ip]
        ports[pkt.dst_port] = now
        cutoff = now - self.scan_window
        for port in [p for p, t in ports.items() if t < cutoff]:
            del ports[port]
        if len(ports) >= self.scan_ports:
            detail = {"source": pkt.src_ip, "source_mac": pkt.src_mac,
                      "target": pkt.dst_ip, "distinct_ports": len(ports),
                      "window_seconds": self.scan_window,
                      "sample_ports": sorted(ports)[:20]}
            ports.clear()
            return [Finding("port_scan", 2,
                            f"Port scan from {pkt.src_ip} "
                            f"({detail['distinct_ports']} ports in "
                            f"{self.scan_window}s)", detail)]
        return []

    def _relay_rule(self, pkt, now: float) -> list[Finding]:
        if pkt.dst_port not in RELAY_PORTS or not pkt.is_syn:
            return []
        sources = self._relay[pkt.dst_ip]
        sources[pkt.src_ip] = now
        cutoff = now - self.relay_window
        for src in [s for s, t in sources.items() if t < cutoff]:
            del sources[src]
        if len(sources) >= self.relay_sources:
            detail = {"target": pkt.dst_ip, "port": pkt.dst_port,
                      "distinct_sources": len(sources),
                      "sources": sorted(sources)[:10],
                      "window_seconds": self.relay_window}
            sources.clear()
            return [Finding("smb_relay", 3,
                            f"{detail['distinct_sources']} hosts opened SMB "
                            f"sessions to {pkt.dst_ip} — possible relay or "
                            f"poisoning activity", detail)]
        return []

    def _port_rule(self, pkt) -> list[Finding]:
        note = SUSPICIOUS_PORTS.get(pkt.dst_port)
        if not note or not pkt.is_syn:
            return []
        return [Finding("nonstandard_port", 2,
                        f"Connection attempt to {pkt.dst_ip}:{pkt.dst_port} "
                        f"({note})",
                        {"source": pkt.src_ip, "target": pkt.dst_ip,
                         "port": pkt.dst_port, "note": note})]

    def _arp_rules(self, pkt, now: float) -> list[Finding]:
        if pkt.arp_op != 2 or not pkt.arp_sender_ip:   # replies only
            return []
        known = self._arp.get(pkt.arp_sender_ip)
        self._arp[pkt.arp_sender_ip] = pkt.arp_sender_mac
        if known and known != pkt.arp_sender_mac:
            return [Finding("arp_spoof", 3,
                            f"{pkt.arp_sender_ip} changed MAC "
                            f"{known} -> {pkt.arp_sender_mac}",
                            {"ip": pkt.arp_sender_ip, "previous_mac": known,
                             "new_mac": pkt.arp_sender_mac,
                             "target": pkt.arp_target_ip})]
        return []

    def _dns_rule(self, pkt, now: float) -> list[Finding]:
        longest = max((len(part) for part in pkt.dns_qname.split(".")), default=0)
        if longest < self.dns_min_label:
            return []
        times = self._dns[pkt.src_ip]
        times.append(now)
        cutoff = now - self.dns_window
        while times and times[0] < cutoff:
            times.pop(0)
        if len(times) >= self.dns_queries:
            detail = {"source": pkt.src_ip, "queries": len(times),
                      "window_seconds": self.dns_window,
                      "longest_label": longest,
                      "sample_query": pkt.dns_qname[:120]}
            times.clear()
            return [Finding("dns_tunnel", 2,
                            f"High-volume long-label DNS from {pkt.src_ip} — "
                            f"possible tunnelling", detail)]
        return []

    def _deauth_rule(self, pkt, now: float) -> list[Finding]:
        if pkt.flags != 0xDE:
            return []
        times = self._deauth[pkt.src_mac or "unknown"]
        times.append(now)
        cutoff = now - self.deauth_window
        while times and times[0] < cutoff:
            times.pop(0)
        if len(times) >= self.deauth_count:
            detail = {"source_mac": pkt.src_mac, "target_mac": pkt.dst_mac,
                      "frames": len(times), "window_seconds": self.deauth_window}
            times.clear()
            return [Finding("deauth_flood", 3,
                            f"802.11 deauthentication flood from {pkt.src_mac}",
                            detail)]
        return []

    # -- housekeeping -----------------------------------------------------

    def _once(self, finding: Finding, now: float, cooldown: int = 120) -> bool:
        """Suppress repeats of the same finding within a cooldown window, so
        one noisy scanner does not produce a thousand evidence records."""
        key = (finding.rule, finding.detail.get("source", ""),
               finding.detail.get("target", ""), finding.detail.get("ip", ""))
        last = self._fired.get(key, 0)
        if now - last < cooldown:
            return False
        self._fired[key] = now
        return True

    def _trim(self, now: float) -> None:
        self._last_trim = now
        for store, window in ((self._scan, self.scan_window),
                              (self._relay, self.relay_window)):
            cutoff = now - window
            for key in list(store):
                inner = store[key]
                for k in [k for k, t in inner.items() if t < cutoff]:
                    del inner[k]
                if not inner:
                    del store[key]
            if len(store) > self.MAX_TRACKED_SOURCES:
                store.clear()
        for key in list(self._fired):
            if now - self._fired[key] > 900:
                del self._fired[key]


def _is_random_mac(mac: str) -> bool:
    """Locally-administered bit set — the marker of a privacy-randomised MAC."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False
