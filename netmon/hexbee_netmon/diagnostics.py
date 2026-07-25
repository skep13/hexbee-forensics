"""Network diagnostics mode.

The only mode that transmits. Every check is an ordinary operational probe
(ping, DNS resolution, traceroute, reading the local ARP table) aimed at the
host's own gateway and resolvers, so it is safe to run on any network you are
already attached to.

Findings become `network_alert` events with a `rule` key, exactly like the IDS
rules, so they thread through the same correlation and ATT&CK path.
"""

from __future__ import annotations

import platform
import re
import socket
import subprocess
import time

IS_WINDOWS = platform.system() == "Windows"


def _run(cmd: list[str], timeout: int = 20) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, errors="ignore")
        return (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return ""


def default_gateway() -> str:
    """The IPv4 default gateway, read from the routing table."""
    if IS_WINDOWS:
        out = _run(["route", "print", "0.0.0.0"])
        m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else ""
    out = _run(["ip", "route", "show", "default"])
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
    if m:
        return m.group(1)
    out = _run(["netstat", "-rn"])
    m = re.search(r"^(?:default|0\.0\.0\.0)\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)
    return m.group(1) if m else ""


def resolvers() -> list[str]:
    if IS_WINDOWS:
        out = _run(["ipconfig", "/all"])
        return re.findall(r"DNS Servers[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", out)[:3]
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            return [line.split()[1] for line in fh
                    if line.startswith("nameserver") and len(line.split()) > 1][:3]
    except OSError:
        return []


def ping(host: str, count: int = 4, timeout: int = 15) -> dict:
    """Round-trip stats for one host. Empty rtts means unreachable."""
    if not host:
        return {"host": host, "reachable": False, "rtts_ms": [], "loss_pct": 100.0}
    cmd = (["ping", "-n", str(count), "-w", "1000", host] if IS_WINDOWS
           else ["ping", "-c", str(count), "-W", "1", host])
    out = _run(cmd, timeout=timeout)
    rtts = [float(v) for v in re.findall(r"time[=<]\s*([\d.]+)\s*ms", out)]
    loss = re.search(r"([\d.]+)%\s*(?:packet\s*)?loss", out)
    return {
        "host": host,
        "reachable": bool(rtts),
        "rtts_ms": rtts,
        "avg_ms": round(sum(rtts) / len(rtts), 2) if rtts else None,
        "max_ms": max(rtts) if rtts else None,
        "loss_pct": float(loss.group(1)) if loss else (0.0 if rtts else 100.0),
    }


def dns_health(names: tuple[str, ...] = ("localhost",)) -> list[dict]:
    """Resolution latency per name. Uses the host resolver, so it reflects
    exactly what applications on this box experience."""
    out = []
    for name in names:
        start = time.perf_counter()
        try:
            addrs = sorted({r[4][0] for r in socket.getaddrinfo(name, None)})
            ok = True
        except socket.gaierror as exc:
            addrs, ok = [str(exc)], False
        out.append({"name": name, "ok": ok,
                    "ms": round((time.perf_counter() - start) * 1000, 1),
                    "addresses": addrs[:4]})
    return out


def route_trace(target: str, max_hops: int = 12) -> list[str]:
    if not target:
        return []
    cmd = (["tracert", "-d", "-h", str(max_hops), "-w", "800", target]
           if IS_WINDOWS else
           ["traceroute", "-n", "-m", str(max_hops), "-w", "1", target])
    out = _run(cmd, timeout=60)
    return [line.strip() for line in out.splitlines()[1:] if line.strip()][:max_hops]


def arp_table() -> list[dict]:
    out = _run(["arp", "-a"]) or _run(["ip", "neigh"])
    entries = []
    for line in out.splitlines():
        ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
        if ip and mac:
            entries.append({"ip": ip.group(1), "mac": mac.group(0).lower().replace("-", ":")})
    return entries


def arp_anomalies(entries: list[dict]) -> list[dict]:
    """One MAC claiming several IPs is the classic signature of a machine
    doing ARP poisoning (or, benignly, a router doing proxy ARP)."""
    by_mac: dict[str, list[str]] = {}
    for e in entries:
        by_mac.setdefault(e["mac"], []).append(e["ip"])
    return [{"mac": mac, "ips": ips} for mac, ips in by_mac.items() if len(ips) > 2]


def snapshot(targets: tuple[str, ...] = ()) -> tuple[dict, list[dict]]:
    """Run every diagnostic. Returns (snapshot payload, alert payloads)."""
    gw = default_gateway()
    dns_servers = resolvers()
    gw_ping = ping(gw) if gw else {"host": "", "reachable": False, "loss_pct": 100.0}
    dns_pings = [ping(s, count=2) for s in dns_servers]
    names = ("localhost",) + tuple(targets)
    dns = dns_health(names)
    arp = arp_table()
    anomalies = arp_anomalies(arp)

    payload = {
        "gateway": gw,
        "gateway_ping": gw_ping,
        "resolvers": dns_servers,
        "resolver_pings": dns_pings,
        "dns_health": dns,
        "arp_entries": len(arp),
        "route_hops": len(route_trace(gw)) if gw else 0,
    }

    alerts = []
    if gw and not gw_ping["reachable"]:
        alerts.append({"rule": "gateway_unreachable", "severity": 3,
                       "summary": f"Default gateway {gw} did not respond to ping",
                       "gateway": gw})
    elif gw_ping.get("avg_ms") and gw_ping["avg_ms"] > 50:
        alerts.append({"rule": "gateway_latency", "severity": 2,
                       "summary": f"Gateway latency {gw_ping['avg_ms']} ms "
                                  f"(loss {gw_ping['loss_pct']}%)",
                       "gateway": gw, "avg_ms": gw_ping["avg_ms"]})
    for check in dns:
        if not check["ok"]:
            alerts.append({"rule": "dns_failure", "severity": 2,
                           "summary": f"DNS resolution failed for {check['name']}",
                           "name": check["name"]})
        elif check["ms"] > 500:
            alerts.append({"rule": "dns_slow", "severity": 1,
                           "summary": f"DNS resolution for {check['name']} took "
                                      f"{check['ms']} ms",
                           "name": check["name"], "ms": check["ms"]})
    for anomaly in anomalies:
        alerts.append({"rule": "arp_anomaly", "severity": 2,
                       "summary": f"MAC {anomaly['mac']} claims "
                                  f"{len(anomaly['ips'])} IP addresses",
                       "mac": anomaly["mac"], "ips": anomaly["ips"][:10]})
    return payload, alerts
