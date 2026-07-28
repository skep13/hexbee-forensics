"""nmap wrapper — scope-gated service discovery that lands in the case.

Everything nmap finds becomes a `recon_finding` event in the Hive's evidence
chain, correlated and IOC-matched like any other artifact. Recon and incident
data end up in one timeline, which is the whole point: the same case shows
what you did and what you found.

The scope gate runs **before** nmap is invoked, target by target. A refused
target is never passed to the binary.
"""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from .pkghint import install_hint

PROFILES = {
    # name: (nmap args, description)
    "quick": (["-T4", "-F"], "top 100 ports, fast"),
    "sweep": (["-T4", "-sV", "--version-intensity", "5"],
              "full service/version scan"),
    "vuln": (["-T4", "-sV", "--script", "vuln"],
             "service scan plus nmap vuln scripts"),
    "discover": (["-sn"], "host discovery only, no port scan"),
}


def available() -> str | None:
    return shutil.which("nmap")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def expand_targets(spec: str, max_hosts: int = 1024) -> list[str]:
    """Expand a CIDR or single target into individual addresses.

    Expansion is what makes per-host scope checking possible: `10.0.0.0/24`
    is checked as 254 separate authorisations, so a partially-authorised
    range scans only the authorised part instead of being refused wholesale.
    """
    spec = spec.strip()
    try:
        network = ipaddress.ip_network(spec, strict=False)
    except ValueError:
        return [spec]                      # hostname or nmap-specific syntax
    if network.num_addresses > max_hosts:
        raise ValueError(f"{spec} expands to {network.num_addresses} hosts "
                         f"(limit {max_hosts}) — narrow the range")
    if network.num_addresses <= 2:
        return [str(network.network_address)]
    return [str(ip) for ip in network.hosts()]


def run_nmap(targets: list[str], profile: str = "quick",
             extra_args: list[str] | None = None,
             timeout: int = 1800) -> tuple[str, str]:
    """Run nmap with XML output. Returns (xml, command line)."""
    binary = available()
    if binary is None:
        raise RuntimeError(f"nmap is not installed — {install_hint('nmap')}")
    if profile not in PROFILES:
        raise ValueError(f"profile must be one of {tuple(PROFILES)}")
    args = [binary, *PROFILES[profile][0], *(extra_args or []),
            "-oX", "-", *targets]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"nmap failed: {(proc.stderr or '').strip()[:300]}")
    return proc.stdout, " ".join(args)


def parse_xml(xml_text: str) -> list[dict]:
    """Hosts, ports, services and versions out of nmap XML."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"unparseable nmap XML: {exc}") from exc

    hosts = []
    for host in root.findall("host"):
        state = host.find("status")
        if state is not None and state.get("state") != "up":
            continue
        addresses = {a.get("addrtype"): a.get("addr")
                     for a in host.findall("address")}
        vendor = next((a.get("vendor") for a in host.findall("address")
                       if a.get("vendor")), "")
        names = [h.get("name") for h in host.findall("hostnames/hostname")
                 if h.get("name")]
        os_match = host.find("os/osmatch")

        ports = []
        for port in host.findall("ports/port"):
            port_state = port.find("state")
            if port_state is None or port_state.get("state") != "open":
                continue
            service = port.find("service")
            scripts = {s.get("id"): (s.get("output") or "")[:400]
                       for s in port.findall("script")}
            ports.append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "service": service.get("name") if service is not None else "",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
                "extra": service.get("extrainfo", "") if service is not None else "",
                "scripts": scripts,
            })
        hosts.append({
            "ip": addresses.get("ipv4") or addresses.get("ipv6") or "",
            "mac": addresses.get("mac", ""),
            "vendor": vendor,
            "hostnames": names,
            "os": os_match.get("name") if os_match is not None else "",
            "os_accuracy": int(os_match.get("accuracy", 0)) if os_match is not None else 0,
            "ports": ports,
        })
    return hosts


def to_events(hosts: list[dict], device: str, profile: str,
              command: str, case_id: int | None = None,
              auth_ref: str = "") -> list[dict]:
    """One event per host plus one per open service, and a sweep summary.

    Per-service granularity matters because the IOC engine and the ATT&CK
    tagger both work on individual events — a version string matching a known
    vulnerable build should raise its own finding.
    """
    events: list[dict] = []
    stamp = _now()

    def ev(payload: dict) -> None:
        events.append({"device": device, "event_type": "recon_finding",
                       "occurred_at": stamp,
                       "payload": payload | {"method": "nmap",
                                             "profile": profile,
                                             "authorisation": auth_ref,
                                             "case_id": case_id}})

    total_ports = 0
    for host in hosts:
        ev({"finding": "host_up", "ip": host["ip"], "mac": host["mac"],
            "vendor": host["vendor"], "hostnames": host["hostnames"],
            "os": host["os"], "os_accuracy": host["os_accuracy"],
            "open_ports": [p["port"] for p in host["ports"]]})
        for port in host["ports"]:
            total_ports += 1
            banner = " ".join(x for x in (port["product"], port["version"],
                                          port["extra"]) if x).strip()
            payload = {
                "finding": "service", "ip": host["ip"], "port": port["port"],
                "protocol": port["protocol"], "service": port["service"],
                "product": port["product"], "version": port["version"],
                "banner": banner,
            }
            vuln_scripts = {k: v for k, v in port["scripts"].items()
                            if "vuln" in k or "CVE" in v.upper()}
            if vuln_scripts:
                payload["finding"] = "vulnerability"
                payload["scripts"] = vuln_scripts
            ev(payload)
    ev({"finding": "sweep_summary", "hosts_up": len(hosts),
        "open_ports": total_ports, "command": command[:500]})
    return events


def scan(client, target_spec: str, *, profile: str = "quick",
         device: str = "Queen-Recon", case_id: int | None = None,
         ingest_key: str | None = None, extra_args: list[str] | None = None,
         dry_run: bool = False) -> dict:
    """Scope-check, scan, parse, and push findings into the Hive."""
    from .scope import guard

    targets = expand_targets(target_spec)
    allowed, refused = [], []
    auth_refs = set()
    for target in targets:
        decision = guard(client, target, tool="hexbee-recon", case_id=case_id,
                         extra={"profile": profile}, quiet=len(targets) > 8)
        if decision:
            allowed.append(target)
            if decision.auth_ref:
                auth_refs.add(decision.auth_ref)
        else:
            refused.append(target)

    if not allowed:
        return {"ok": False, "scanned": 0, "refused": len(refused),
                "reason": "every target was out of scope"}
    if dry_run:
        return {"ok": True, "dry_run": True, "would_scan": allowed,
                "refused": len(refused)}

    xml_text, command = run_nmap(allowed, profile, extra_args)
    hosts = parse_xml(xml_text)
    events = to_events(hosts, device, profile, command, case_id,
                       ", ".join(sorted(auth_refs)))
    stored = 0
    if ingest_key:
        stored = client.ingest(events, ingest_key).get("stored", 0)
    return {"ok": True, "scanned": len(allowed), "refused": len(refused),
            "hosts_up": len(hosts),
            "services": sum(len(h["ports"]) for h in hosts),
            "events": len(events), "stored": stored, "hosts": hosts,
            "command": command}
