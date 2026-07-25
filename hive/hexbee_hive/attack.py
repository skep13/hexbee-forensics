"""Offline MITRE ATT&CK tagging.

Every event that lands in the Hive is checked against a mapping table of
artifact type -> technique. Matches are written to `event_techniques`, which
gives incidents and cases a tactic breakdown for free: the dashboard heatmap
and the engagement report both read from that one table.

Two data sources, both offline:

  1. A built-in mapping (below). It is small, hand-curated, and always
     present, so tagging works on a fresh install with no data files.
  2. Optionally, a real ATT&CK STIX bundle on the HDD
     (`HEXBEE_ATTACK_BUNDLE=/mnt/evidence/enterprise-attack.json`). When the
     file is present, technique *names and tactics* are refreshed from it and
     any technique referenced by a rule but missing from the built-in table is
     filled in. The bundle is parsed once, lazily, and only the fields we need
     are retained — a Pi 3B+ never holds the whole 30 MB document.

Nothing here touches the evidence hash chain. ATT&CK attribution is Hive-side
interpretation and is stored beside the evidence, never inside it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .db import Database

# The 14 enterprise tactics, in kill-chain order. The heatmap renders columns
# in this order, so keep it stable.
TACTICS = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

TACTIC_LABELS = {t: t.replace("-", " ").title() for t in TACTICS}

# technique id -> (name, tactic)
TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1005": ("Data from Local System", "collection"),
    "T1040": ("Network Sniffing", "credential-access"),
    "T1046": ("Network Service Discovery", "discovery"),
    "T1049": ("System Network Connections Discovery", "discovery"),
    "T1053.003": ("Scheduled Task/Job: Cron", "persistence"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "persistence"),
    "T1057": ("Process Discovery", "discovery"),
    "T1059": ("Command and Scripting Interpreter", "execution"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "execution"),
    "T1078": ("Valid Accounts", "defense-evasion"),
    "T1082": ("System Information Discovery", "discovery"),
    "T1083": ("File and Directory Discovery", "discovery"),
    "T1091": ("Replication Through Removable Media", "lateral-movement"),
    "T1098": ("Account Manipulation", "persistence"),
    "T1110": ("Brute Force", "credential-access"),
    "T1113": ("Screen Capture", "collection"),
    "T1136.001": ("Create Account: Local Account", "persistence"),
    "T1200": ("Hardware Additions", "initial-access"),
    "T1204.002": ("User Execution: Malicious File", "execution"),
    "T1498": ("Network Denial of Service", "impact"),
    "T1543.002": ("Create or Modify System Process: Systemd Service", "persistence"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "persistence"),
    "T1546.004": ("Event Triggered Execution: Unix Shell Configuration Modification",
                  "persistence"),
    "T1547.001": ("Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                  "persistence"),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
                  "privilege-escalation"),
    "T1557.001": ("Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay",
                  "credential-access"),
    "T1557.002": ("Adversary-in-the-Middle: ARP Cache Poisoning", "credential-access"),
    "T1558": ("Steal or Forge Kerberos Tickets", "credential-access"),
    "T1558.003": ("Steal or Forge Kerberos Tickets: Kerberoasting", "credential-access"),
    "T1558.004": ("Steal or Forge Kerberos Tickets: AS-REP Roasting", "credential-access"),
    "T1571": ("Non-Standard Port", "command-and-control"),
    "T1595": ("Active Scanning", "reconnaissance"),
    "T1071": ("Application Layer Protocol", "command-and-control"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "command-and-control"),
    "T1027": ("Obfuscated Files or Information", "defense-evasion"),
    "T1518.001": ("Software Discovery: Security Software Discovery", "discovery"),
}

# event_type -> technique ids that always apply.
_BY_TYPE: dict[str, tuple[str, ...]] = {
    "usb_inserted": ("T1200", "T1091"),
    "usb_scan": ("T1091",),
    "usb_device": ("T1200",),
    "usb_new": ("T1200", "T1091"),
    "executable_found": ("T1204.002",),
    "script_found": ("T1059",),
    "autorun_found": ("T1547.001",),
    "powershell_launched": ("T1059.001",),
    "process_launched": ("T1059",),
    "process_snapshot": ("T1057",),
    "process_new": ("T1057",),
    "network_discovered": ("T1049",),
    "network_connection": ("T1049",),
    "network_new": ("T1049",),
    "network_beacon": ("T1071",),
    "host_info": ("T1082",),
    "logon_session": ("T1078",),
    "logon_new": ("T1078",),
    "recent_file": ("T1083",),
    "artifact_web_visit": ("T1071.001",),
    "carved_file": ("T1005",),
    "yara_match": ("T1204.002", "T1027"),
    "credential_capture": ("T1557.001",),
    "recon_finding": ("T1046", "T1595"),
    "wireless_sighting": ("T1040",),
    "hid_deployment": ("T1200", "T1059"),
    "field_photo": ("T1113",),
}

# Sub-mappings driven by a payload discriminator: event_type -> (key, {value: ids}).
_BY_PAYLOAD: dict[str, tuple[str, dict[str, tuple[str, ...]]]] = {
    "persistence_item": ("type", {
        "registry_run": ("T1547.001",),
        "startup_folder": ("T1547.001",),
        "cron": ("T1053.003",),
        "systemd_unit": ("T1543.002",),
        "shell_init": ("T1546.004",),
        "scheduled_task": ("T1053.005",),
        "windows_service": ("T1543.003",),
    }),
    "network_alert": ("rule", {
        "port_scan": ("T1046",),
        "arp_spoof": ("T1557.002",),
        "deauth_flood": ("T1498",),
        "smb_relay": ("T1557.001",),
        "dns_tunnel": ("T1071",),
        "nonstandard_port": ("T1571",),
        "new_host": ("T1046",),
    }),
    "log_anomaly": ("rule", {
        "auth_bruteforce": ("T1110",),
        "privilege_escalation": ("T1548.003",),
        "account_created": ("T1136.001",),
        "account_modified": ("T1098",),
        "service_installed": ("T1543.003",),
        "cron_added": ("T1053.003",),
        "log_cleared": ("T1027",),
        "security_tool_stopped": ("T1518.001",),
    }),
    "ad_recon_finding": ("finding", {
        "kerberoastable": ("T1558.003",),
        "asrep_roastable": ("T1558.004",),
        "unconstrained_delegation": ("T1558",),
        "domain_admin_path": ("T1078",),
    }),
}


# -- optional STIX bundle enrichment --------------------------------------

_BUNDLE_LOADED = False


def load_bundle(path: str | Path | None = None) -> int:
    """Merge technique names/tactics from an offline ATT&CK STIX bundle.

    Returns the number of techniques learned. Safe to call when the file is
    absent or malformed — the built-in table simply stays as-is.
    """
    global _BUNDLE_LOADED
    path = path or os.environ.get("HEXBEE_ATTACK_BUNDLE", "")
    if not path:
        return 0
    p = Path(path)
    if not p.is_file():
        return 0
    try:
        bundle = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, MemoryError):
        return 0
    learned = 0
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked"):
            continue
        tid = next((r.get("external_id") for r in obj.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if not tid:
            continue
        phases = obj.get("kill_chain_phases") or []
        tactic = next((ph.get("phase_name") for ph in phases
                       if ph.get("kill_chain_name") == "mitre-attack"), "")
        if tactic not in TACTICS:
            tactic = TECHNIQUES.get(tid, ("", "discovery"))[1]
        TECHNIQUES[tid] = (obj.get("name", tid), tactic)
        learned += 1
    _BUNDLE_LOADED = True
    return learned


def technique(tid: str) -> dict:
    name, tactic = TECHNIQUES.get(tid, (tid, "discovery"))
    return {"id": tid, "name": name, "tactic": tactic,
            "tactic_label": TACTIC_LABELS.get(tactic, tactic)}


# -- mapping ---------------------------------------------------------------

def map_event(event_type: str, payload: dict | None = None) -> list[str]:
    """Technique ids implied by one event. Order is stable and de-duplicated."""
    payload = payload or {}
    ids: list[str] = list(_BY_TYPE.get(event_type, ()))
    rule = _BY_PAYLOAD.get(event_type)
    if rule:
        key, table = rule
        value = str(payload.get(key, "")).strip().lower()
        ids.extend(table.get(value, ()))
    # Explicit attribution from the producing tool always wins its way in.
    declared = payload.get("attack") or payload.get("technique")
    if isinstance(declared, str):
        declared = [declared]
    if isinstance(declared, list):
        ids.extend(str(t).strip().upper() for t in declared if str(t).strip())
    seen, out = set(), []
    for tid in ids:
        if tid not in seen:
            seen.add(tid)
            out.append(tid)
    return out


def tag_event(db: Database, event_id: int, event_type: str,
              payload: dict | None = None) -> list[str]:
    """Attribute techniques to a stored event. Returns the ids written."""
    ids = map_event(event_type, payload)
    for tid in ids:
        db.execute(
            "INSERT OR IGNORE INTO event_techniques (event_id, technique_id, tactic) "
            "VALUES (?, ?, ?)",
            (event_id, tid, technique(tid)["tactic"]),
        )
    return ids


def backfill(db: Database) -> int:
    """Attribute techniques to every event that has none yet (after an
    upgrade, or once a STIX bundle is added). Returns events tagged."""
    rows = db.query(
        """SELECT e.id, e.event_type, e.payload FROM events e
           WHERE NOT EXISTS (SELECT 1 FROM event_techniques t WHERE t.event_id = e.id)
           ORDER BY e.id"""
    )
    tagged = 0
    for row in rows:
        try:
            payload = json.loads(row["payload"])
        except json.JSONDecodeError:
            payload = {}
        if tag_event(db, row["id"], row["event_type"], payload):
            tagged += 1
    return tagged


# -- aggregation for the heatmap and reports ------------------------------

def _coverage(db: Database, where: str, params: tuple) -> dict:
    rows = db.query(
        f"""SELECT t.technique_id, t.tactic, COUNT(*) AS n
            FROM event_techniques t JOIN events e ON e.id = t.event_id
            {where}
            GROUP BY t.technique_id, t.tactic
            ORDER BY n DESC""",
        params,
    )
    by_tactic: dict[str, list[dict]] = {t: [] for t in TACTICS}
    total = 0
    for r in rows:
        total += r["n"]
        entry = technique(r["technique_id"]) | {"count": r["n"]}
        by_tactic.setdefault(r["tactic"], []).append(entry)
    return {
        "tactics": [
            {"tactic": t, "label": TACTIC_LABELS.get(t, t),
             "techniques": by_tactic.get(t, []),
             "events": sum(x["count"] for x in by_tactic.get(t, []))}
            for t in TACTICS
        ],
        "total_attributions": total,
        "distinct_techniques": len(rows),
    }


def case_coverage(db: Database, case_id: int) -> dict:
    return _coverage(
        db,
        "JOIN incidents i ON i.id = e.incident_id WHERE i.case_id = ?",
        (case_id,),
    )


def incident_coverage(db: Database, incident_id: int) -> dict:
    return _coverage(db, "WHERE e.incident_id = ?", (incident_id,))


def global_coverage(db: Database) -> dict:
    return _coverage(db, "", ())


def event_techniques(db: Database, event_id: int) -> list[dict]:
    rows = db.query(
        "SELECT technique_id FROM event_techniques WHERE event_id = ? ORDER BY technique_id",
        (event_id,))
    return [technique(r["technique_id"]) for r in rows]
