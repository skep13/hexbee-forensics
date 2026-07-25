"""BloodHound collector output → Hive findings.

Parses the JSON produced by SharpHound or bloodhound.py (both the legacy
flat-file format and the current zipped bundle) and extracts the four things
that actually drive an internal AD engagement report:

    kerberoastable accounts        (T1558.003)
    AS-REP roastable accounts      (T1558.004)
    unconstrained delegation hosts (T1558)
    Domain Admin group membership  (T1078)

Parsing is offline and streaming-ish: each file in the bundle is read one at
a time, and only matching objects are retained. A large domain's `users.json`
is tens of MB, which is fine on the T470 one file at a time, and would not be
if we held the whole bundle.

The BloodHound *graph* is not reimplemented here. Path-finding is what the
BloodHound UI is for; this bridge captures the findings so they join the
evidence chain and the report.
"""

from __future__ import annotations

import json
import logging
import zipfile
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("hexbee.queen.bloodhound")

DA_GROUP_HINTS = ("DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS",
                  "SCHEMA ADMINS")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iter_documents(target: Path):
    """Yield (filename, parsed json) for every collector file under `target`."""
    if target.is_dir():
        for path in sorted(target.glob("*.json")):
            try:
                yield path.name, json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                log.warning("skipping %s: %s", path.name, exc)
        for path in sorted(target.glob("*.zip")):
            yield from _iter_zip(path)
        return
    if target.suffix.lower() == ".zip":
        yield from _iter_zip(target)
        return
    try:
        yield target.name, json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("skipping %s: %s", target.name, exc)


def _iter_zip(path: Path):
    try:
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if not name.lower().endswith(".json"):
                    continue
                with zf.open(name) as fh:
                    try:
                        yield name, json.load(fh)
                    except json.JSONDecodeError as exc:
                        log.warning("skipping %s in %s: %s", name, path.name, exc)
    except (OSError, zipfile.BadZipFile) as exc:
        log.warning("cannot read %s: %s", path.name, exc)


def _props(obj: dict) -> dict:
    return obj.get("Properties") or obj.get("properties") or {}


def _name(obj: dict) -> str:
    props = _props(obj)
    return (obj.get("Name") or props.get("name") or obj.get("ObjectIdentifier")
            or props.get("distinguishedname") or "")


def parse(target: str | Path) -> dict:
    """Extract findings from a collector directory, zip, or single file."""
    target = Path(target)
    findings = {"kerberoastable": [], "asrep_roastable": [],
                "unconstrained_delegation": [], "domain_admins": [],
                "domains": set(), "counts": {}}

    for filename, doc in _iter_documents(target):
        objects = doc.get("data") or doc.get("nodes") or []
        if not isinstance(objects, list):
            continue
        kind = (doc.get("meta", {}) or {}).get("type", "").lower() or filename.lower()
        findings["counts"][filename] = len(objects)

        for obj in objects:
            if not isinstance(obj, dict):
                continue
            props = _props(obj)
            name = _name(obj)
            domain = props.get("domain") or props.get("domainsid") or ""
            if domain:
                findings["domains"].add(str(domain))

            if "user" in kind:
                spns = props.get("serviceprincipalnames") or props.get("hasspn")
                if spns and props.get("enabled", True):
                    findings["kerberoastable"].append({
                        "account": name, "domain": domain,
                        "spns": spns if isinstance(spns, list) else [],
                        "admin_count": bool(props.get("admincount")),
                        "pwd_last_set": props.get("pwdlastset"),
                    })
                if props.get("dontreqpreauth"):
                    findings["asrep_roastable"].append({
                        "account": name, "domain": domain,
                        "admin_count": bool(props.get("admincount")),
                    })
            if "computer" in kind and props.get("unconstraineddelegation"):
                findings["unconstrained_delegation"].append({
                    "host": name, "domain": domain,
                    "os": props.get("operatingsystem", ""),
                })
            if "group" in kind and any(
                    hint in str(name).upper() for hint in DA_GROUP_HINTS):
                members = obj.get("Members") or obj.get("members") or []
                findings["domain_admins"].append({
                    "group": name, "domain": domain,
                    "member_count": len(members),
                    "members": [m.get("ObjectIdentifier", "") if isinstance(m, dict)
                                else str(m) for m in members[:50]],
                })
    findings["domains"] = sorted(findings["domains"])
    return findings


def to_events(findings: dict, device: str, case_id: int | None = None,
              auth_ref: str = "") -> list[dict]:
    """One event per finding — each carries the discriminator the Hive's
    ATT&CK tagger keys on (`finding`)."""
    events: list[dict] = []
    stamp = _now()

    def ev(payload: dict) -> None:
        events.append({"device": device, "event_type": "ad_recon_finding",
                       "occurred_at": stamp,
                       "payload": payload | {"method": "bloodhound",
                                             "case_id": case_id,
                                             "authorisation": auth_ref}})

    for item in findings["kerberoastable"]:
        ev({"finding": "kerberoastable", "account": item["account"],
            "domain": item["domain"], "spns": item["spns"][:10],
            "privileged": item["admin_count"],
            "summary": f"{item['account']} has an SPN and can be Kerberoasted"})
    for item in findings["asrep_roastable"]:
        ev({"finding": "asrep_roastable", "account": item["account"],
            "domain": item["domain"], "privileged": item["admin_count"],
            "summary": f"{item['account']} does not require Kerberos "
                       f"pre-authentication"})
    for item in findings["unconstrained_delegation"]:
        ev({"finding": "unconstrained_delegation", "host": item["host"],
            "domain": item["domain"], "os": item["os"],
            "summary": f"{item['host']} is trusted for unconstrained "
                       f"delegation"})
    for item in findings["domain_admins"]:
        ev({"finding": "domain_admin_path", "group": item["group"],
            "domain": item["domain"], "member_count": item["member_count"],
            "members": item["members"][:20],
            "summary": f"{item['group']} has {item['member_count']} member(s)"})
    ev({"finding": "collection_summary",
        "domains": findings["domains"],
        "kerberoastable": len(findings["kerberoastable"]),
        "asrep_roastable": len(findings["asrep_roastable"]),
        "unconstrained_delegation": len(findings["unconstrained_delegation"]),
        "privileged_groups": len(findings["domain_admins"]),
        "files": findings["counts"],
        "summary": "BloodHound collection imported"})
    return events


def ingest(client, target: str | Path, *, device: str = "Queen-BloodHound",
           case_id: int | None = None, ingest_key: str | None = None) -> dict:
    findings = parse(target)
    events = to_events(findings, device, case_id)
    stored = 0
    if ingest_key:
        stored = client.ingest(events, ingest_key).get("stored", 0)
    return {
        "kerberoastable": len(findings["kerberoastable"]),
        "asrep_roastable": len(findings["asrep_roastable"]),
        "unconstrained_delegation": len(findings["unconstrained_delegation"]),
        "privileged_groups": len(findings["domain_admins"]),
        "domains": findings["domains"],
        "events": len(events), "stored": stored, "findings": findings,
    }
