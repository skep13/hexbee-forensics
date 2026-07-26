"""The HexBee operator's manual, in a form a small local model can use.

Hive Mind runs a 1–3B model on a laptop with 8 GB of RAM. A model that size
cannot be *told* how HexBee works in a system prompt and cannot be trusted to
remember it — ask an ungrounded 3B "how do I seal a case" and it will invent a
plausible command that does not exist. Inventing commands is worse than
refusing, because the operator will try them.

So the model is never asked to recall anything. It is handed the exact
reference material for the question and told to answer only from that.

Two kinds of knowledge live here:

**Extracted** — generated from the running code, so it cannot go stale. Event
types and their severities come from `normalize.EVENT_SEVERITY`, technique
mappings from `attack`, CLI commands by walking the argparse tree, API routes
from the Flask app. If someone adds an event type and forgets the docs, this
still knows about it.

**Curated** — the task recipes below. "How do I start an engagement" is not
derivable from code; it is a sequence a person decided on. These are written
once and reviewed like any other source.

Retrieval is BM25 over that corpus — no embedding model, no vector store, no
extra resident memory, and deterministic results you can debug. For a corpus
of a hundred short documents it is competitive with embeddings and costs
nothing, which is the right trade on this hardware.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path

# Where `scripts/build_knowledge.py` writes the CLI snapshot for components
# the Hive cannot import (Queen, Comb, Forager, Netmon are separate packages).
SNAPSHOT = Path(__file__).parent / "knowledge_commands.json"


@dataclass
class Doc:
    """One retrievable unit of manual."""

    id: str
    title: str
    body: str
    kind: str = "reference"          # recipe | command | reference | concept
    commands: list[str] = field(default_factory=list)
    source: str = "curated"
    keywords: list[str] = field(default_factory=list)

    def render(self) -> str:
        out = [f"## {self.title}", self.body.strip()]
        if self.commands:
            out.append("Commands:")
            out.extend(f"    {c}" for c in self.commands)
        return "\n".join(out)


# How strongly each kind of document is preferred when scores are close.
# Curated recipes are the answers a person wrote for a question a person asks;
# auto-extracted command docs are supporting detail. Without this weighting the
# command docs win on length normalisation alone — they are one line long — and
# the operator gets a flag list instead of a procedure.
# Workflows sit just below recipes on purpose. Both answer usage questions,
# but a workflow is a whole procedure and a recipe is one task — so "what
# command exports a bundle" should get the command, while "I need to hand
# evidence to someone" gets the procedure. The keywords carry situation
# phrasing to the workflows; this weighting keeps precise questions precise.
KIND_WEIGHT = {"recipe": 1.7, "workflow": 1.6, "concept": 1.45,
               "reference": 1.25, "command": 1.0}

# Only these kinds decide whether a question is about *using HexBee* at all.
# Command docs are full of ordinary words ("host", "found", "device"), so
# letting them vote sends evidence questions to the manual.
ROUTING_KINDS = ("recipe", "workflow", "concept")

# Operator vocabulary that does not appear in the text it should match.
# Keeping the aliases in one table rather than scattered through the recipes
# makes the synonym coverage reviewable in one place.
KEYWORDS: dict[str, list[str]] = {
    "recipe-triage-usb": ["usb stick", "scan usb", "scan a stick", "thumb drive",
                          "flash drive", "disk image", "seized media",
                          "mount image", "dd image", "examine drive",
                          "analyse disk", "analyze disk", "inspect drive"],
    # "handing evidence over" belongs to the wf-handover workflow, which walks
    # the whole procedure; this recipe is the single export command.
    "recipe-export-bundle": ["export bundle", "signed bundle",
                             "chain of custody export"],
    "recipe-start-engagement": ["authorise", "authorize", "authorisation",
                                "in scope", "add scope", "target range",
                                "permission to test", "rules of engagement",
                                "begin engagement", "new engagement"],
    "recipe-report": ["pentest report", "client report", "engagement report",
                      "deliverable", "final report", "write up findings",
                      "pdf report"],
    "recipe-case-report": ["case report", "forensic report", "evidence report",
                           "csv export", "json export"],
    "recipe-netmon": ["passive monitoring", "network monitoring", "sniff",
                      "packet capture", "ids", "intrusion detection",
                      "watch traffic", "pcap", "arp spoofing", "port scan"],
    "recipe-stinger-scan": ["esp32", "c3", "wireless scanner", "wifi scan",
                            "bluetooth", "ble", "beacon", "passive recon"],
    "recipe-stinger-hid": ["badusb", "rubber ducky", "duckyscript", "keystroke",
                           "hid", "stinger", "payload", "bluetooth keyboard",
                           "ble hid", "keystroke injection"],
    "recipe-stinger-portal": ["rogue ap", "evil twin", "captive portal",
                              "fake wifi", "harvest credentials",
                              "phishing portal", "credential harvest"],
    "recipe-seal": ["witness", "seal evidence", "close case formally",
                    "tamper", "anchor case", "sign off"],
    "recipe-memory": ["ram dump", "memory dump", "volatility", "lime",
                      "winpmem", "capture ram", "memory image"],
    "recipe-diagnostics": ["health", "smart", "temperature", "disk full",
                           "monitoring", "it support", "troubleshoot machine"],
    "recipe-forager-collect": ["live response", "triage a host", "running host",
                               "processes", "autoruns", "collect artifacts"],
    # Deliberately avoids the bare phrase "usb stick" — that belongs to
    # recipe-triage-usb, which is what someone means by "scan a USB stick".
    "recipe-forager-usb": ["run agent from usb", "no python on target",
                           "standalone exe", "portable collector",
                           "triage stick", "forager exe"],
    "recipe-ai-setup": ["ollama", "local model", "llm", "hive mind", "assistant",
                        "ai setup", "which model"],
    "recipe-intel": ["threat feeds", "abuse.ch", "urlhaus", "malwarebazaar",
                     "misp", "download feeds", "before deployment"],
    "recipe-verify-chain": ["integrity", "tamper", "prove", "hash chain",
                            "verify evidence", "anchor"],
    "recipe-search": ["find", "look for", "query evidence", "filter events"],
    "recipe-offline-content": ["maps", "mbtiles", "wikipedia", "zim",
                               "reference library"],
    "recipe-start-hive": ["first run", "initial setup", "install", "bootstrap",
                          "create user", "get started"],
    "recipe-connect-queen": ["log in", "login", "connect", "session"],
    "recipe-pivot": ["drop box", "dropbox", "reverse ssh", "tunnel", "autossh",
                     "remote access", "call home"],
    "recipe-syslog": ["logs", "log collection", "siem", "event log",
                      "windows events", "forward logs"],
    "concept-roles": ["viewer", "investigator", "administrator", "permissions",
                      "who can", "access control", "privileges"],
    "concept-offline": ["offline", "no internet", "air gapped", "airgap",
                        "disconnected", "without network", "field use",
                        "work offline", "needs internet"],
    # Deliberately avoids generic phrasings like "how does it work" — those
    # tokens match any question and stole "does this work offline".
    "concept-evidence-chain": ["hash chain", "chain of custody",
                               "tamper evident", "append only", "integrity",
                               "evidence log"],
    "concept-scope": ["why was i blocked", "refused", "denied", "fails closed",
                      "why can't i scan"],
    "concept-modes": ["ir mode", "pentest mode", "diagnostics mode",
                      "case mode", "switch mode"],
    "ref-config": ["environment variable", "env var", "setting", "configure",
                   "HEXBEE_", "export variable"],
    "ref-event-types": ["event type", "severity", "what severity",
                        "which events", "event list"],
    "ref-attack-map": ["mitre", "att&ck", "attack technique", "tactic",
                       "which technique", "what technique", "maps to",
                       "technique for", "t1"],
    "recipe-iocs": ["indicator", "watchlist", "known bad", "hash lookup"],
    "recipe-yara": ["malware detection", "signature", "rules", "detect malware"],
    "recipe-recon": ["nmap", "port scan", "service scan", "enumerate hosts",
                     "scan network"],
    "recipe-responder": ["ntlm", "hashes", "poisoning", "llmnr", "relay",
                         "credential capture"],
    "recipe-bloodhound": ["active directory", "domain", "kerberoast",
                          "sharphound", "ad recon"],
    "recipe-attack-coverage": ["coverage", "heatmap", "which tactics",
                               "backfill techniques"],
    "recipe-check-scope": ["is it in scope", "allowed to scan", "can i test"],
    "recipe-scope-window": ["time window", "testing hours", "only during"],
    "troubleshoot-no-model": ["model not found", "ai not working",
                              "assistant unavailable", "ollama not reachable"],
    "troubleshoot-ingest-refused": ["401", "403", "bad ingest key",
                                    "ingest disabled", "cannot upload"],
    "troubleshoot-capture-permission": ["permission denied", "operation not "
                                        "permitted", "cannot capture", "setcap"],
}


# =========================================================================
# Curated task recipes
#
# These are the questions an operator actually asks, with the exact commands.
# Keep them task-shaped ("how do I ...") rather than feature-shaped — the
# retrieval works on the operator's words, not ours.
# =========================================================================

RECIPES: list[Doc] = [
    Doc(
        id="recipe-start-engagement",
        title="Start an authorised pentest engagement",
        kind="recipe",
        body=(
            "Before any active tool will fire, the target must be inside the "
            "engagement scope. HexBee fails closed: with no scope rules "
            "defined, every active tool refuses. Create the case, set it to "
            "pentest mode, then authorise the ranges with the client's "
            "authorisation reference."
        ),
        commands=[
            'hexbee-queen case new "Client engagement" -d "Authorised assessment"',
            "hexbee-queen mode <case_id> pentest",
            "hexbee-queen scope add cidr 10.10.0.0/24 --auth-ref SOW-2026-14",
            "hexbee-queen scope add domain client.test --auth-ref SOW-2026-14",
            "hexbee-queen scope list",
        ],
    ),
    Doc(
        id="recipe-scope-window",
        title="Authorise a target only during an agreed time window",
        kind="recipe",
        body=(
            "Scope rules take optional UTC start and end times. Outside the "
            "window the rule matches but does not authorise, and the refusal "
            "says so. Use this when the client has agreed specific testing "
            "hours."
        ),
        commands=[
            "hexbee-queen scope add cidr 10.10.0.0/24 --auth-ref SOW-2026-14 "
            "--starts 2026-08-01T09:00:00Z --ends 2026-08-05T18:00:00Z",
            "hexbee-queen scope check 10.10.0.5",
        ],
    ),
    Doc(
        id="recipe-check-scope",
        title="Check whether a target is in scope before acting",
        kind="recipe",
        body=(
            "Ask the Hive directly. Exit status is 0 when in scope and 2 when "
            "not, so this is safe to use in a shell guard. A refusal from an "
            "actual tool is also recorded in the evidence chain as a "
            "scope_violation event — blocked attempts are evidence that you "
            "stayed inside the authorisation."
        ),
        commands=[
            "hexbee-queen scope check 10.10.0.5",
            "hexbee-hive scope check 10.10.0.5",
        ],
    ),
    Doc(
        id="recipe-recon",
        title="Run a port and service scan into a case",
        kind="recipe",
        body=(
            "hexbee-queen recon wraps nmap and checks scope per host before "
            "the binary is invoked, so a partially-authorised range scans only "
            "its authorised part. Findings land in the evidence chain as "
            "recon_finding events, one per host and one per open service. "
            "Profiles: quick (top 100 ports), sweep (service versions), vuln "
            "(nmap vuln scripts), discover (host discovery only). Use "
            "--dry-run to resolve scope without scanning."
        ),
        commands=[
            "hexbee-queen recon quick 10.10.0.0/24 --case 1",
            "hexbee-queen recon sweep 10.10.0.5 --case 1",
            "hexbee-queen recon vuln 10.10.0.5 --case 1",
            "hexbee-queen recon quick 10.10.0.0/24 --dry-run",
        ],
    ),
    Doc(
        id="recipe-responder",
        title="Capture credentials with Responder into the evidence chain",
        kind="recipe",
        body=(
            "Run Responder yourself, then point the bridge at its Logs "
            "directory. Each capture becomes a credential_capture event. By "
            "default only a SHA-256 fingerprint of the hash is stored, not the "
            "hash itself — pass --include-material if your rules of engagement "
            "require the full material, and that choice is recorded in the "
            "event. --watch follows continuously and skips captures that were "
            "already on disk when it started."
        ),
        commands=[
            "hexbee-queen responder --watch --case 1",
            "hexbee-queen responder --log-dir /usr/share/responder/logs --case 1",
            "hexbee-queen responder --watch --case 1 --include-material",
        ],
    ),
    Doc(
        id="recipe-bloodhound",
        title="Import BloodHound Active Directory findings",
        kind="recipe",
        body=(
            "Run SharpHound or bloodhound.py against the domain yourself, then "
            "import the output — a zip bundle, a directory, or a single JSON "
            "file. Extracts kerberoastable accounts, AS-REP roastable "
            "accounts, unconstrained delegation hosts, and privileged group "
            "membership as ad_recon_finding events. Path-finding is not "
            "reimplemented; use the BloodHound UI for graphs."
        ),
        commands=[
            "hexbee-queen bloodhound ./20260725_bloodhound.zip --case 1",
            "hexbee-queen bloodhound ./collection_dir/ --case 1",
        ],
    ),
    Doc(
        id="recipe-report",
        title="Produce the client engagement report",
        kind="recipe",
        body=(
            "Pulls every event in the case, groups them into findings, maps "
            "them to ATT&CK tactics, and renders a standalone HTML report. "
            "Hive Mind drafts a paragraph per finding group when a local model "
            "is running; without one, deterministic text is used and the "
            "report is still produced. --pdf runs it through wkhtmltopdf. "
            "Preview it in the dashboard first at /cases/<id>/preview."
        ),
        commands=[
            "hexbee-queen engagement report 1 -o HB-2026-0001.html",
            "hexbee-queen engagement report 1 -o HB-2026-0001.html --pdf",
            "hexbee-queen engagement report 1 -o report.html --no-ai",
        ],
    ),
    Doc(
        id="recipe-case-report",
        title="Export a case report in HTML, JSON, or CSV",
        kind="recipe",
        body=(
            "The case report is the forensic record — evidence, timeline, "
            "notes, chain status. Distinct from the engagement report, which "
            "is the client-facing pentest deliverable."
        ),
        commands=[
            "hexbee-queen report 1 -f html -o case1.html",
            "hexbee-queen report 1 -f json -o case1.json",
            "hexbee-hive report 1 --format csv -o case1.csv",
        ],
    ),
    Doc(
        id="recipe-triage-usb",
        title="Triage a seized USB stick or disk image",
        kind="recipe",
        body=(
            "Comb scans a mounted filesystem or an extraction directory — it "
            "never mounts anything itself. On Linux, loop-mount read-only "
            "first. Add --hive and --key to push findings into the evidence "
            "chain. YARA runs automatically when yara-python and a ruleset are "
            "present."
        ),
        commands=[
            "sudo mount -o ro,loop,offset=$((512*2048)) /evidence/disk.dd /mnt/evidence",
            "hexbee-comb scan /mnt/evidence -o report.html",
            "hexbee-comb scan /mnt/evidence --hive http://hive.local:8080 --key $HEXBEE_INGEST_KEY",
            "hexbee-comb partitions /evidence/disk.dd",
            "hexbee-comb carve /evidence/disk.dd /cases/carved",
            "hexbee-comb serve",
        ],
    ),
    Doc(
        id="recipe-yara",
        title="Set up and run YARA malware detection in Comb",
        kind="recipe",
        body=(
            "YARA is optional. Put a rule bundle on the external HDD and point "
            "HEXBEE_YARA_RULES at it. Rules compile once per scan, not per "
            "file. Matches become yara_match events at severity 3. Only "
            "matched string identifiers are recorded, never matched bytes."
        ),
        commands=[
            "pip install 'hexbee-comb[yara]'",
            "export HEXBEE_YARA_RULES=/mnt/evidence/yara",
            "hexbee-comb yara",
            "hexbee-comb scan /mnt/evidence --yara-rules /mnt/evidence/yara",
            "hexbee-comb scan /mnt/evidence --no-yara",
        ],
    ),
    Doc(
        id="recipe-forager-collect",
        title="Collect live-response artifacts from a running host",
        kind="recipe",
        body=(
            "Forager is read-only: it inspects the host, it never modifies it. "
            "Collects processes, network connections, logons, autoruns, USB "
            "history, and recent files. With no Hive reachable it spools to "
            "disk and flushes on the next successful contact."
        ),
        commands=[
            "hexbee-forager config --hive http://hive.local:8080 --key $HEXBEE_INGEST_KEY",
            "hexbee-forager collect",
            "hexbee-forager collect -o run.json",
            "hexbee-forager watch --interval 60",
            "hexbee-forager status",
        ],
    ),
    Doc(
        id="recipe-forager-usb",
        title="Run Forager from a USB stick on a target with no Python",
        kind="recipe",
        body=(
            "Build a standalone executable, carry it on the stick, capture to "
            "the stick, then submit later from a networked machine. The spool "
            "defaults to sitting beside the executable so no evidence is left "
            "on the target's own disk."
        ),
        commands=[
            "powershell -File forager\\usb\\build_windows.ps1",
            "RUN-WINDOWS.bat",
            "hexbee-forager submit collections/*.json --hive http://hive.local:8080 --key KEY",
        ],
    ),
    Doc(
        id="recipe-diagnostics",
        title="Monitor machine health instead of collecting forensics",
        kind="recipe",
        body=(
            "Diagnostics mode swaps Forager's collector set for health "
            "checks — SMART, CPU temperature, RAM and swap pressure, disk "
            "fill, failed services, top consumers. Readings are "
            "diagnostic_snapshot events; threshold crossings are "
            "diagnostic_alert. Deliberately mapped to no ATT&CK technique: a "
            "full disk is not adversary behaviour."
        ),
        commands=[
            "hexbee-forager collect --mode diagnostics",
            "hexbee-forager watch --mode diagnostics --interval 300",
            "hexbee-netmon check",
            "hexbee-netmon run --mode diagnostics --interval 300",
        ],
    ),
    Doc(
        id="recipe-memory",
        title="Acquire physical memory from a target",
        kind="recipe",
        body=(
            "Point it at the external HDD, never the target's own disk. Free "
            "space is checked before acquisition starts. The image is written "
            "by LiME or winpmem and hashed back in 8 MB chunks, so a dump "
            "larger than your RAM still works. Only the path, size, and "
            "SHA-256 enter the chain. This is the one Forager operation that "
            "is not strictly read-only — it loads a kernel driver on the "
            "target. Analyse with Volatility afterwards on the Queen, not "
            "here."
        ),
        commands=[
            "hexbee-forager memory --status",
            "hexbee-forager memory /mnt/evidence --dry-run",
            "hexbee-forager memory /mnt/evidence --case 3 --note 'front desk PC'",
            "vol -f /mnt/evidence/HOST_20260725T101500Z_memory.raw windows.pslist",
        ],
    ),
    Doc(
        id="recipe-netmon",
        title="Watch the network passively from the Hive host",
        kind="recipe",
        body=(
            "ids and recon are receive-only; diagnostics transmits ordinary "
            "probes. Raw capture needs CAP_NET_RAW — grant it once with setcap "
            "rather than running as root. Detects port scans, ARP spoofing, "
            "SMB relay, DNS tunnelling, suspicious destination ports, and "
            "802.11 deauth floods. --pcap streams frames to the HDD with "
            "rotation."
        ),
        commands=[
            "sudo setcap cap_net_raw,cap_net_admin=eip \"$(readlink -f \"$(which python3)\")\"",
            "hexbee-netmon config --hive http://127.0.0.1:8080 --key $HEXBEE_INGEST_KEY",
            "hexbee-netmon run --mode ids --iface eth0",
            "hexbee-netmon run --mode recon --iface eth0 --duration 300",
            "hexbee-netmon run --mode ids --pcap /mnt/evidence/capture.pcap",
            "hexbee-netmon status",
        ],
    ),
    Doc(
        id="recipe-syslog",
        title="Collect logs from other machines and detect anomalies",
        kind="recipe",
        body=(
            "The Hive listens for syslog over UDP and accepts JSON from a "
            "Windows Event Log forwarder. Only findings are stored — raw log "
            "lines never enter the database, which is what stops a chatty "
            "network filling the Pi's SD card. Port 514 needs privileges; use "
            "5514 instead if you would rather not grant them."
        ),
        commands=[
            "hexbee-hive syslog --port 5514",
            "sudo setcap cap_net_bind_service=+ep \"$(readlink -f \"$(which python3)\")\"",
            "hexbee-hive syslog --port 514",
        ],
    ),
    Doc(
        id="recipe-intel",
        title="Load threat intelligence before going into the field",
        kind="recipe",
        body=(
            "sync-intel is the only Hive command that touches the internet. "
            "Run it at home before deployment. Feeds import into a separate "
            "database on the external HDD, and in the field the IOC engine "
            "queries it entirely offline. abuse.ch requires a free account for "
            "most downloads — set HEXBEE_ABUSE_CH_KEY to your Auth-Key."
        ),
        commands=[
            "hexbee-hive sync-intel --list",
            "export HEXBEE_ABUSE_CH_KEY=your-auth-key",
            "hexbee-hive sync-intel",
            "hexbee-hive sync-intel urlhaus malwarebazaar",
            "hexbee-hive intel-status",
        ],
    ),
    Doc(
        id="recipe-iocs",
        title="Add and review indicators of compromise",
        kind="recipe",
        body=(
            "IOCs are matched against every incoming event's payload. A hit "
            "escalates the event to severity 3, which guarantees an incident "
            "opens, tags it 'ioc', and lands in the audit log. Kinds: sha256, "
            "filename, ip, domain, substring."
        ),
        commands=[
            "hexbee-queen ioc add sha256 <64-hex-digest> -n 'from client IR report'",
            "hexbee-queen ioc add domain evil.example",
            "hexbee-queen ioc list",
            "hexbee-queen ioc hits",
        ],
    ),
    Doc(
        id="recipe-verify-chain",
        title="Verify evidence integrity and prove it later",
        kind="recipe",
        body=(
            "Every event's hash chains over the previous one, so any "
            "retroactive edit breaks verification from that point on. An "
            "anchor is a signed receipt of the chain head at a moment in "
            "time — save it somewhere else, and you can prove later that the "
            "log has not been rewritten since."
        ),
        commands=[
            "hexbee-queen verify",
            "hexbee-hive verify",
            "hexbee-queen anchor -o anchor-20260725.json",
            "hexbee-queen anchor-verify anchor-20260725.json",
            "hexbee-hive security-check",
        ],
    ),
    Doc(
        id="recipe-export-bundle",
        title="Produce a signed evidence bundle for handover",
        kind="recipe",
        body=(
            "A bundle contains the case's events, the audit trail, per-file "
            "hashes, and an HMAC signature over the whole thing. Verification "
            "works offline on any machine with the same signing key, which is "
            "what makes it useful for handing to someone else."
        ),
        commands=[
            "hexbee-queen export 1",
            "hexbee-hive export 1",
            "hexbee-hive verify-bundle /path/to/bundle",
        ],
    ),
    Doc(
        id="recipe-seal",
        title="Seal a case in front of a witness",
        kind="recipe",
        body=(
            "Sealing records that you declared a case complete at a stated "
            "moment, before a stated witness, and pins that to the state of "
            "the evidence log by taking a signed chain anchor. The anchor is "
            "what gives it force: anyone holding it can show later that the "
            "log has not been rewritten since. Save it somewhere separate "
            "from the Hive — an anchor stored only alongside the thing it "
            "protects proves nothing. Sealing refuses if the chain does not "
            "verify."
        ),
        commands=[
            "hexbee-queen verify",
            "hexbee-queen seal 3 --operator jacob --witness 'DS Miller' "
            "-o seal-HB-2026-0003.json",
        ],
    ),
    Doc(
        id="recipe-stinger-hid",
        title="Inject keystrokes into a host over Bluetooth",
        kind="recipe",
        body=(
            "The ESP32-C3 Stinger advertises as a Bluetooth keyboard and "
            "types a DuckyScript payload into whatever pairs with it. There "
            "is no cable: you need radio range rather than physical access to "
            "a port. The finding is a host that accepts an unauthenticated "
            "HID connection — a host that demands confirmed pairing is not "
            "vulnerable to this, and the report should say so. Deployments "
            "report themselves to the Hive over Wi-Fi as hid_deployment "
            "events, so nothing has to be imported afterwards. Set "
            "mode = 'hid' in config.py before flashing."
        ),
        commands=[
            "cp payloads/00-proof-of-execution.txt payload.txt",
            "mpremote connect /dev/ttyACM0 fs cp payload.txt :payload.txt",
            "mpremote connect /dev/ttyACM0 reset",
        ],
    ),
    Doc(
        id="recipe-stinger-portal",
        title="Stand up a rogue access point with a captive portal",
        kind="recipe",
        body=(
            "The Stinger broadcasts an open access point, answers every DNS "
            "query with its own address so any request triggers the target's "
            "captive-portal check, and serves a login page. It demonstrates "
            "one finding: that people will type credentials into a network "
            "that merely looks familiar. Captured credentials are recorded as "
            "a SHA-256 fingerprint by default, not the password itself — turn "
            "portal_include_material on only if your rules of engagement "
            "require the material. This transmits, so it must be inside your "
            "authorised scope. Set mode = 'portal' and portal_ssid in "
            "config.py before flashing."
        ),
        commands=[
            "mpremote connect /dev/ttyACM0 fs cp config.py :config.py",
            "mpremote connect /dev/ttyACM0 reset",
            "hexbee-queen search --event-type credential_capture",
        ],
    ),
    Doc(
        id="recipe-stinger-scan",
        title="Deploy the ESP32-C3 for passive wireless recon",
        kind="recipe",
        body=(
            "Scan mode listens only — it never probes and never associates "
            "with what it observes. Wi-Fi beacons and BLE advertisements "
            "become wireless_sighting events and plot on the offline map. "
            "This is the mode to leave running before an engagement to learn "
            "what is there. Set lat/lon in the config if the board sits at a "
            "fixed point."
        ),
        commands=[
            "esptool.py --chip esp32c3 write_flash -z 0 ESP32_GENERIC_C3.bin",
            "mpremote connect /dev/ttyACM0 fs cp config.py :config.py",
            "mpremote connect /dev/ttyACM0 fs cp main.py :main.py",
            "mpremote connect /dev/ttyACM0 fs cp link.py :link.py",
        ],
    ),
    Doc(
        id="recipe-pivot",
        title="Set up the Raspberry Pi as a drop box",
        kind="recipe",
        body=(
            "The Pi dials home to the Queen over autossh, so nothing needs to "
            "route inbound. generate renders the unit and a setup script for "
            "you to review — it does not reconfigure the Pi behind your back. "
            "--hive-pause frees about 150 MB during a session by stopping the "
            "dashboard; ingest keeps running because losing evidence to save "
            "memory would be the wrong trade."
        ),
        commands=[
            "hexbee-queen pivot generate queen.lan -o ./pivot",
            "hexbee-queen pivot status",
            "hexbee-queen pivot connect --port 2222 --case 3",
            "hexbee-queen pivot connect --hive-pause",
        ],
    ),
    Doc(
        id="recipe-attack-coverage",
        title="See which ATT&CK techniques a case covers",
        kind="recipe",
        body=(
            "Techniques are attributed at ingest and stored beside the "
            "evidence, never inside the hash chain. If you collected evidence "
            "before this existed, backfill it. Drop an ATT&CK STIX bundle on "
            "the HDD and set HEXBEE_ATTACK_BUNDLE for full technique names."
        ),
        commands=[
            "hexbee-hive attack coverage",
            "hexbee-hive attack coverage --case 1",
            "hexbee-hive attack backfill",
            "export HEXBEE_ATTACK_BUNDLE=/mnt/evidence/enterprise-attack.json",
        ],
    ),
    Doc(
        id="recipe-start-hive",
        title="Start the Hive and create the first user",
        kind="recipe",
        body=(
            "The engine consumes MQTT; the web process serves the dashboard "
            "and REST API. Both need the database to exist first. Passwords "
            "must be at least 12 characters and not a common password."
        ),
        commands=[
            "export HEXBEE_DATA_DIR=/mnt/evidence/hexbee",
            "export HEXBEE_INGEST_KEY=$(openssl rand -hex 24)",
            "hexbee-hive init",
            "hexbee-hive user add analyst administrator",
            "hexbee-hive web",
            "hexbee-hive engine",
        ],
    ),
    Doc(
        id="recipe-connect-queen",
        title="Connect the Queen to a Hive",
        kind="recipe",
        body=(
            "The session is stored 0600 in ~/.hexbee-queen.json. Save the "
            "ingest key at connect time so the active tools can write findings "
            "back without you retyping it."
        ),
        commands=[
            "hexbee-queen connect http://hive.local:8080 -u analyst",
            "hexbee-queen connect http://hive.local:8080 -u analyst --ingest-key KEY",
            "hexbee-queen status",
        ],
    ),
    Doc(
        id="recipe-search",
        title="Search the evidence log",
        kind="recipe",
        body=(
            "Filters combine. Text search matches anywhere in the payload. The "
            "dashboard search bar does the same thing at /search."
        ),
        commands=[
            "hexbee-queen search --text evil.exe",
            "hexbee-queen search --event-type yara_match --since 2026-07-01",
            "hexbee-queen search --device Scout01 --tag ioc",
            "hexbee-queen tag 42 malware",
        ],
    ),
    Doc(
        id="recipe-ai-setup",
        title="Set up Hive Mind, the local AI assistant",
        kind="recipe",
        body=(
            "Hive Mind talks to Ollama on the LAN — never the internet. Point "
            "HEXBEE_AI_URL at whichever machine hosts the model; on a small "
            "kit that is the analyst laptop, not the Pi. With 8 GB of RAM stay "
            "in the 1–3B class and set a short keep-alive so the model unloads "
            "between questions. Everything degrades to deterministic output "
            "when no model is reachable."
        ),
        commands=[
            "ollama pull llama3.2:3b",
            "export OLLAMA_KEEP_ALIVE=30s",
            "export HEXBEE_AI_URL=http://192.168.1.20:11434",
            "export HEXBEE_AI_MODEL=llama3.2:3b",
            "hexbee-queen ai ask 'what happened on Scout01 today?'",
            "hexbee-queen ai summarize 1",
        ],
    ),
    Doc(
        id="recipe-offline-content",
        title="Load offline maps and reference material",
        kind="recipe",
        body=(
            "All user-supplied and all local. Maps render from any raster "
            "MBTiles file; without one the map still plots evidence against a "
            "placeholder grid. ZIM files need python-libzim installed."
        ),
        commands=[
            "cp region.mbtiles $HEXBEE_DATA_DIR/maps/",
            "cp wikipedia_en_all_mini.zim $HEXBEE_DATA_DIR/reference/",
            "pip install libzim",
        ],
    ),
    Doc(
        id="concept-evidence-chain",
        title="How the evidence chain works",
        kind="concept",
        body=(
            "Every event is appended to a hash-chained log. Each row's hash "
            "covers the previous row's hash, so editing any historical record "
            "breaks verification from that point forward and the dashboard's "
            "integrity shield goes red. There is exactly one write path into "
            "the chain — store_event — regardless of whether an event arrived "
            "over MQTT, REST, the field PWA, or a Queen tool. Severity, IOC "
            "hits, and ATT&CK attribution are stored alongside the chain, "
            "never inside it, because they are Hive-side interpretation rather "
            "than evidence."
        ),
    ),
    Doc(
        id="concept-scope",
        title="How scope enforcement works and why it fails closed",
        kind="concept",
        body=(
            "The scope table is the authority and it lives in the Hive, so one "
            "definition covers every operator and every tool. Three deliberate "
            "behaviours: no rules defined means everything is denied, because "
            "an empty table is not permission; an unreachable Hive also means "
            "denied, because an unreachable authorisation server is not "
            "permission either; and DNS is never consulted, because letting a "
            "DNS record decide what is in scope would hand an attacker the "
            "ability to widen the engagement. Refusals are written into the "
            "chain. HEXBEE_SCOPE_MODE=permissive relaxes only the empty-table "
            "case and is for lab use."
        ),
    ),
    Doc(
        id="concept-modes",
        title="Case operating modes",
        kind="concept",
        body=(
            "A case is worked in one of three modes: ir (incident response), "
            "pentest (engagement), or diagnostics (IT health). The mode "
            "changes nothing about how evidence is stored. It drives the "
            "dashboard banner, decides which event types the UI highlights, "
            "and tells the Queen which report template to reach for."
        ),
        commands=["hexbee-queen mode <case_id> pentest"],
    ),
    Doc(
        id="concept-roles",
        title="User roles and what each can do",
        kind="concept",
        body=(
            "viewer reads everything: dashboard, search, timelines, reports. "
            "investigator adds case creation, notes, tagging, incident triage, "
            "scope changes, and evidence export. administrator adds user "
            "management, the audit log, and the admin page. Roles nest: "
            "administrator includes everything below it."
        ),
        commands=[
            "hexbee-hive user add <name> viewer",
            "hexbee-hive user add <name> investigator",
            "hexbee-hive user add <name> administrator",
            "hexbee-hive user disable <name>",
        ],
    ),
    Doc(
        id="concept-offline",
        title="What works offline, with no internet",
        kind="concept",
        body=(
            "Everything except one command. The Hive, Comb, Forager, Netmon, "
            "the Queen, the dashboard, the map, the reference library, and "
            "Hive Mind all run with no external connectivity. The single "
            "exception is hexbee-hive sync-intel, which pulls threat feeds and "
            "is meant to be run at home before deployment. Model inference is "
            "local, map tiles are local, and the reference library is local."
        ),
    ),
    Doc(
        id="troubleshoot-ingest-refused",
        title="Ingest is being refused",
        kind="recipe",
        body=(
            "REST ingest is disabled entirely unless HEXBEE_INGEST_KEY is set "
            "on the Hive. A 401 means the key sent does not match; a 403 means "
            "no key is configured server-side. The key is shown to "
            "administrators on the /collect page."
        ),
        commands=[
            "export HEXBEE_INGEST_KEY=$(openssl rand -hex 24)",
            "hexbee-hive security-check",
        ],
    ),
    Doc(
        id="troubleshoot-no-model",
        title="Hive Mind says no model is reachable",
        kind="recipe",
        body=(
            "Check Ollama is running and that HEXBEE_AI_URL points at the "
            "machine hosting it — on a small kit that is usually the analyst "
            "laptop, not the Raspberry Pi, which cannot run a model usefully. "
            "Every AI feature has a deterministic fallback, so this degrades "
            "rather than breaks."
        ),
        commands=[
            "curl http://127.0.0.1:11434/api/tags",
            "export HEXBEE_AI_URL=http://<laptop-ip>:11434",
            "ollama serve",
        ],
    ),
    Doc(
        id="troubleshoot-capture-permission",
        title="Netmon cannot open a raw socket",
        kind="recipe",
        body=(
            "Raw capture needs CAP_NET_RAW. Grant the capability once rather "
            "than running the whole agent as root. Raw capture is Linux-only; "
            "on macOS or Windows use --backend scapy with a capture driver "
            "installed."
        ),
        commands=[
            "sudo setcap cap_net_raw,cap_net_admin=eip \"$(readlink -f \"$(which python3)\")\"",
            "hexbee-netmon status",
        ],
    ),
]


# =========================================================================
# Extracted knowledge — generated from live code so it cannot go stale
# =========================================================================

def _event_type_docs() -> list[Doc]:
    """One document describing every event type the Hive accepts."""
    from .normalize import EVENT_SEVERITY

    names = {0: "info", 1: "notice", 2: "warning", 3: "critical"}
    by_sev: dict[int, list[str]] = {}
    for event_type, severity in sorted(EVENT_SEVERITY.items()):
        by_sev.setdefault(severity, []).append(event_type)

    lines = [
        "Every event type the Hive recognises, with the severity it is given "
        "on arrival (0 info, 1 notice, 2 warning, 3 critical). Unknown types "
        "are accepted at severity 0, so a new collector never needs a Hive "
        "upgrade first. Severity 2 or above opens an incident.",
        "",
    ]
    for severity in sorted(by_sev):
        lines.append(f"Severity {severity} ({names.get(severity, '?')}): "
                     + ", ".join(by_sev[severity]))
    return [Doc(id="ref-event-types", title="Event types and severities",
                body="\n".join(lines), kind="reference", source="extracted")]


def _attack_docs() -> list[Doc]:
    """How artifacts map to ATT&CK techniques."""
    from . import attack

    lines = ["Artifact type to MITRE ATT&CK technique, applied at ingest.", ""]
    for event_type, ids in sorted(attack._BY_TYPE.items()):
        described = ", ".join(f"{t} ({attack.technique(t)['name']})" for t in ids)
        lines.append(f"{event_type}: {described}")
    lines.append("")
    lines.append("Mappings that depend on a payload field:")
    for event_type, (key, table) in sorted(attack._BY_PAYLOAD.items()):
        for value, ids in sorted(table.items()):
            lines.append(f"{event_type} with {key}={value}: " + ", ".join(ids))
    return [Doc(id="ref-attack-map", title="ATT&CK technique mappings",
                body="\n".join(lines), kind="reference", source="extracted")]


def _config_docs() -> list[Doc]:
    """Environment variables that change how HexBee behaves."""
    settings = [
        ("HEXBEE_DATA_DIR", "Where evidence, exports, maps, reference material, "
                            "and the intel database live. Point it at the "
                            "external HDD."),
        ("HEXBEE_INGEST_KEY", "Shared key collectors present to the REST ingest "
                              "endpoint. Empty disables REST ingest entirely."),
        ("HEXBEE_AI_URL", "Ollama endpoint for Hive Mind. Default "
                          "http://127.0.0.1:11434. Never the internet."),
        ("HEXBEE_AI_MODEL", "Model name Hive Mind requests. Default llama3.2."),
        ("HEXBEE_SCOPE_MODE", "enforce (default) denies when no scope rules "
                              "exist; permissive allows. Lab use only."),
        ("HEXBEE_SCOPE_OVERRIDE", "Set to i-accept-responsibility to bypass the "
                                  "Queen-side scope gate. Every action still "
                                  "announces the bypass."),
        ("HEXBEE_ATTACK_BUNDLE", "Path to an offline ATT&CK STIX bundle for "
                                 "full technique names."),
        ("HEXBEE_YARA_RULES", "Directory or file of YARA rules for Comb."),
        ("HEXBEE_ABUSE_CH_KEY", "abuse.ch Auth-Key, needed by sync-intel."),
        ("HEXBEE_MISP_FEED_URL", "Optional MISP feed to include in sync-intel."),
        ("HEXBEE_SECURE_COOKIES", "Set to 1 when serving over HTTPS. Adds the "
                                  "Secure flag and HSTS."),
        ("HEXBEE_SIGNING_KEY", "HMAC key for signed exports, anchors, and CSRF. "
                               "Auto-generated and persisted 0600 if unset."),
        ("HEXBEE_MQTT_HOST", "Mosquitto broker the ingest engine subscribes to."),
        ("HEXBEE_WEB_PORT", "Dashboard/API port. Default 8080."),
        ("HEXBEE_MIN_PASSWORD_LENGTH", "Minimum password length. Default 12."),
        ("HEXBEE_HIVE_URL", "Hive base URL, read by Forager and Netmon."),
        ("HEXBEE_SPOOL_DIR", "Where Forager buffers events when offline."),
        ("OLLAMA_KEEP_ALIVE", "Not a HexBee setting, but the highest-value one "
                              "on a small machine: how long Ollama holds the "
                              "model resident. Set 30s on 8 GB."),
    ]
    lines = ["Environment variables, and what each changes.", ""]
    lines.extend(f"{name}: {description}" for name, description in settings)
    return [Doc(id="ref-config", title="Configuration environment variables",
                body="\n".join(lines), kind="reference", source="extracted")]


def _cli_docs_from_parser(prog: str, parser) -> list[Doc]:
    """Walk an argparse tree into one document per subcommand.

    Generated rather than written, so a command that is renamed or removed
    cannot linger in the manual telling operators to run something that no
    longer exists.
    """
    import argparse

    docs: list[Doc] = []

    def walk(node, path: list[str]) -> None:
        for action in getattr(node, "_actions", []):
            if not isinstance(action, argparse._SubParsersAction):
                continue
            for name, sub in action.choices.items():
                sub_path = path + [name]
                has_children = any(
                    isinstance(a, argparse._SubParsersAction)
                    for a in getattr(sub, "_actions", []))
                if has_children:
                    walk(sub, sub_path)
                    continue
                options = []
                for a in getattr(sub, "_actions", []):
                    if a.dest in ("help",):
                        continue
                    flags = ", ".join(a.option_strings) or a.dest
                    if a.help:
                        options.append(f"{flags} — {a.help}")
                    else:
                        options.append(flags)
                full = " ".join([prog] + sub_path)
                body = (sub.description or getattr(action.choices[name], "prog", "")
                        or "").strip()
                help_text = ""
                for a in getattr(node, "_actions", []):
                    if isinstance(a, argparse._SubParsersAction):
                        choice = a._choices_actions
                        for c in choice:
                            if c.dest == name:
                                help_text = c.help or ""
                docs.append(Doc(
                    id=f"cmd-{'-'.join([prog] + sub_path)}",
                    title=full,
                    kind="command",
                    source="extracted",
                    body="\n".join(filter(None, [
                        help_text or body,
                        ("Options: " + "; ".join(options)) if options else "",
                    ])),
                    commands=[full],
                ))
        return None

    walk(parser, [])
    return docs


def _workflow_docs() -> list[Doc]:
    """The Start Here guided jobs, so asking gives the same answer as clicking."""
    from .workflows import as_knowledge_docs

    return as_knowledge_docs()


# Plain-English definitions. A beginner asking "what is a case" needs an
# answer, and every forensics tool assumes you already know.
GLOSSARY = [
    ("event", "One thing that was observed and recorded — a USB stick being "
              "plugged in, a file being found, a login. The smallest unit of "
              "evidence in HexBee. Events are never edited or deleted."),
    ("incident", "A group of related events that look like one thing "
                 "happening. HexBee creates these automatically: when "
                 "something serious is recorded, the events around it on the "
                 "same machine get pulled in, so you see the sequence rather "
                 "than isolated records."),
    ("case", "The folder for one job. Cases hold incidents, your notes, and "
             "produce the final report. You create a case first, before you "
             "start looking at anything."),
    ("evidence chain", "The tamper-evident log. Every record is sealed with a "
                       "fingerprint of the record before it, so changing "
                       "anything after the fact breaks the seal visibly and "
                       "permanently. This is what lets you show the evidence "
                       "has not been altered."),
    ("hash", "A short fingerprint of a file. Change one byte of the file and "
             "the fingerprint changes completely. It is how you prove a file "
             "is the same file you found, hours or years later."),
    ("chain of custody", "The record of who handled evidence, when, and what "
                         "they did with it. HexBee keeps this automatically in "
                         "the audit log, which is included in exports."),
    ("IOC", "Indicator of Compromise — a specific thing known to be bad: a "
            "file fingerprint, a domain, an IP address. HexBee checks every "
            "incoming record against your list and raises the alarm on a "
            "match."),
    ("ATT&CK", "A public catalogue, maintained by MITRE, of the techniques "
               "attackers actually use. Labelling findings with it lets you "
               "describe what happened in language other security people "
               "already share, and clients expect to see it in reports."),
    ("severity", "How serious a record is, from 0 (routine) to 3 (critical). "
                 "Anything 2 or above automatically opens an incident."),
    ("scope", "The list of systems you are authorised to test. HexBee refuses "
              "to run active tools against anything not on it, and records "
              "the refusal — which proves you stayed inside your permission."),
    ("triage", "A first quick look, to work out what deserves proper "
               "attention. Not the full investigation."),
    ("live response", "Collecting evidence from a computer while it is still "
                      "running, before anything is lost by switching it off."),
    ("acquisition", "Making a copy of evidence — a disk image, or a copy of "
                    "memory — so you work from the copy and leave the "
                    "original untouched."),
    ("write blocker", "Hardware that lets a computer read a drive but "
                      "physically prevents it writing. It is the proper way "
                      "to examine a drive without changing it."),
    ("anchor", "A signed receipt of what the evidence log looked like at a "
               "moment in time. Save one somewhere separate and you can prove "
               "later that the log has not been rewritten since."),
    ("YARA", "A way of describing what a piece of malware looks like, so "
             "files can be checked against a library of known patterns."),
    ("air-gapped", "Not connected to any network. HexBee is built to work "
                   "this way — everything except downloading threat feeds "
                   "runs with no internet at all."),
]


def _glossary_docs() -> list[Doc]:
    """One document per term, so a definition can be retrieved on its own."""
    docs = []
    for term, definition in GLOSSARY:
        docs.append(Doc(
            id=f"glossary-{term.lower().replace(' ', '-').replace('&', '')}",
            title=f"What is a {term}?" if term[0].islower() else f"What is {term}?",
            body=definition,
            kind="concept",
            source="glossary",
            # The first keyword is the term itself — `define()` keys on it.
            keywords=[term.lower(), f"what is {term}",
                      f"what does {term} mean", f"define {term}",
                      f"explain {term}", "glossary", "definition"],
        ))
    return docs


def _snapshot_docs() -> list[Doc]:
    """CLI documents produced by scripts/build_knowledge.py.

    The Hive cannot import the Queen, Comb, Forager, or Netmon packages —
    they install separately. The build script can, because it runs from the
    repo root, so it writes a snapshot the Hive reads at runtime.
    """
    if not SNAPSHOT.is_file():
        return []
    try:
        data = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    docs = []
    for item in data.get("commands", []):
        docs.append(Doc(
            id=item.get("id", ""), title=item.get("title", ""),
            body=item.get("body", ""), kind="command", source="extracted",
            commands=item.get("commands", []),
        ))
    return docs


# =========================================================================
# Corpus + BM25 retrieval
# =========================================================================

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.\-]*")

# "what is a case", "what does IOC mean", "define chain of custody"
_DEFINE_RE = re.compile(
    r"^(?:what(?:'s| is| are)?|whats)\s+(?:a|an|the)?\s*(?P<term>.+?)"
    r"(?:\s+mean(?:s)?)?[?.]?$"
    r"|^(?:what does)\s+(?P<term2>.+?)\s+mean[?.]?$"
    r"|^(?:define|explain)\s+(?P<term3>.+?)[?.]?$",
    re.I)

# Words that carry no signal in a corpus that is entirely about HexBee.
_STOP = {
    # Articles, prepositions, and the conversational filler that surrounds a
    # question. These match everything and discriminate nothing — "me" alone
    # was enough to match "Someone handed me a USB stick" against "write me a
    # poem".
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with",
    "is", "are", "be", "was", "were", "it", "its", "that", "this", "these",
    "those", "how", "do", "does", "did", "i", "you", "your", "my", "me",
    "we", "us", "our", "they", "them", "their", "can", "what", "when",
    "which", "who", "from", "at", "by", "as", "if", "not", "have", "has",
    "had", "get", "got", "want", "need", "please", "any", "some", "there",
    "here", "then", "than", "just", "about", "will", "would", "should",
    "could", "into", "am", "been", "being",
    "hexbee",
}


def tokenize(text: str) -> list[str]:
    """Lowercase word tokens, plus the parts of hyphenated command names.

    `hexbee-queen recon` has to match a question phrased "queen recon", so
    compound tokens contribute their pieces as well as themselves.
    """
    tokens: list[str] = []
    for match in _TOKEN_RE.finditer(text.lower()):
        token = match.group(0).strip(".-_")
        if not token or token in _STOP:
            continue
        tokens.append(token)
        if "-" in token or "_" in token or "." in token:
            for part in re.split(r"[-_.]+", token):
                if part and part not in _STOP and part != token:
                    tokens.append(part)
    return tokens


class Knowledge:
    """BM25 index over the HexBee manual.

    Built once and cached. The corpus is small enough (a hundred short
    documents) that the whole index is a few hundred kilobytes and querying
    is sub-millisecond — no vector store, no embedding model, no extra
    resident memory on a machine that has none to spare.
    """

    K1 = 1.5
    # Lower than the usual 0.75 on purpose. The auto-extracted command docs
    # are a single line each, and standard length normalisation hands them a
    # large advantage over the multi-paragraph recipes that actually answer
    # the question. 0.4 keeps some normalisation without that distortion.
    B = 0.4
    # Curated aliases are the strongest signal available — an author saying
    # "this is what people call this" beats term frequency. Repeating them in
    # the index is the simplest way to weight them.
    KEYWORD_REPEAT = 4

    def __init__(self, docs: list[Doc] | None = None):
        self.docs = docs if docs is not None else build_corpus()
        self._tokens = [
            tokenize(f"{d.title} {d.body} {' '.join(d.commands)} "
                     + " ".join(d.keywords) * self.KEYWORD_REPEAT)
            for d in self.docs
        ]
        self._len = [len(t) or 1 for t in self._tokens]
        self._avg = sum(self._len) / max(1, len(self._len))
        self._tf: list[dict[str, int]] = []
        self._df: dict[str, int] = {}
        for tokens in self._tokens:
            counts: dict[str, int] = {}
            for token in tokens:
                counts[token] = counts.get(token, 0) + 1
            self._tf.append(counts)
            for token in counts:
                self._df[token] = self._df.get(token, 0) + 1
        self._n = max(1, len(self.docs))

    def _idf(self, term: str) -> float:
        df = self._df.get(term, 0)
        # Okapi BM25 IDF with the +1 guard so common terms never go negative.
        return math.log(1 + (self._n - df + 0.5) / (df + 0.5))

    def search(self, query: str, k: int = 4,
               kinds: tuple[str, ...] | None = None) -> list[tuple[Doc, float]]:
        """Top-k documents for a query, optionally restricted to some kinds."""
        terms = tokenize(query)
        if not terms:
            return []
        scored: list[tuple[Doc, float]] = []
        for index, doc in enumerate(self.docs):
            if kinds and doc.kind not in kinds:
                continue
            score = 0.0
            for term in terms:
                freq = self._tf[index].get(term, 0)
                if not freq:
                    continue
                norm = 1 - self.B + self.B * self._len[index] / self._avg
                score += self._idf(term) * (freq * (self.K1 + 1)) / (
                    freq + self.K1 * norm)
            score *= KIND_WEIGHT.get(doc.kind, 1.0)
            if score > 0:
                scored.append((doc, score))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:k]

    def define(self, query: str) -> Doc | None:
        """Answer a "what is X" question by looking X up directly.

        A glossary is a keyed lookup, not a search problem. BM25 handles it
        badly for exactly the terms that matter most: "case" appears in
        almost every document in this corpus, so its IDF is near zero and
        "what is a case" scores below the noise floor. Matching the term
        itself sidesteps that entirely.
        """
        match = _DEFINE_RE.match(query.strip())
        if not match:
            return None
        term = (match.group("term") or match.group("term2")
                or match.group("term3") or "").strip().strip("?.\"' ").lower()
        if not term:
            return None

        # Longest glossary term first, so "chain of custody" beats "chain".
        entries = sorted(
            ((d, (d.keywords[0] if d.keywords else "").lower())
             for d in self.docs if d.source == "glossary"),
            key=lambda pair: -len(pair[1]))

        # Try the whole phrase, then drop leading qualifiers one at a time:
        # "sha256 hash" -> "hash", "signed evidence bundle" -> "bundle".
        # People name the thing they mean at the end of the phrase.
        words = term.split()
        for start in range(len(words)):
            candidate = " ".join(words[start:])
            for doc, name in entries:
                if name and candidate in (name, f"a {name}", f"an {name}"):
                    return doc
        return None

    def routing_score(self, query: str) -> float:
        """How confidently this looks like a question about *using* HexBee.

        Scored over curated documents only. The auto-extracted command docs
        are full of ordinary words — 'host', 'device', 'found' — so letting
        them vote would send "was evil.exe seen anywhere" to the manual.
        """
        hits = self.search(query, 1, kinds=ROUTING_KINDS)
        return hits[0][1] if hits else 0.0

    def _covers(self, doc_index: int, terms: list[str]) -> int:
        """How many distinct query terms appear in a document."""
        return sum(1 for term in set(terms) if self._tf[doc_index].get(term))

    def _accept(self, query: str, doc: Doc, score: float,
                min_score: float) -> bool:
        """Is this a real answer, or one incidental word in common?

        Score alone is not enough. "write me a poem" scored 6.5 against the
        report recipe purely because that recipe mentions writing — one term
        out of three. Requiring the match to cover at least two distinct query
        terms (for queries long enough to have two) rejects that without
        rejecting short legitimate questions like "what can a viewer do".
        """
        if score < min_score:
            return False
        terms = tokenize(query)
        if not terms:
            return False
        # Two matching terms, or all of them for a one-word query. A single
        # incidental word in common is a coincidence, not an answer.
        needed = min(2, len(set(terms)))
        return self._covers(self.docs.index(doc), terms) >= needed

    def relevant(self, query: str, k: int = 3,
                 min_score: float = 5.0) -> list[Doc]:
        """Documents that genuinely answer the query, best first.

        The single source of truth for both the reference handed to the model
        and the sources cited back to the operator — if those two disagree,
        the citation is a lie.
        """
        defined = self.define(query)
        docs = [doc for doc, score in self.search(query, k)
                if self._accept(query, doc, score, min_score)]
        if defined is not None and defined not in docs:
            docs.insert(0, defined)
        return docs[:k]

    def reference_for(self, query: str, k: int = 3,
                      min_score: float = 5.0) -> str:
        """The manual sections relevant to a question, ready for a prompt.

        Empty when nothing clears the bar — the signal to the caller that
        this is not a HexBee-usage question at all, and the assistant should
        say so rather than answer. Three sections, not more: a 1-3B model
        given four competing procedures starts blending them.
        """
        docs = self.relevant(query, k, min_score)
        return "\n\n".join(doc.render() for doc in docs) if docs else ""

    def best(self, query: str, min_score: float = 5.0) -> Doc | None:
        defined = self.define(query)
        if defined is not None:
            return defined
        hits = self.search(query, 1)
        if hits and self._accept(query, hits[0][0], hits[0][1], min_score):
            return hits[0][0]
        return None


_CACHE: Knowledge | None = None


def build_corpus() -> list[Doc]:
    """Curated recipes plus everything extractable from the running code."""
    docs = list(RECIPES)
    for producer in (_workflow_docs, _glossary_docs, _event_type_docs,
                     _attack_docs, _config_docs, _snapshot_docs):
        try:
            docs.extend(producer())
        except Exception:
            # A knowledge source failing must never take down the assistant.
            continue
    # Aliases from the table are merged in, never substituted — workflow and
    # glossary documents carry their own and would otherwise be wiped.
    for doc in docs:
        extra = KEYWORDS.get(doc.id, [])
        if extra:
            doc.keywords = list(dict.fromkeys(doc.keywords + extra))
    return docs


def get() -> Knowledge:
    global _CACHE
    if _CACHE is None:
        _CACHE = Knowledge()
    return _CACHE


def reset() -> None:
    """Drop the cached index (used by tests and after a snapshot rebuild)."""
    global _CACHE
    _CACHE = None
