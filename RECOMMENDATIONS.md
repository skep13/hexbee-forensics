# HexBee — feature recommendations

> Generated after a full read of the README, OVERVIEW, component docs, directory structure, and hardware constraints.
> All recommendations account for actual hardware limits. Nothing here requires spending more money.

---

## Hardware constraints (applied throughout)

| Device | Constraint |
|---|---|
| ThinkPad T470 | 4GB RAM, no battery, Kali Linux x86. Ollama phi3:mini uses ~2.2GB — ~1.8GB left for everything else. No GPU. Can't run Metasploit + Ollama heavily at the same time. |
| RPi 3B+ | 1GB RAM, ARM Cortex-A53. Hive (Flask + SQLite + Mosquitto) already uses ~300–400MB. Not much headroom for additional services. Power banks give ~8–12hrs runtime. |
| ESP32-S3 | Scout firmware already written. TinyUSB acquisition path stubbed/simulation only. 520KB SRAM, 8MB flash. WiFi + USB OTG capable. |
| ESP32-C3 | Completely unused. 400KB SRAM, 4MB flash. WiFi + BLE 5.0. No USB OTG. Ideal passive scanner. |
| RPi Pico ×2 | **Plain Pico, not Pico W — no WiFi.** 264KB SRAM. USB HID capable via CircuitPython/TinyUSB. Any HexBee integration must be pre-loaded or wired via UART to a WiFi-capable device. |
| iPhone XR | PWA already working. iOS sandboxing prevents raw packet capture and BLE scanning from a PWA. Camera + NFC (via Shortcuts) are accessible. |
| Storage | 64GB SD (RPi OS + Hive data), external HDD (evidence, model weights, exports), 2× USB drives. HDD should hold: YARA rules, ATT&CK bundle, threat intel feeds, memory dumps, Ollama models. |

---

## Tier 1 — build these first

Low RAM cost, high return, slots directly into existing HexBee architecture.

### 1. `hexbee-netmon` (runs on RPi)

**What:** Passive packet capture + lightweight IDS running on the RPi alongside the Hive. Uses scapy in promiscuous mode. Rule-based detections (port scan, ARP spoofing, deauth floods, SMB relay attempts) POST to the existing `/ingest` endpoint as `network_alert` events. Appears in the Hive dashboard timeline alongside forensic evidence.

**Why build it:** The OVERVIEW explicitly lists "network packet capture" as out of scope. It's the single biggest capability gap. Scapy uses ~80MB on the RPi — tight but feasible if you keep rule evaluation lean (no deep packet inspection, just header analysis). Fills blue team IDS, red team passive recon, and network diagnostics use cases from the same module using a `--mode` flag.

**Modes:**
- `--mode ids` — passive detection, alerts only
- `--mode recon` — log all unique MACs, IPs, services seen (red team enumeration)
- `--mode diagnostics` — latency, DNS health, route trace, ARP table anomalies

**RAM note:** Keep scapy in stream mode (don't buffer full PCAPs in memory). Write raw PCAP to the HDD if capture is needed. Never load a full capture file into RPi RAM.

---

### 2. ESP32-C3 passive wireless scanner

**What:** MicroPython on the idle C3. Passively scans BLE advertisements and WiFi probe requests. Posts `wireless_sighting` events to the Hive ingest API over WiFi, including: device MAC, randomised MAC flag, RSSI, SSID preferences from probe requests, BLE device name/UUID where broadcast. Sightings plotted on the existing offline Hive map.

**Why build it:** The C3 is completely unused. 400KB SRAM is ample for this — BLE + WiFi scan loops use well under 100KB. No extra hardware needed. Red team value: passive device enumeration and SSID preference harvesting before an engagement. Blue team value: rogue device detection on your own network.

**Note on Pico WiFi:** Plain Picos have no WiFi. If you want a Pico to communicate with the Hive, you'd need to wire UART from the Pico to the C3 and have the C3 forward the event. Keep this in mind for any Pico integration.

---

### 3. YARA integration in Comb

**What:** Add `yara-python` as an optional dependency in Comb. After file carving and filesystem walk, run each file against a local YARA ruleset stored on the HDD. Matches are logged as `ioc_hit` events in the Hive chain with the rule name, file path, and SHA-256. Include an offline community ruleset (Yara-Rules GitHub bundle, ~10MB) on the HDD.

**Why build it:** Comb already walks every file and computes hashes. YARA is one extra pass — marginal CPU cost, negligible RAM. Transforms Comb from a cataloguer into an actual malware detector. The HDD has plenty of space for rules.

**Implementation note:** Make YARA optional (`try: import yara` with a graceful skip) so Comb still works without it. Load rules once at scan start, not per-file.

---

### 4. Scope enforcer in Queen

**What:** An `engagement_scope` table in the Hive (IP CIDR ranges, domain patterns, start/end datetime, authorisation reference). A small Queen-side Python library (`from hexbee_queen.scope import check`) that every active tool imports before firing. Out-of-scope attempts are blocked and logged as `scope_violation` warnings in the Hive with full caller context.

**Why build it:** Zero RAM overhead — just a DB table and a Python function. Legally critical for professional engagements. Should be built before any active red team tooling is added. Makes HexBee commercially viable as a pentest platform.

---

### 5. Forager `--mode diagnostics`

**What:** A new mode flag on the existing Forager agent. Instead of collecting forensic artifacts, collects: disk SMART data via `smartmontools`, CPU temperature via `/sys/class/thermal`, RAM pressure and swap usage, systemd failed units, disk fill percentages, and top CPU/memory consumers. Posts as `diagnostic_snapshot` events to the Hive.

**Why build it:** Reuses all existing Forager plumbing — discovery, ingest, offline spooling, watch mode. No new agent to deploy. Turns HexBee into an IT diagnostics tool at zero extra RAM cost. `hexbee-forager watch --mode diagnostics --interval 300` gives you continuous health monitoring on any Linux host.

---

### 6. MITRE ATT&CK offline tagger

**What:** An offline ATT&CK STIX bundle (JSON, ~2MB, stored on HDD) queried at Hive ingest time. A mapping table links known artifact types (registry autorun keys → T1547, browser history → T1217, scheduled tasks → T1053, etc.) to technique IDs. Incidents in the dashboard show which ATT&CK tactics are present. Cases export with a tactic coverage summary.

**Why build it:** ~2MB data file, pure Python dict lookup, no RAM impact. Dramatically improves report quality for both IR and pentest deliverables. Makes the auto-report feature (Tier 2) far more useful. Purple team debrief-ready out of the box.

---

## Tier 2 — meaningful additions, still hardware-realistic

### 7. Responder → Hive bridge

**What:** A Python watcher (~50 lines) that tails Responder's `Logs/` directory on Kali. Parses NTLMv2 hash captures and cleartext credential files as they appear. POSTs each as a `credential_capture` event to the Hive ingest API with: target host, captured user, hash/cleartext, timestamp, capture method. Responder is already installed on Kali — no additional dependencies.

**Why build it:** Captured credentials automatically enter the evidence chain without manual case notes. Combined with the scope enforcer and ATT&CK tagger, a Responder session produces a complete, chain-of-custody-backed finding ready for the report.

---

### 8. `hexbee-recon` (Queen-side nmap wrapper)

**What:** A thin Queen subcommand wrapping nmap. Checks the scope enforcer before firing. Runs a service version scan (`-sV`) against in-scope targets. Parses nmap XML output. Logs discovered hosts, open ports, service names, and version strings to the Hive as `recon_finding` events. Correlates discovered services against the IOC watchlist automatically.

**Why build it:** nmap is already on Kali. Python subprocess + XML parse is ~80 lines. Results in the Hive timeline alongside forensic evidence — recon and IR data in the same case.

**Modes:**
- `hexbee-queen recon sweep <target>` — full service scan
- `hexbee-queen recon quick <target>` — top 100 ports, fast
- `hexbee-queen recon vuln <target>` — nmap vuln scripts (in-scope only)

---

### 9. Scout TinyUSB hardware bring-up

**What:** Complete the stubbed TinyUSB MSC (Mass Storage Class) acquisition path in the existing Scout ESP-IDF firmware. USB insertion on the S3 triggers real file metadata harvest from the target drive: directory listing, file hashes (SHA-256 of first 4KB for speed), timestamps. Results POST to the Hive via MQTT as they were in simulation mode.

**Why build it:** The firmware skeleton already exists and the simulator exercises the whole pipeline. The ESP32-S3 has USB OTG hardware support. This is the final implementation step that makes Scout a real field tool rather than a demo.

**Implementation note:** Hash only the first 4KB of each file on the S3 — full file hashing on 520KB SRAM against a large drive will OOM. Full hash can be computed by Comb later on the Queen.

---

### 10. Log aggregation + anomaly detection

**What:** A syslog UDP listener (port 514) added to the Hive. A Windows Event Log forwarder path (NXLog or winlogbeat on the target → Hive REST). A lightweight rule engine that flags: repeated auth failures (brute force), sudo/privilege escalation, new cron entries, account creation, and service installs. Flagged events POST to the Hive ingest chain as `log_anomaly` events.

**Why build it:** The syslog listener itself is ~30 lines of Python. Stream parse rather than buffer — keeps RPi RAM low. Makes HexBee a lightweight SIEM. Massive blue team and IT diagnostics value from minimal code.

---

### 11. Auto pentest report from Hive case

**What:** A Queen command (`hexbee-queen report engagement <case_id>`) that pulls all events for a case, groups them by ATT&CK tactic, uses Hive Mind (local Ollama `phi3:mini`) to draft a narrative paragraph per finding, and exports a structured HTML report. A second pass through `wkhtmltopdf` (lightweight, already packaged for Kali/Debian) produces a PDF.

**Why build it:** This is the deliverable that makes HexBee commercially viable. Everything else feeds into it. `phi3:mini` fits within the T470's 4GB alongside other processes if you're not running Metasploit simultaneously. Queue Ollama calls sequentially — don't try to summarise everything in parallel.

**Report structure:** Executive summary → Scope + methodology → Attack narrative (ATT&CK-mapped) → Technical findings (per event) → Evidence chain summary → Appendix (raw exports).

---

### 12. Pico 1 as BadUSB / HID implant

**What:** CircuitPython on Pico 1. Appears as a USB HID keyboard on plug-in. Payloads stored as plain `.txt` files in DuckyScript-compatible format on a USB drive (not on the Pico itself — just copy the chosen payload to the Pico's `CIRCUITPY` drive to select it). Queen logs which payload file was deployed and when as an `hid_deployment` event (manually triggered — Pico has no WiFi to auto-report).

**Why build it:** Plain Pico has no WiFi, so remote control isn't possible. Pre-loading payloads and logging manually from Queen is the right approach for this constraint. CircuitPython HID is well-documented and the total code is ~100 lines.

**Payload library ideas (store on HDD):** reverse shell dropper, credential harvester, persistence installer, network enumeration, lock screen bypass.

**Note:** Keep Pico 2 separate — reserve it for a different role (see Tier 3: physical case seal).

---

## Tier 3 — bigger scope, do after tier 1 and 2 are solid

### 13. RPi drop box + reverse SSH tunnel

**What:** Configure the RPi to auto-establish a reverse SSH tunnel to the T470 on boot (`autossh` + systemd unit). A new Queen command (`hexbee-queen pivot connect`) opens a shell through the tunnel. Traffic is routed from Kali through the RPi to the target network.

**Constraint:** The RPi is already running the Hive on ~300–400MB of its 1GB. Running both simultaneously is feasible for a short engagement but tight for a long-running one. Consider a `--hive-pause` flag that temporarily suspends non-essential Hive services during a pivot session to free RAM.

**Power:** Two power banks give roughly 10hrs of RPi runtime unplugged. Plan around this for physical drop box operations.

---

### 14. Forager memory acquisition

**What:** Extend Forager to trigger a RAM dump via LiME kernel module (Linux targets) or winpmem (Windows targets). Stream the dump to the external HDD in chunks — never load the full image into T470 RAM. Create a Hive chain entry on completion with the dump's SHA-256 and file location. Volatility 3 analysis runs separately on the T470 against the dump on the HDD.

**Why build it:** Critical for malware IR — memory is where running malware lives. The chunked-streaming approach is essential: a 16GB target RAM dump would OOM the T470 if loaded whole. Always stream direct to HDD.

**Volatility note:** Volatility 3 itself uses ~500MB–1GB during analysis depending on the plugin. Run it when Ollama is not active.

---

### 15. BloodHound AD ingest

**What:** A Queen command that parses BloodHound collector JSON output (produced by SharpHound or BloodHound.py after a collection run). Extracts: Domain Admin paths, kerberoastable accounts, unconstrained delegation targets, AS-REP roastable accounts. Pushes each as a `ad_recon_finding` event to the Hive with ATT&CK tagging. Hive Mind drafts the Active Directory section of the pentest report.

**Why build it:** BloodHound JSON is well-structured and offline parse is trivial. Only relevant for internal AD engagements. Pairs with the auto-report feature to produce a complete AD attack path narrative automatically.

---

### 16. Offline threat intel sync

**What:** A pre-deployment script (`hexbee-hive sync-intel`) that downloads structured threat intel feeds while you have internet access at home: abuse.ch URLhaus, MalwareBazaar hash feed, and a MISP community feed. Stores as a local SQLite database on the HDD. The existing Hive IOC engine queries the local DB in the field — fully offline, no internet needed during deployment.

**Why build it:** The current Hive IOC engine works with manually entered IOCs. Pre-synced feeds dramatically improve hit rates without changing how the field deployment works. Run the sync script before each deployment.

---

### 17. Pico 2 as physical case-seal trigger

**What:** CircuitPython on Pico 2. A physical button wired to the Pico. When pressed, Pico sends a signal via UART to the ESP32-C3 (which has WiFi), which POSTs a `case_seal` event to the Hive. The Hive runs `hexbee-hive anchor` automatically on receipt. Physical, tamper-evident case closure — pressing the button in front of a witness seals the evidence chain.

**Constraint:** Pico has no WiFi, so UART → C3 → Hive is the only wireless path. Alternatively, connect Pico 2 via USB to the T470 and have a small Queen-side listener trigger the anchor. The USB approach is simpler to implement.

---

## Web UI improvements

Based on the existing Flask dashboard, these additions would meaningfully improve day-to-day use without adding RAM pressure:

- **Mode indicator banner** — clearly shows whether the current case is in IR mode, pentest engagement mode, or diagnostics mode. Affects which event types are highlighted.
- **ATT&CK coverage heatmap** — a simple HTML/CSS grid showing which tactics are present in the current case. No external JS, just coloured cells.
- **Live event feed** — the dashboard currently shows events but a real-time feed (Server-Sent Events, not WebSockets — lower overhead) would make monitoring feel alive during an active engagement.
- **Scope enforcer UI** — a simple form on the Admin page to define engagement scope (CIDR ranges, domains, authorisation reference number). Currently requires direct DB access.
- **Device map clustering** — the offline slippy map already plots GPS evidence. Add clustering for wireless sightings from the C3 scanner so the map doesn't get cluttered.
- **Quick triage panel** — a one-click panel on the incident view that sends the incident to Hive Mind with a structured prompt (severity classification + recommended next steps) rather than requiring freeform Q&A.
- **Report preview** — a live HTML preview of the auto-generated pentest report within the dashboard before PDF export.

---

## What to build in order

```
Week 1–2:   Scope enforcer + ATT&CK tagger (no hardware, pure Python, unblocks red team work)
Week 2–3:   ESP32-C3 passive scanner (uses idle hardware, gives wireless recon immediately)
Week 3–4:   hexbee-netmon on RPi (biggest capability gap, blue + red + diagnostics)
Week 4–5:   YARA in Comb + Forager diagnostics mode (extends existing code, high value)
Week 6–7:   Responder bridge + hexbee-recon + auto pentest report (completes red team loop)
Week 8+:    Scout TinyUSB bring-up, log aggregation, BloodHound ingest, drop box config
```

---

*Recommendations written against: README.md, docs/OVERVIEW.md, directory structure (hive/, comb/, forager/, queen/, scout/, docs/), 48-test suite status, and full hardware inventory.*
