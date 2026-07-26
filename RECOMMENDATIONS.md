# HexBee — feature recommendations, as built

Every recommendation in the original version of this file has been
implemented. This document now records **what was built, where it lives, how
it fits the hardware, and what it cannot do.**

The limitations are not an appendix of excuses — several of them changed the
design. Where a recommendation's suggested approach would not survive contact
with 1 GB of RAM or a radio-less microcontroller, the deviation is stated at
the point it matters and again in [Limitations](#limitations).

**Status:** 17/17 features built · 7/7 UI improvements built · plus a grounded
operator knowledge base so the local model can actually drive the toolkit ·
287 tests passing · no hardware-in-the-loop validation yet (see
[What is not validated](#what-is-not-validated-on-hardware)).

---

## Hardware constraints (applied throughout)

| Device | Constraint | How the build respects it |
|---|---|---|
| ThinkPad T470 | 4 GB RAM, no battery, Kali x86, no GPU. `phi3:mini` uses ~2.2 GB. | Report narration is strictly sequential and capped at 10 AI calls; memory images are hashed in 8 MB chunks, never loaded; Volatility is explicitly deferred, not invoked. |
| RPi 3B+ | 1 GB RAM, Cortex-A53. Hive already uses ~300–400 MB. | Netmon uses a stdlib `AF_PACKET` decoder instead of scapy (~80 MB saved); syslog stores findings only, never raw lines; intel lives in a separate DB with indexed exact-match lookups; systemd caps Netmon at 192 MB. |
| ESP32-S3 | 520 KB SRAM, 8 MB flash, USB OTG. | USB acquisition hashes a 4 KB prefix per file, streams one event per file, caps at 512 files and depth 6, and yields every 8 files so Wi-Fi/MQTT don't starve. |
| ESP32-C3 | 400 KB SRAM, ~100 KB usable heap, Wi-Fi + BLE 5.0, **no USB OTG**. | Bounded dedup table (400 devices), one report per device per 15 min, batched uploads, queue trimmed at 200, `gc.collect()` every cycle. |
| RPi Pico ×2 | **Plain Picos, not Pico W — no Wi-Fi.** 264 KB SRAM, USB HID capable. | Neither Pico talks to the Hive. The Stinger logs to its own drive for later import; the Sentinel reports over USB serial to a Queen listener. |
| iPhone XR | PWA works; iOS sandboxing blocks raw packet capture and BLE from a PWA. | Unchanged — the field PWA remains camera + notes only. |
| Storage | 64 GB SD (RPi OS + Hive), external HDD, 2× USB drives. | HDD is the documented home for YARA rules, the ATT&CK bundle, intel feeds, PCAPs, and memory images. Point `HEXBEE_DATA_DIR` at it. |

---

# Tier 1

## 1. `hexbee-netmon` — passive capture + lightweight IDS  ✅ built

**Where:** `netmon/` (new installable package), `netmon/README.md`,
`netmon/hexbee-netmon.service`

Three modes behind one `--mode` flag, exactly as recommended:

| Mode | Transmits? | Output |
|---|---|---|
| `ids` | no | `network_alert` events per detection |
| `recon` | no | `recon_finding` events — one per host, plus a sweep summary |
| `diagnostics` | yes | `diagnostic_snapshot` + `network_alert` |

Six detection rules: `port_scan` (T1046), `arp_spoof` (T1557.002),
`smb_relay` (T1557.001), `dns_tunnel` (T1071), `nonstandard_port` (T1571),
`deauth_flood` (T1498). Repeat findings are suppressed for 120 s per
(rule, source, target), so a noisy scanner produces one evidence record
rather than thousands.

**Deviation from the recommendation — no scapy by default.** The original
budgeted ~80 MB for scapy on a Pi already running the Hive. Instead the
default backend is a stdlib `AF_PACKET` socket with a hand-written header
decoder in `decode.py`: no import cost, a 256-byte snaplen so payloads are
never copied out of the kernel, decoding that stops at layer 4, and rule
state that is explicitly bounded and trimmed every 30 s. scapy remains an
optional extra and is needed for exactly one thing: 802.11 monitor mode.

**PCAP:** `--pcap /mnt/evidence/capture.pcap` streams frames to disk with
64 MB rotation and a bounded file count. Nothing beyond the current frame is
ever in memory, and Netmon never reads a capture back.

**Compatibility:** Linux only for raw capture. Needs `CAP_NET_RAW` —
`setcap` once, no root. The systemd unit drops everything else and sets
`MemoryMax=192M`.

---

## 2. ESP32-C3 passive wireless scanner  ✅ built

**Where:** `scout/c3-scanner/main.py`, `config.example.py`, `README.md`

MicroPython. Wi-Fi beacon scan (SSID, BSSID, channel, RSSI, security mode,
open-network flag) plus BLE advertisement scan (address, address type, name,
service UUIDs, RSSI). Every sighting carries a `randomised_mac` flag, because
a randomised MAC cannot be used to track a device across sessions and a
report should not imply that it can.

Sightings become `wireless_sighting` events (ATT&CK T1040) and plot on the
offline evidence map — where the new [map clustering](#ui-5) keeps a
walk-around's worth of pins legible.

**It listens only.** It never probes, never associates with anything it
observes, and connects only to your own uplink network.

**Limitation that changed the scope:** MicroPython's `WLAN.scan()` returns
**access-point beacons only**. The probe-request harvesting the original
recommendation described — collecting the SSIDs client devices are looking
for — requires raw 802.11 monitor mode, which the MicroPython port does not
expose. For probe requests, use `hexbee-netmon run --monitor` with a
monitor-capable USB adapter, or rewrite the C3 firmware against ESP-IDF's
`esp_wifi_set_promiscuous()`.

**Note on Pico ↔ C3:** the recommendation suggested UART-bridging a Pico
through the C3 for Wi-Fi. That was not needed — see
[#12](#12-pico-1--stinger-hid-payload-deployer--built-not-hardware-validated) and
[#17](#17-pico-2--sentinel-hardware-evidence-seal-token--built-not-hardware-validated)
for how the Picos actually report.

---

## 3. YARA integration in Comb  ✅ built

**Where:** `comb/hexbee_comb/yara_scan.py`, wired into `analysis.py`,
`cli.py` (`--yara-rules`, `--no-yara`, `hexbee-comb yara`), and the Comb web UI

Rules are compiled **once** at scan start, never per file, and matched during
the same pass that already reads each file for hashing — so YARA costs one
extra evaluation, not extra I/O. Matches become `yara_match` events
(severity 3, ATT&CK T1204.002 + T1027) with the rule name, namespace, tags,
description, and file SHA-256.

Fully optional in both directions: no `yara-python` → the pass is skipped and
the CLI says why; no rules found → same, with the search paths printed.
Individual broken rule files are skipped with a warning rather than failing
the scan, because community bundles reliably contain a few files needing
modules you do not have compiled in.

**Deliberate omission:** matched **string identifiers** are recorded, never
matched **data**. The matched bytes could be the very content under
investigation — a password, a key, PII — and a detection record is not the
place to copy it.

**Compatibility:** `pip install 'hexbee-comb[yara]'`. Rules live on the HDD
(`HEXBEE_YARA_RULES`, or `/mnt/evidence/yara`). Files over 64 MB are skipped:
YARA over a multi-GB VM disk inside a triage window is not a good trade on a
4 GB laptop.

---

## 4. Scope enforcer  ✅ built

**Where:** `hive/hexbee_hive/scope.py` (authority), `queen/hexbee_queen/scope.py`
(client gate), Admin page `#scope`, `hexbee-hive scope`, `hexbee-queen scope`

The authority lives in the Hive so one definition covers every operator and
every tool. Rules are CIDR / host / domain, each with an authorisation
reference, an optional UTC time window, and an optional case binding.

**It fails closed.** Three decisions worth stating:

- **No rules defined → everything is denied.** An empty scope table is not
  permission. (`HEXBEE_SCOPE_MODE=permissive` relaxes this for lab use, and
  the Admin page says loudly when it is set.)
- **Hive unreachable → denied.** An unreachable authorisation server is not
  permission either.
- **DNS is never consulted.** A hostname is matched literally against host and
  domain rules. Letting DNS decide what is in scope would hand an
  attacker-controlled record the power to widen the engagement.

Refusals are written into the hash chain as `scope_violation` events. That is
the point: a blocked attempt proves the operator stayed inside the
authorisation, which is exactly what a client or a court wants to see.

Per-host expansion means a partially-authorised range scans its authorised
part rather than being refused wholesale — `10.0.0.0/24` is checked as 254
separate authorisations.

An override exists (`HEXBEE_SCOPE_OVERRIDE=i-accept-responsibility`),
deliberately awkward to set by accident, and every allowed action still
announces that the gate was bypassed.

---

## 5. Forager `--mode diagnostics`  ✅ built

**Where:** `forager/hexbee_forager/diagnostics.py`, `--mode` on `collect` and
`watch`

Reuses every piece of Forager plumbing — Hive discovery, batching, offline
spooling, USB-stick operation. The mode swaps the collector registry and
nothing else, which is why it costs no extra memory and no second agent.

Collects: SMART health and attributes, CPU/SoC temperature, RAM and swap
pressure, disk fill, failed systemd units (or stopped Windows services),
top memory consumers, load average, uptime.

Two event types: `diagnostic_snapshot` (readings, severity 0) and
`diagnostic_alert` (a threshold crossed, severity 2). Alerts carry a `rule`
key so they thread through correlation like any other finding — but
deliberately map to **no** ATT&CK technique, because a full disk is not an
adversary behaviour and pretending otherwise would poison the heatmap.

```bash
hexbee-forager watch --mode diagnostics --interval 300
```

**Compatibility:** psutil when present, native fallbacks (`/proc`, `/sys`,
`wmic`, `systemctl`, `sc`) otherwise. `smartctl` is optional and silent when
absent — a missing tool must never fail a collection run in the field.

---

## 6. MITRE ATT&CK offline tagger  ✅ built

**Where:** `hive/hexbee_hive/attack.py`, tagging in `ingest.py`,
`/attack` page, heatmap on the dashboard / case / preview pages

Attribution happens at ingest as a pure dict lookup and is stored in
`event_techniques` — **outside the hash chain**, because ATT&CK attribution
is Hive-side interpretation and must never alter the evidence record itself.
A tagging failure is logged and swallowed; it can never lose an event.

**Deviation from the recommendation.** It suggested shipping a ~2 MB STIX
bundle. Instead there is a curated built-in mapping table that works on a
fresh install with **zero data files**, plus optional enrichment from a real
ATT&CK STIX bundle on the HDD (`HEXBEE_ATTACK_BUNDLE`). The bundle is parsed
once, lazily, keeping only the fields needed, so the Pi never holds the whole
30 MB document. This matters for an air-gapped kit: the feature works before
you have managed to get the bundle onto the drive.

Mapping is by event type, by payload discriminator (`persistence_item` +
`type=cron` → T1053.003), and by explicit declaration from the producing tool.
`hexbee-hive attack backfill` tags evidence collected before the feature
existed. A test asserts every referenced technique is defined and every
technique's tactic is one the heatmap renders — a technique pointing at an
unknown tactic would silently vanish from reports.

---

# Tier 2

## 7. Responder → Hive bridge  ✅ built

**Where:** `queen/hexbee_queen/responder.py`, `hexbee-queen responder`

Tails Responder's `Logs/` directory, parses NTLMv2, NTLMv1, and cleartext
captures, and forwards each as a `credential_capture` event (severity 3,
ATT&CK T1557.001) with account, domain, protocol, source host, and capture
method. Deduplicated by fingerprint, because the same hash reappears every
time a host retries and one capture should be one evidence record. Read-only:
Responder's files are never modified or removed.

**Deliberate deviation: it does not ship the secret by default.** The hash or
password is fingerprinted (SHA-256) and its *structure* recorded. Pushing
harvested credentials into a database on an SD card — in an evidence log you
will later hand to a client — is not something a tool should do quietly.
`--include-material` stores the full hash when your rules of engagement
require it, and the event records that you chose to.

---

## 8. `hexbee-recon` — scope-gated nmap wrapper  ✅ built

**Where:** `queen/hexbee_queen/recon.py`, `hexbee-queen recon <profile> <target>`

Profiles: `quick` (top 100 ports), `sweep` (`-sV`), `vuln` (nmap vuln
scripts), `discover` (`-sn`). The scope gate runs **before** nmap is invoked,
target by target; a refused target is never passed to the binary.

XML output is parsed into one `recon_finding` per host and one per open
service, plus a sweep summary. Per-service granularity matters: the IOC
engine and ATT&CK tagger both work on individual events, so a version string
matching a known-vulnerable build raises its own finding. Ports with vuln
script output are re-labelled `finding: vulnerability`.

**Compatibility:** nmap is already on Kali. Pure stdlib XML parsing.

---

## 9. Scout TinyUSB hardware bring-up  ⚠️ built, not hardware-validated

**Where:** `scout/firmware/main/usb_watch.c` / `.h`, `Kconfig.projbuild`,
`idf_component.yml`

The S3 acts as USB **host**, not device: the stick goes into the Scout. That
is the forensically useful direction — the Scout is the collector. On
insertion the MSC driver enumerates the device, mounts the filesystem, and
walks it, emitting per-file size, mtime, prefix hash, and
executable-extension flagging as `file_metadata` events.

Every design decision follows from 520 KB of SRAM:

| Choice | Reason |
|---|---|
| SHA-256 over the first 4 KB (`CONFIG_HEXBEE_USB_HASH_BYTES`) | As the recommendation specified. Full-file hashing on the S3 would take hours and gains nothing Comb cannot do later on the Queen. Events carry `"partial_hash": true` so nothing downstream mistakes it for a full hash. |
| One event per file, streamed | No directory listing is ever assembled in RAM. |
| 512-file cap, depth 6 | Bounds the walk *and* how much one stick can flood the Hive. |
| Yield every 8 files | Otherwise the walk starves the Wi-Fi and MQTT tasks and the event buffer overflows. |
| `format_if_mount_failed = false` | An unrecognised filesystem is evidence. Formatting it destroys what you came for. |
| Filenames JSON-escaped | Names on a seized stick are attacker-controlled; an unescaped quote would corrupt the evidence record. |

Falls back to the original simulation mode when `CONFIG_HEXBEE_USB_HOST` is
off, so the pipeline still demos without hardware.

**Forensic caveat:** FATFS is mounted read-write by the MSC driver. HexBee
never writes, but "the software promises not to" is not a write blocker. For
acquisition intended to stand up in court, use a hardware write blocker and
image the device — the Scout's role is field triage, not seizure.

**Wiring:** host mode needs the S3's OTG pins wired for it — a 5 V supply
switched onto VBUS, D+/D− on GPIO19/20. Most dev boards ship device-only.

---

## 10. Log aggregation + anomaly detection  ✅ built

**Where:** `hive/hexbee_hive/syslog.py`, `hexbee-hive syslog`,
`POST /api/v1/logs`

Two inputs, one rule engine: a UDP syslog listener (RFC 3164 and RFC 5424
both parse) and a JSON endpoint for a Windows Event Log forwarder (NXLog
`om_http` / winlogbeat), authenticated with the ingest key.

Eight rules: `auth_bruteforce` (threshold, 5 in 300 s → T1110),
`privilege_escalation` (T1548.003), `account_created` (T1136.001),
`account_modified` (T1098), `service_installed` (T1543.003), `cron_added`
(T1053.003), `log_cleared` (T1027), `security_tool_stopped` (T1518.001).
Windows Event IDs (4625, 4672, 4720, 7045, 1102, …) are matched alongside
Unix log text.

**Raw log lines are never stored.** One datagram is handled at a time,
nothing is buffered, and only *findings* become events — a test feeds 21
lines and asserts exactly one evidence record comes out. That is what stops a
chatty network filling the Pi's SD card. Threshold rules keep a bounded deque
per (rule, host) and fire once per window rather than once per line
thereafter.

**Compatibility:** port 514 is privileged — either `setcap
cap_net_bind_service=+ep`, or `--port 5514` and an iptables redirect. The
socket uses a small receive buffer on purpose: under a flood, dropping
datagrams beats growing the kernel queue on a 1 GB host.

---

## 11. Auto pentest report from a Hive case  ✅ built

**Where:** `hive/hexbee_hive/engagement.py` (data),
`queen/hexbee_queen/engagement.py` (narration + rendering),
`hexbee-queen engagement report <case> -o out.html --pdf`

Structure exactly as recommended: Executive summary → Scope + methodology →
Attack narrative (ATT&CK-mapped) → Technical findings → Evidence chain
summary → Appendix.

**Deviation: assembly happens Hive-side.** Grouping five thousand events into
finding groups is two SQLite reads on the Pi; doing it on the Queen would mean
pulling five thousand rows across the API first. `GET
/api/v1/cases/<id>/engagement` returns the structured data, and both the
dashboard's [report preview](#ui-7) and the Queen's renderer consume it — so
the preview an analyst reviews and the document a client receives cannot
drift apart.

**Ollama calls are strictly sequential and capped at 10 groups.** `phi3:mini`
holds ~2.2 GB of the T470's 4 GB while generating; issuing these concurrently
is how you get an OOM kill halfway through a client deliverable.

**The report never depends on the AI.** Every section falls back to a
deterministic template built from the same data. If Ollama is not running —
or you are on battery and would rather it were not — the report is still
produced; only the prose quality changes. `--no-ai` skips it entirely.

Harvested secrets are redacted from the client-facing document (`material`,
`password`, `hash` → `[redacted — see evidence log]`). The HTML is entirely
self-contained: no CDN, no external font, no JavaScript, because this gets
read on an air-gapped machine and emailed to a client. `--pdf` runs it
through `wkhtmltopdf`, which is packaged for Kali and far lighter than a
headless browser on 4 GB.

---

## 12. Pico 1 — Stinger HID payload deployer  ⚠️ built, not hardware-validated

**Where:** `pico/badusb/code.py`, `boot.py`, `payloads/`, `pico/README.md`

CircuitPython. Enumerates as a USB keyboard and types a DuckyScript 1.0
payload. Payload selection is a file copy, not a reflash. The interpreter
supports `REM`, `DELAY`, `DEFAULT_DELAY`, `STRING`, `STRINGLN`, `REPEAT`, and
arbitrary modifier+key combinations; `REPEAT` is capped at 500 iterations so
a typo cannot lock up a target.

**It does not fire on plug-in alone.** An arm jumper (GP15–GND) is required;
a safe pin (GP14–GND) overrides it. Without arming it enumerates, prints what
it *would* have done, and stops. An implant that types the instant it touches
USB is a hazard to your own machines first.

When armed, `boot.py` hides the mass-storage drive and enables only the
keyboard, then remounts the filesystem writable so the board can log its own
deployment — a target host can neither mount the drive nor tamper with the
log.

**Reporting, given no radio:** each run appends to `deploy.log` on the Pico's
own drive with a payload fingerprint, result, line count, and keystroke
count. Import it afterwards:

```bash
hexbee-queen pico hid /media/$USER/CIRCUITPY/deploy.log --case 3 --target RECEPTION-PC
```

Each line becomes a `hid_deployment` event (T1200 + T1059).

**On the payload library:** the recommendation listed reverse-shell droppers
and credential harvesters as payload ideas. The *engine* is complete and runs
any DuckyScript you write. The payloads shipped in the repo are
demonstrative — proof-of-execution, read-only host enumeration, workstation
lock. Payloads that only make sense as live attack tooling belong in your own
engagement notes, alongside the authorisation that covers them.

---

# Tier 3

## 13. RPi drop box + reverse SSH tunnel  ✅ built

**Where:** `queen/hexbee_queen/pivot.py`, `hexbee-queen pivot
generate|status|connect`

`pivot generate` renders the Pi's `autossh` systemd unit and a reviewable
setup script — it does not silently reconfigure a remote host. `pivot
connect` opens a shell through an established tunnel. Session start and end
are written to the Hive as `pivot_session` events, so the engagement record
shows when remote access existed.

The reverse forward binds to `127.0.0.1` on the Queen only (`GatewayPorts`
stays `no`), so nothing on the Queen's network can reach the drop box
through it.

**RAM, as flagged in the recommendation:** the unit sets `MemoryMax=64M` —
autossh itself is tiny, so a short pivot alongside a running Hive is fine.
`--hive-pause` stops the dashboard (`hexbee-web`, ~150 MB) for the session
while **leaving ingest running**. Losing evidence to save memory would be the
wrong trade, and a test asserts `hexbee-engine` is never in the stop list.

**Power:** unchanged from the original estimate — two power banks give
roughly 10 hours of Pi runtime unplugged. Plan drop-box operations around it.

---

## 14. Forager memory acquisition  ✅ built

**Where:** `forager/hexbee_forager/memory.py`, `hexbee-forager memory <dest>`

Methods: LiME (Linux), winpmem (Windows), `/proc/kcore` as a last resort.
The acquisition tool writes the image itself; Forager never holds it. Hashing
streams the file back in 8 MB chunks, so peak memory for a 64 GB dump is one
chunk — a test asserts the incremental read rather than trusting it.

Free space is checked **before** acquisition starts (image + 10%), because
running a target out of disk mid-dump is worse than not dumping at all.
`--dry-run` runs the prechecks alone; `--status` reports what would be used.

Only the path, size, and SHA-256 enter the chain (`memory_acquired`). A 16 GB
image belongs on the HDD, not in an evidence database on an SD card.

**Stated plainly in the CLI and in the event:** this is the one Forager
operation that is not strictly read-only. LiME and winpmem load a kernel
driver on the target. That is unavoidable for live memory capture, and the
tool says so rather than implying otherwise.

**Volatility is deliberately not invoked here.** It uses ~500 MB–1 GB during
analysis; run it on the Queen, against the file on the HDD, when Ollama is
not active. The `memory_acquired` event carries the next command to run.

---

## 15. BloodHound AD ingest  ✅ built

**Where:** `queen/hexbee_queen/bloodhound.py`, `hexbee-queen bloodhound <path>`

Parses SharpHound / bloodhound.py output — directory, single `.json`, or
zipped bundle — and extracts the four findings that actually drive an
internal AD report: kerberoastable accounts (T1558.003), AS-REP roastable
accounts (T1558.004), unconstrained delegation hosts (T1558), and privileged
group membership (T1078). Each becomes an `ad_recon_finding` carrying the
discriminator the ATT&CK tagger keys on.

Files are read one at a time; a large domain's `users.json` is tens of MB,
which is fine on the T470 singly and would not be as a whole bundle.
Unreadable or malformed files are skipped with a warning.

**Not reimplemented:** the BloodHound *graph*. Path-finding is what the
BloodHound UI is for. This bridge captures findings so they join the evidence
chain and the report.

---

## 16. Offline threat intel sync  ✅ built

**Where:** `hive/hexbee_hive/intel.py`, `hexbee-hive sync-intel`,
`hexbee-hive intel-status`, Admin page

Pre-deployment command — the only Hive command that touches the internet.
Feeds: URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker (recent and full
variants), plus any MISP feed via `HEXBEE_MISP_FEED_URL`. Downloads stream to
a temp file and import in 5,000-row batches; nothing is read whole into RAM.

**The intel DB is a separate file** (`<data_dir>/intel/intel.db`), not part of
`hive.db`. Point `HEXBEE_DATA_DIR` at the HDD and a large feed never lands on
the SD card, and the evidence database stays small enough to copy off quickly.

**Lookups are indexed exact matches, unlike the analyst IOC watchlist's
substring scan.** Candidate values (hashes, IPs, domains, URLs) are extracted
from the payload first, then looked up by index. A linear scan across 250,000
intel rows for every ingested event would flatten a Pi 3B+. Private address
space is skipped entirely, and extraction is capped at 40 candidates so a
pathological payload cannot cause a query storm.

A feed hit is auto-promoted into the analyst watchlist with its provenance,
so it appears on `/iocs` and gets the full treatment: severity 3, an
auto-incident, the `ioc` tag, and an audit entry.

**Compatibility note:** abuse.ch now requires a free account for most
downloads. Set `HEXBEE_ABUSE_CH_KEY` to your Auth-Key; a 401/403 produces
exactly that message rather than a generic failure.

---

## 17. Pico 2 — Sentinel hardware evidence-seal token  ⚠️ built, not hardware-validated

**Where:** `pico/sentinel/code.py`, `boot.py`, `queen/hexbee_queen/pico.py`,
`hexbee-queen pico seal|provision`

The original recommendation was a button that triggers `hexbee-hive anchor`.
This is that, strengthened: **a signed seal, not just a press.**

The token holds a per-device HMAC key in its own flash and signs each seal
over `(device id, kind, counter, nonce, chain head)`. Consequences:

- the seal is attributable to **one specific physical token** you can hand to
  a witness — not merely proof that some button somewhere was pressed;
- the counter is monotonic and persisted, so replays are detectable (the
  Queen keeps a per-token high-water mark and rejects anything that goes
  backwards);
- when the Queen pushes the current chain head before a press, the signature
  **binds the seal to a specific state of the evidence log**.

A seal press writes a `case_seal` event and requests a signed chain anchor.
A seal that fails verification is still recorded, with the reason — a failed
seal is itself something the case should show. A second button (hold 2 s)
emits a `tamper_mark`.

**Stated honestly in the code, the README, and the evidence record:**

- The key lives in flash on a microcontroller with no secure element. It
  resists forgery by someone without the token; it does **not** resist someone
  who has the token and a debugger. This is a custody aid, not an HSM.
- A plain Pico has no real-time clock, so the token cannot timestamp its own
  seals. Time comes from the Queen, and every payload says
  `timestamp_source: queen (token has no real-time clock)`.

The recommendation's UART→C3 idea was dropped: USB serial to the Queen is
simpler, needs no second board in the loop, and gives a bidirectional channel
(which is what makes the chain-head binding possible).

---

# Web UI improvements

All seven built. No external JavaScript, no CDN, CSP-nonce safe, fully offline.

<a id="ui-1"></a>
**1. Mode indicator banner** — `cases.mode` is `ir` | `pentest` |
`diagnostics`, set from the case page or `hexbee-queen mode`. The banner
colours differently per mode (pentest is red-tinted on purpose — misreading
the mode is how an operator runs the wrong playbook), and the dashboard
highlights that mode's event types in the evidence table.

<a id="ui-2"></a>
**2. ATT&CK coverage heatmap** — a CSS grid macro in `macros.html`, reused on
the dashboard, case page, and report preview. Intensity is **bucketed, not
continuously scaled**, so the same colour always means the same thing across
cases. A dedicated `/attack` page gives the full technique breakdown,
filterable by case.

<a id="ui-3"></a>
**3. Live event feed** — Server-Sent Events at `/api/v1/stream`, as
recommended (SSE over WebSockets: one plain HTTP response, no library, and
the browser reconnects by itself when the Pi's Wi-Fi drops). The server closes
the stream after 5 minutes and the browser silently reopens it, so no thread
is pinned forever. Feed rows are built with `textContent` throughout —
evidence payloads are attacker-influenced data and must never be parsed as
markup. This replaced the old 30-second full-page reload.

<a id="ui-4"></a>
**4. Scope enforcer UI** — full CRUD on the Admin page (`/admin#scope`) with
authorisation reference, time window, and case binding. It states the current
enforcement mode and warns explicitly when an empty table means everything is
blocked. No more direct DB access.

<a id="ui-5"></a>
**5. Device map clustering** — grid clustering in Web Mercator pixel space,
computed **server-side** for the zoom the viewer is currently showing. The Pi
does the arithmetic once per zoom change instead of the browser redoing it on
every pan, and the viewer stays dependency-free. Clusters size and label
themselves, show a sample of members on hover, and zoom in on click. Requests
are debounced so a wheel-spin is one call, not ten.

<a id="ui-6"></a>
**6. Quick triage panel** — one click on an incident sends a *structured*
prompt (severity call, three investigative steps, one containment action) to
Hive Mind, rather than requiring the analyst to compose a good question under
time pressure. Falls back to the rule-based engine when no model is running.
Available as `POST /api/v1/incidents/<id>/triage` and as a button on the
incident page.

<a id="ui-7"></a>
**7. Report preview** — `/cases/<id>/preview` renders the engagement report
from the same structured data the exported document uses. Rendered as a page,
not an embedded frame: the Hive sets `frame-ancestors 'none'`, and weakening
that for a convenience feature would be the wrong trade.

---

# Addition: the assistant knows how to operate HexBee  ✅ built

**Where:** `hive/hexbee_hive/knowledge.py`, `scripts/build_knowledge.py`,
`ai.py`, `POST /api/v1/ai/howto`, `hexbee-hive howto`, `hexbee-queen ai how`

Not in the original recommendations, but necessary once Hive Mind became the
operator's front door: the assistant knew the *evidence* and nothing about the
*tool*. Asked "how do I seal a case", a 1–3B local model invents a plausible
command — which is worse than refusing, because the operator will try it.

So the model is never asked to recall anything. Retrieval finds the matching
manual sections, and the model is handed those with instructions that it may
not go beyond them.

**The command reference is generated, not written.** `build_knowledge.py`
walks all five argparse trees and snapshots 78 commands; event types come from
`normalize.EVENT_SEVERITY`, technique mappings from `attack`. A hand-written
manual drifts the moment a flag is renamed; a generated one cannot tell an
operator to run something that no longer exists. A test asserts the snapshot
is current.

**Retrieval is BM25, not embeddings.** No embedding model, no vector store, no
extra resident memory on a machine that has none to spare — and deterministic
results you can debug. Curated aliases (`KEYWORDS`) carry the operator's
vocabulary: "usb stick", "rubber ducky", "air gapped".

Three things that took real tuning, all covered by tests:

- **Command docs were outranking recipes.** One line each, so standard length
  normalisation handed them the win. Fixed with `b=0.4` and kind weighting.
- **Evidence questions were routing to the manual.** "was evil.exe seen
  anywhere" scored 26 because *evil* and *exe* both appear in the manual.
  Fixed by scoring routing over curated documents only, plus direct detection
  of artifact markers (filenames, IPs, hashes, device names) which veto the
  manual route.
- **Weak single-term matches passed as answers.** "write me a poem" matched
  the report recipe because it mentions writing. Fixed with a term-coverage
  requirement.

**It works with no model at all.** The fallback returns the matching manual
section verbatim, which for a command lookup is the correct answer rather than
a degraded one.

---

# Limitations

## The assistant's knowledge

- **Retrieval is lexical.** It matches words, not meaning. A question phrased
  entirely in vocabulary absent from the manual and the alias table will miss,
  and the fix is to add the alias rather than to hope.
- **Coverage is what is written.** 33 recipes and 5 concepts cover the common
  operator tasks. A question about something nobody wrote a recipe for gets an
  honest refusal, not an answer.
- **The snapshot must be regenerated after CLI changes.** `python
  scripts/build_knowledge.py`, and commit the result. A test fails if it drifts
  for the commands it checks, but it cannot catch every rename.
- **Grounding constrains the model; it does not compel it.** The prompt
  forbids inventing commands and every answer cites its sources so you can
  check, but a small model can still paraphrase badly. The `sources` field
  exists precisely so you can go and read what it was actually shown.
- **Only the Hive holds the manual.** Queen and CLI clients ask the Hive, so
  an unreachable Hive means no assistance — the same failure mode as every
  other Queen feature.

## What is not validated on hardware

Everything below is written and reviewed but has **not been run on the
physical device**. This is the honest state of the build.

| Component | Status | What validation needs |
|---|---|---|
| Scout USB MSC host (#9) | Compiles conditionally; logic unexercised | An S3 board with OTG host wiring (VBUS supply, D+/D− on GPIO19/20) and the `usb_host_msc` component vendored in |
| ESP32-C3 scanner (#2) | Not run on a C3 | A flashed board; verify BLE IRQ constants and the `WLAN.scan()` tuple layout for your MicroPython build |
| Pico Stinger (#12) | Not run on a Pico | CircuitPython + the `adafruit_hid` bundle in `/lib`; confirm `boot.py` remount and drive-hiding behaviour on your CircuitPython version |
| Pico Sentinel (#17) | Not run on a Pico | A CircuitPython build with a `hashlib` providing SHA-256 (`adafruit_hashlib`), plus USB CDC data endpoint enumeration |
| Netmon raw capture | Decoder and rules unit-tested against synthetic frames; not run against a live interface | A Linux host with `CAP_NET_RAW` and real traffic |
| Memory acquisition (#14) | Prechecks, hashing, and event shapes tested; no dump performed | LiME built for your kernel, or winpmem on a Windows target |

The Python side — Hive, Comb, Forager, Queen, Netmon decoding and rules — is
covered by **332 passing tests**, run on Linux, macOS and Windows by CI on
every push. CI also fails the build if the assistant's generated command
reference drifts from the actual CLIs, and lints the installer.

## Bugs found by auditing the finished build

Three shipped before they were caught. All are fixed, with regression tests:

- **Threat-feed hits were poisoning the ingest hot path.** Feed indicators
  were promoted into the analyst watchlist, which is scanned by substring
  against every string of every ingested event. A synced feed therefore made
  ingest slower over time — exactly what the separate indexed intel database
  exists to prevent. Feed rows are now excluded from that scan (they are
  already matched by index) and shown separately in the UI. Measured: 150
  accumulated feed hits, 0 rows scanned per event, ingest time flat.
- **The assistant misrouted beginner questions.** The pattern that recognises
  device names like `Scout01` also matched `SHA256` and `Windows10`, so "what
  is a SHA256 hash" was treated as a question about specific evidence and
  answered with hive statistics. Glossary lookups now take precedence and
  known technical terms are excluded.
- **Live streams could starve ingest.** Each Server-Sent Events connection
  pins a thread and polls SQLite through one shared connection; several
  forgotten browser tabs would contend with evidence ingest on a 1 GB Pi.
  Concurrent streams are now capped, with the slot released on any exit path.

Verified sound while checking: shell scripts are LF in the repository (so the
installer runs on macOS), and the hand-rolled HMAC in the Pico Sentinel
firmware matches Python's `hmac` on every vector including the over-length
key path — a silent mismatch there would have made every evidence seal fail
verification for no visible reason.

## Capability limits by design

- **Netmon sees only what reaches the interface.** On a switched network
  without a SPAN/mirror port or an inline tap, that is broadcast, multicast,
  and the Pi's own traffic — enough for ARP spoofing, DHCP, mDNS, and
  broadcast discovery, but not another host's unicast sessions.
- **Detection is header-only.** Anything needing payload inspection — TLS
  fingerprinting, protocol decoding, file extraction from streams — is out of
  scope for this hardware.
- **802.11 rules need monitor mode.** The Pi 3B+'s onboard `brcmfmac` radio
  cannot do monitor mode reliably; use a supported USB adapter. This applies
  to `deauth_flood` and to any probe-request work.
- **The C3 sees access points, not clients.** MicroPython does not expose raw
  802.11, so SSID-preference harvesting from probe requests is unavailable on
  that board (see #2 for the two workarounds).
- **The C3 scans in cycles, not continuously.** A device that appears and
  leaves between cycles is missed. Shorten the interval at the cost of power.
- **No BLE 5 extended advertising** on the C3 — MicroPython's `bluetooth`
  module handles legacy advertisements only.
- **Scout hashes are partial.** 4 KB prefixes fingerprint a file and catch
  header/extension mismatches; they are not full-file hashes and are labelled
  `partial_hash: true` everywhere.
- **The Scout is not a write blocker.** FATFS mounts read-write. Use hardware
  write blocking for anything intended for court.
- **Neither Pico has a radio.** No live reporting from the Stinger, no
  self-timestamping on the Sentinel. Both are documented rather than hidden.
- **The Sentinel key is not hardware-protected.** No secure element on an
  RP2040.
- **Intel matching is exact, not fuzzy.** A URL that differs by a query
  parameter will not match a feed entry. That is the price of indexed lookups
  fast enough for a Pi.
- **The IOC watchlist is still a linear substring scan.** Fine at hundreds of
  analyst-entered indicators; the intel DB exists precisely because it does
  not scale to hundreds of thousands.
- **Log anomaly rules are regex, not correlation.** They catch the classic
  signatures listed in #10. They do not do cross-host sequence analysis or
  behavioural baselining.
- **BloodHound path-finding is not reimplemented.** Use the BloodHound UI for
  graphs; this imports findings.
- **Report narration quality depends on `phi3:mini`.** A 3.8B model on 4 GB
  produces serviceable finding paragraphs, not a senior consultant's prose.
  Every paragraph is meant to be reviewed before the report goes out.

## Operational limits

- **Scope enforcement is advisory outside HexBee.** It gates HexBee's own
  tooling. Nothing stops an operator running raw `nmap` from a shell — the
  gate is a control, not a sandbox.
- **`sync-intel` needs internet and, for abuse.ch, an account.** Run it at
  home before deployment; set `HEXBEE_ABUSE_CH_KEY`.
- **Port 514 needs privileges.** Use `--port 5514` or grant
  `cap_net_bind_service`.
- **Diagnostics mode transmits.** `ids` and `recon` are receive-only;
  `diagnostics` pings and resolves against the host's own gateway and
  resolvers.
- **The pivot competes with the Hive for RAM.** Short engagements are fine;
  for long ones use `--hive-pause`, which keeps ingest running and stops only
  the dashboard.
- **Volatility, Ollama, and Metasploit cannot comfortably share 4 GB.** Run
  them one at a time. The report generator queues its AI calls for this
  reason.

## Deliberate omissions

- **Credential material is fingerprinted, not stored**, unless
  `--include-material` is passed (#7).
- **YARA records matched string identifiers, not matched bytes** (#3).
- **Weaponised HID payloads are not in the repo**; the interpreter runs
  whatever you supply (#12).
- **ATT&CK attribution is stored outside the hash chain** (#6) — it is
  interpretation, not evidence.

---

# Build order actually followed

```
Scope enforcer + ATT&CK tagger        no hardware, pure Python, unblocks everything
Syslog/SIEM + offline threat intel    Hive-side, low RAM, high value
hexbee-netmon                         biggest capability gap; blue + red + diagnostics
YARA in Comb                          extends the existing scan pass
Forager diagnostics + memory          reuses all existing agent plumbing
Queen engagement tooling              responder, recon, bloodhound, pivot, report
Firmware                              C3 scanner, Scout USB host, both Picos
Web UI                                all seven improvements
Tests + docs                          233 tests, this document
```

---

*Built against the existing HexBee architecture: `hive/`, `comb/`,
`forager/`, `queen/`, `netmon/`, `scout/`, `pico/`. All new code follows the
existing conventions — one write path into the evidence chain, offline by
default, optional dependencies degrade with an explanation rather than
failing.*
