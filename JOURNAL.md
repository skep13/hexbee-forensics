# HexBee Forensics — Build Journal

A distributed digital forensics & incident response (DFIR) platform.
**Detect · Isolate · Analyse.**

- **Builder:** skep13
- **Repo:** https://github.com/skep13/hexbee-forensics
- **Hardware:** ESP32-S3 (Scout) · Raspberry Pi 3B+ (Hive) · Kali ThinkPad T470 (Queen) · iPhone XR (field companion)

> **How to read this journal.** The upper section is a chronological
> **development log** of build sessions. The lower section is a complete
> **inventory** of every part built, plus the hardware, constraints, and end
> goal. Each log entry has a `Time:` line — fill in your actual working time
> per session, and add photos/screenshots as you go (drop images in a
> `journal/` folder and link them). Do **not** invent hours; log real ones.

---

## Development log

### Entry 1 — Platform core (Hive)
**Time:** _(fill in)_

Built the heart of the Hive on a Raspberry Pi–friendly, 1 GB-RAM-conscious
design:

- SQLite schema + thread-safe wrapper (WAL mode, single lock).
- **Evidence integrity via a SHA-256 hash chain** — each event commits to the
  entire history before it, so any edit/deletion breaks verification.
- Event **normalization** (accepts ISO-8601 or epoch timestamps; per-type
  severity table).
- Single write path (`store_event`) feeding an event-driven **incident
  correlation engine** (severity ≥ 2 opens/extends an incident and pulls in
  recent same-device context).
- **Timeline** reconstruction, **case management** (`HB-YYYY-NNNN`), **auth +
  RBAC** (PBKDF2, tokens, viewer/investigator/administrator), **search**, and
  an **append-only audit log**.

*Decision:* hash-chain over per-event hashes, because a single hash proves a
record wasn't corrupted but not that nothing was deleted or reordered.

### Entry 2 — Web dashboard + REST API
**Time:** _(fill in)_

One Flask app serving both the analyst dashboard and a versioned `/api/v1`
REST surface, sharing a single token auth path. HTML/JSON/CSV **report
engine**. Honey-on-black themed, server-rendered templates.

### Entry 3 — Queen analyst CLI + Scout firmware & simulator
**Time:** _(fill in)_

- **Queen** (`hexbee-queen`): stdlib-only REST client + CLI for cases,
  incidents, timeline, search, reports.
- **Scout firmware** (ESP-IDF, C): Wi-Fi station + auto-reconnect, SNTP,
  MQTT publish (QoS 1), heartbeat, and a RAM **offline event buffer** that
  flushes in order on reconnect. `usb_watch` runs in simulation mode until the
  TinyUSB acquisition path is validated on real silicon.
- **Scout simulator** (Python): emits the exact JSON a real Scout sends, so
  the full pipeline runs with no hardware (`quiet`/`usb`/`incident` scenarios).

### Entry 4 — Deployment + first end-to-end test
**Time:** _(fill in)_

Raspberry Pi `install.sh` (Mosquitto, dedicated user, virtualenv, DB init,
systemd services that auto-start headless), systemd units, and docs. Ran the
simulator against a live Hive: events → auto-correlated incident → case →
report → verified hash chain. First green test suite.

### Entry 5 — Branding + IOC engine
**Time:** _(fill in)_

- Integrated the official **HexBee Forensics logo** (favicon, navbar, login,
  embedded in reports) with generated size variants.
- **IOC engine**: watchlist (sha256/filename/ip/domain/substring) matched at
  ingest; a hit escalates to critical, opens/extends an incident, tags the
  event, and audit-logs it. Added Devices, IOCs, and Audit pages.

### Entry 6 — Comb forensic triage toolkit (Autopsy/AXIOM-class)
**Time:** _(fill in)_

Queen-side analysis toolkit whose findings upload into the Hive's evidence
chain: magic-byte typing + **extension-mismatch detection**, **file carving**
from raw images, **MBR/GPT** partition parsing, **EXIF/GPS** extraction,
**browser history** (Chrome/Firefox), optional **Sleuth Kit** integration, and
a scan pipeline + branded report.

### Entry 7 — Offline maps, reference library, and local AI
**Time:** _(fill in)_

- **Offline evidence map**: zero-dependency slippy map serving standard
  MBTiles, plotting GPS coordinates recovered from evidence.
- **Offline reference library**: serves ZIM archives (offline Wikipedia) plus
  local HTML/Markdown/PDF field docs.
- **Hive Mind local AI**: case summaries + evidence Q&A via a local Ollama
  model, with a deterministic rule-based fallback (fully offline).

### Entry 8 — iPhone XR field companion + QR evidence labels
**Time:** _(fill in)_

Installable **PWA** at `/field` (Add to Home Screen, no App Store): view open
incidents, photograph evidence **directly into the hash chain**, and per-case
**QR labels** the iPhone camera scans to open a case. Mobile-responsive across
all pages. Test suite grew to **48 passing tests**.

### Entry 9 — Ship prep: Kali setup, docs, LICENSE, hardware BOM
**Time:** _(fill in)_

Kali `setup-kali.sh` for the Queen (pipx + Sleuth Kit), disk-image mounting
workflow docs, a forensic-hygiene fix (browser DB copies are shredded after
reading), MIT `LICENSE`, and a hardware **bill of materials + wiring**
([docs/HARDWARE.md](docs/HARDWARE.md)). Published to GitHub.

### Entry 10 — Security & forensic hardening
**Time:** _(fill in)_

Raised the platform to a professional field-forensics standard:

- **OWASP Top 10 pass** (see [SECURITY.md](SECURITY.md) for the full mapping):
  strict Content-Security-Policy with **per-response script nonces**, full
  security-header set, **HMAC CSRF tokens** on all dashboard forms,
  **login rate-limiting + lockout**, constant-time secret comparison,
  a strong **password policy** (NIST 800-63B style), IP-stamped audit logging,
  secure-cookie/HSTS support, and a `hexbee-hive security-check` command.
- **Forensic evidence upgrades** (see [docs/FORENSICS.md](docs/FORENSICS.md)):
  **signed chain-anchor receipts** (pin the log head so history can't be
  rewound/truncated), **HMAC-signed evidence-export bundles** (manifest +
  per-file hashes + full audit trail, verifiable offline), and Comb
  **multi-hash** (MD5/SHA-1/SHA-256) for cross-tool verification.
- Test suite grew to **63 passing tests** (added `test_security.py`).

### Entry 11 — Forager: autonomous live-response collector
**Time:** _(fill in)_

Built **HexBee Forager** (`forager/`), a read-only agent that collects forensic
evidence from a live host on its own — no interactive input:

- Cross-platform collectors (psutil + stdlib/native fallbacks): host info,
  processes, network connections with owning process, logged-on users,
  persistence/autoruns (registry Run keys, startup, cron, systemd), USB
  history, and recent files.
- Autonomous by design: Hive location auto-discovered (args → env → config
  file); every collector runs automatically; a `watch` mode continuously
  samples and emits `process_new` / `network_new` / `logon_new` / `usb_new`
  events when something appears. Offline events **spool locally and retry**.
- Ships through the same `/ingest` path as everything else, so findings are
  hash-chained, correlated, IOC-matched, and export-ready.
- **Live-verified**: collected 460+ real artifacts from the dev host into the
  Hive (persistence entries, network connections with process names) — chain
  verified over 950+ events. New event types registered in the normalizer.
- Test suite now **73 passing** (added `test_forager.py`).

### Entry 12 — Point-and-click UIs (usability pass)
**Time:** _(fill in)_

Made the whole platform usable without the command line:

- **Hive Admin page** (`/admin`, administrators): point-and-click user
  management (create/enable/disable), a live security-posture report, chain
  verification, and one-click signed-anchor download.
- **Comb web UI** (`hexbee-comb serve`): a stdlib-only local browser page —
  paste a target path, click **Scan**, view the report, optionally push to the
  Hive. No commands, no extra dependencies.
- **Forager USB launcher** is now a **menu** (Collect / Monitor / Status) on
  Windows and Linux, so a responder just double-clicks and picks an option.
- Refactored the security posture into a shared `ops.py` used by both the CLI
  and the Admin page. Tests: **81 passing** (added `test_ui.py`).

### Entry 13 — Scout hardware bring-up (in progress)
**Time:** _(fill in)_

_Next hardware milestone — log as you go:_

- [ ] Flash the firmware onto a physical ESP32-S3 and confirm Wi-Fi + MQTT to
      the Pi (heartbeats appear on the dashboard).
- [ ] Implement the real **TinyUSB** device-mode enumeration on the target PC
      (replace the simulated insertion in `usb_watch.c`).
- [ ] MSC-host triage of an attached USB stick (file metadata → events).
- [ ] Photograph the assembled Scout + a live capture on the dashboard.
- [ ] (Stretch) per-Scout cryptographic identity + event signing; MQTT TLS.

---

## Hardware used

### Scout — ESP32-S3
USB-OTG field agent that plugs into a target computer. Flash storage only,
limited RAM, USB/battery powered. **Constraints:** acquisition and triage
only — no heavy analysis, no databases; everything it sends is small JSON.

### Hive — Raspberry Pi 3B+
Always-on, headless evidence hub. Quad-core Cortex-A53, **1 GB RAM**, boots
from USB SSD. **Constraints:** 1 GB RAM forces SQLite over PostgreSQL,
event-driven processing over batch jobs, and memory-capped services.

### Queen — Lenovo ThinkPad T470 (Kali Linux)
Analyst workstation where heavy analysis (Comb) runs. No significant limits.

### iPhone XR — field validation terminal
Not an acquisition device: human validation, QR scanning, evidence
photography, and offline field reference via a home-screen web app.

See [docs/HARDWARE.md](docs/HARDWARE.md) for the full BOM, pinout, and
assembly.

---

## Software built (complete inventory)

Python 3 unless noted; Scout firmware is C/ESP-IDF; front-end is vanilla
HTML/CSS/JS.

### Hive — `hive/hexbee_hive/`
`config.py` (env config + data-dir layout), `db.py` (SQLite schema +
thread-safe wrapper), `integrity.py` (hash chain + verification),
`normalize.py` (canonical event shape), `store.py` (single write path),
`correlate.py` (incident correlation engine), `timeline.py` (narrative
timeline), `cases.py` (cases/notes/tags), `auth.py` (PBKDF2 + RBAC),
`search.py` (filter + stats), `reports.py` (HTML/JSON/CSV), `ingest.py`
(MQTT + REST pipeline), `ioc.py` (IOC watchlist + matching), `maps.py`
(MBTiles tile server + evidence points), `reference.py` (ZIM + document
library), `ai.py` (Hive Mind local AI + rule-based fallback),
`security.py` (CSP/nonces, security headers, HMAC CSRF, login rate limiter),
`evidence_export.py` (signed bundles + chain anchors), `api.py` (Flask
REST + dashboard), `cli.py` (`hexbee-hive` command). Plus 22 HTML templates,
logo/PWA static assets, `install.sh`, two systemd units, packaging.

### Queen — `queen/hexbee_queen/`
`client.py` (stdlib REST client), `cli.py` (`hexbee-queen` command),
`setup-kali.sh`.

### Comb — `comb/hexbee_comb/`
`magic.py`, `inventory.py`, `carver.py`, `diskimage.py`, `exif.py`,
`browser.py`, `tsk.py`, `analysis.py`, `cli.py` (`hexbee-comb` command).

### Forager — `forager/hexbee_forager/`
`collectors.py` (read-only host collectors), `agent.py` (autonomous
orchestration, offline spool, watch-mode deltas), `cli.py` (`hexbee-forager`
command), systemd unit.

### Scout — `scout/`
Firmware `main/scout_main.c`, `event_buffer.c/.h`, `usb_watch.c/.h`, CMake +
Kconfig + `sdkconfig.defaults`; Python simulator `scout/simulator/scout_sim.py`.

### Tests — `tests/` (48 passing)
`test_core.py`, `test_api.py`, `test_ioc.py`, `test_comb.py`,
`test_field_features.py`, `conftest.py`.

### Docs — `README.md`, `docs/ARCHITECTURE.md`, `docs/DEPLOYMENT.md`,
`docs/API.md`, `docs/COMB.md`, `docs/HARDWARE.md`, `JOURNAL.md`, `LICENSE`.

---

## Design principles honoured
- **One write path** — MQTT and REST both funnel through `store_event`, which
  is what makes the hash chain trustworthy.
- **SQLite on 1 GB RAM** — WAL, single lock, event-driven correlation.
- **Stdlib-first** — auth, Queen client, map viewer, and AI/reference
  fallbacks avoid heavy deps so the air-gapped Pi and a bare Kali both work.
- **Fully offline** — maps, reference/Wikipedia, and AI run on the LAN; each
  degrades gracefully without its optional data/model.
- **Evidence hygiene** — browser DBs copied then shredded; targets never
  opened read-write; every analyst action audit-logged.

---

## What HexBee does when done

A field-deployable DFIR platform where a **Scout** on a suspect machine streams
tamper-evident events to a headless **Hive**, which hash-chains and
auto-correlates them into incidents with timelines; **IOC** watchlists
auto-escalate known-bad indicators; the **Queen** runs **Comb** to triage
seized disk images (carving, partitions, EXIF/GPS, browser history, Sleuth Kit)
straight into the same evidence chain; analysts work cases via web + CLI, plot
GPS on an **offline map**, consult an **offline Wikipedia**, ask a **local AI**
to summarise, and export verifiable reports; and an **iPhone XR** serves as a
field companion for photographing evidence into the chain and scanning case QR
labels — every layer offline, from acquisition to signed report.
