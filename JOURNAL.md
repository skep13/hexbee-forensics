# 🐝 HexBee Forensics — Development Journal

A distributed digital forensics & incident response (DFIR) platform.
**Detect · Isolate · Analyse.**

This journal documents every part built for HexBee: the hardware it runs on,
the constraints each device imposes, every software component written, and
what the finished platform does. Entries are organised by build phase and
component rather than by time.

---

## The concept

Traditional forensic suites (Autopsy, Magnet AXIOM) run everything on one
powerful workstation. HexBee instead spreads the work across a *hive* of
purpose-built devices, each with one clear responsibility, and keeps the whole
pipeline **fully offline** with tamper-evident evidence integrity from the
moment of collection.

```
Target Computer ──USB──> 🐝 Scout (ESP32-S3 field agent)
                              │ Wi-Fi / MQTT
                              ▼
                         🏠 Hive (Raspberry Pi 3B+ evidence hub)
                              │ Wi-Fi / REST
             ┌────────────────┼────────────────┐
             ▼                ▼                 ▼
     👑 Queen (Kali T470)  📱 iPhone XR      🧠 Hive Mind
     analysis + Comb       field companion   local AI (offline)
```

---

## Hardware used

### 🐝 Scout — ESP32-S3
The field acquisition agent that plugs into a target computer.

- ESP32-S3 microcontroller with USB-OTG (device) capability
- Wi-Fi radio
- Flash storage only, limited RAM (~512 KB SRAM)
- USB / battery powered

**Constraints:** cannot perform heavyweight analysis, tiny storage, no
databases, suitable only for acquisition and triage. Everything it sends must
be small JSON.

### 🏠 Hive — Raspberry Pi 3B+
The always-on evidence aggregation hub. Headless (no monitor/keyboard/mouse),
boots from a USB SSD, runs Raspberry Pi OS Lite 64-bit.

- Quad-core Cortex-A53, **1 GB RAM**
- Wi-Fi or Ethernet

**Constraints:** 1 GB RAM forces SQLite over PostgreSQL, event-driven
processing instead of batch jobs, and per-service memory caps. Designed as an
evidence hub, not an analysis workstation.

### 👑 Queen — Lenovo ThinkPad T470
The analyst investigation workstation running **Kali Linux**.

- Full desktop environment, no major hardware limits for this project
- Kali's forensics tooling (Sleuth Kit, mount helpers) available

**Constraints:** none significant; this is where heavy analysis (Comb) runs.

### 📱 iPhone XR — field validation terminal
Not a forensic acquisition device. Used for human validation, QR scanning,
evidence photography, and offline field reference via a home-screen web app.

---

## Software built

Everything below was written for this project. Language is Python 3 unless
noted (Scout firmware is C / ESP-IDF; front-end is vanilla HTML/CSS/JS).

### 🏠 Hive — `hive/hexbee_hive/` (the platform core)

| File | What it does |
|------|--------------|
| `__init__.py` | Package + version metadata |
| `config.py` | All settings from `HEXBEE_*` environment variables; data-dir layout (db, exports, maps, reference, evidence); AI endpoint config |
| `db.py` | SQLite schema + thread-safe wrapper (WAL mode, one process-wide lock, transaction context manager). Tables: devices, events, incidents, cases, case_notes, tags, event_tags, users, api_tokens, iocs, ioc_hits, audit_log |
| `integrity.py` | The evidence **hash chain**: `event_hash = SHA-256(prev_hash ‖ canonical_event)`; canonical JSON; full-chain verification |
| `normalize.py` | Converts loose Scout/Comb JSON into one canonical event shape; accepts ISO-8601 or epoch timestamps; per-type severity table (0 info → 3 critical); rejects malformed events |
| `store.py` | The single write path into the evidence log; device upsert; audit helper |
| `correlate.py` | **Incident correlation engine** — severity ≥ 2 events open an incident and retroactively pull in recent same-device context events within a time window; escalates severity; event-driven (cheap on 1 GB RAM) |
| `timeline.py` | **Timeline reconstruction** — renders raw events into human-readable narrative entries per incident/case |
| `cases.py` | **Case management** — cases (auto-numbered `HB-YYYY-NNNN`), notes, tags, incident assignment, status |
| `auth.py` | **Authentication + RBAC** — PBKDF2-HMAC-SHA256 passwords (stdlib only), bearer tokens with TTL, three ranked roles (viewer ⊂ investigator ⊂ administrator) |
| `search.py` | Evidence search/filter (device, type, time, incident, tag, free-text over payload) + platform statistics |
| `reports.py` | **Report engine** — self-contained HTML (with embedded logo), JSON, and CSV case reports; integrity status baked in |
| `ingest.py` | Ingest pipeline (normalize → IOC check → store → correlate); MQTT subscriber (paho-mqtt, auto-reconnect, optional TLS) and the shared `process_raw_event` used by REST too |
| `ioc.py` | **IOC engine** — watchlist (sha256/filename/ip/domain/substring) matched against every event at ingest; a hit escalates to critical, records a hit, tags the event, audit-logs it |
| `maps.py` | **Offline evidence map** — MBTiles tile server (handles TMS↔XYZ flip); extracts every event carrying lat/lon as a map marker; hand-built placeholder PNG tile when no MBTiles installed |
| `reference.py` | **Offline reference library** — serves ZIM archives (offline Wikipedia via optional libzim) plus local HTML/Markdown/PDF docs; tiny safe markdown renderer |
| `ai.py` | **Hive Mind local AI** — talks to a local Ollama/llama.cpp server for case summaries + evidence Q&A; deterministic rule-based fallback when no model is present; builds evidence context; never touches the internet |
| `api.py` | The Flask application: full `/api/v1` REST surface **and** all dashboard pages, sharing one token-based auth path |
| `cli.py` | `hexbee-hive` command: `init`, `engine`, `web`, `user add/disable`, `verify`, `correlate`, `report` |

**Hive front-end — `hive/hexbee_hive/templates/`** (server-rendered, honey-on-black theme, mobile-responsive):
`base.html` (nav, theme, PWA manifest links), `login.html`, `dashboard.html`
(auto-refresh, stats, event-type breakdown), `incidents.html`, `incident.html`
(timeline + triage controls), `cases.html`, `case.html`, `search.html`,
`devices.html` (online/offline inventory), `iocs.html`, `audit.html`,
`map.html` (zero-dependency slippy map), `reference.html`, `reference_doc.html`,
`assistant.html` (Hive Mind chat), `field.html` (iPhone companion),
`field_uploaded.html`, `label.html` (printable QR evidence label), `error.html`.

**Hive static — `hive/hexbee_hive/static/`:**
`logo.png` (the project logo) + generated `logo-512/256/180/64.png`, `logo.svg`
(vector navbar mark), `manifest.webmanifest` (PWA install metadata).

**Hive deployment — `hive/`:**
`install.sh` (Raspberry Pi installer: Mosquitto, dedicated `hexbee` user,
virtualenv, DB init, systemd enable), `systemd/hexbee-engine.service` and
`systemd/hexbee-web.service` (memory-capped, auto-start on boot, headless),
`pyproject.toml`, `requirements.txt`.

### 👑 Queen — `queen/hexbee_queen/` (analyst CLI)

| File | What it does |
|------|--------------|
| `client.py` | Stdlib-only (`urllib`) REST client for the Hive — auth, events, incidents, cases, reports, verify, IOCs, AI |
| `cli.py` | `hexbee-queen` command: `connect`, `status`, `incidents`, `incident`, `cases`, `case show/new/note/status`, `assign`, `search`, `tag`, `ioc list/add/del/hits`, `ai ask/summarize`, `report`, `verify`. Session persisted in `~/.hexbee-queen.json` |

`queen/setup-kali.sh` (Kali installer via pipx + Sleuth Kit), `pyproject.toml`.

### 🔬 Comb — `comb/hexbee_comb/` (forensic triage toolkit, Autopsy/AXIOM-class)

Runs on the Queen. Its unique twist: every finding can be pushed into the
Hive's hash-chained evidence log, so analysis artifacts get the same
chain-of-custody as live acquisitions.

| File | What it does |
|------|--------------|
| `magic.py` | File-type identification by magic bytes; **extension-mismatch detection** (an .exe renamed .jpg) |
| `inventory.py` | Recursive file walk hashing (SHA-256) and typing every file, with MAC timestamps and executable/mismatch flags |
| `carver.py` | **Signature-based file carving** from raw disk images (JPEG/PNG/GIF/PDF/ZIP/SQLite) using mmap so multi-GB images don't need RAM |
| `diskimage.py` | **MBR and GPT partition-table parsing**, pure Python (type codes + GPT type GUIDs) |
| `exif.py` | EXIF extraction — camera make/model, capture time, and **GPS coordinates** (feeds the Hive map) |
| `browser.py` | **Browser history** parsing (Chrome/Chromium/Edge + Firefox); works on a shredded temp copy so evidence is never opened read-write or left in /tmp |
| `tsk.py` | Optional **Sleuth Kit** integration (`mmls`/`fls`) for NTFS/ext4/HFS+ walks including deleted entries, when installed |
| `analysis.py` | The scan pipeline (inventory + EXIF + browser → findings); converts findings to Hive events; uploads via REST; branded HTML + JSON reports |
| `cli.py` | `hexbee-comb` command: `scan`, `carve`, `partitions`, `tsk-ls` |

`comb/pyproject.toml` (depends on Pillow for EXIF).

### 🐝 Scout — `scout/`

**Firmware — `scout/firmware/`** (C, ESP-IDF v5.x):

| File | What it does |
|------|--------------|
| `main/scout_main.c` | App entry: Wi-Fi station + auto-reconnect, SNTP time sync, MQTT publish (QoS 1) to `hexbee/events/<device>`, scout_online announcement, heartbeat task |
| `main/event_buffer.c/.h` | **Offline event buffering** — RAM ring buffer; events queue while the broker is unreachable and flush in order on reconnect |
| `main/usb_watch.c/.h` | USB acquisition interface (simulation mode until hardware validation — emits a simulated insertion so the pipeline can be exercised from real firmware) |
| `main/CMakeLists.txt`, `main/Kconfig.projbuild` | Build + configurable device name / Wi-Fi / broker / heartbeat |
| `CMakeLists.txt`, `sdkconfig.defaults` | Project build config (ESP32-S3 target, TinyUSB, NVS, mbedTLS bundle) |
| `README.md` | What works vs. what's hardware-gated |

**Simulator — `scout/simulator/scout_sim.py`:** emits the exact JSON a real
Scout sends (over REST or MQTT), with `quiet` / `usb` / `incident` scenarios,
so the entire platform can be developed and demonstrated with no hardware.

### ✅ Tests — `tests/` (48 passing)

| File | Covers |
|------|--------|
| `conftest.py` | Shared fixtures (temp DB, path setup) |
| `test_core.py` | Normalization, hash-chain verify + tamper/deletion detection, correlation grouping, cases, auth/RBAC, search, reports |
| `test_api.py` | Flask API: auth, RBAC enforcement, ingest validation, full investigation flow, dashboard pages |
| `test_ioc.py` | IOC validation, recursive payload matching, ingest escalation, hit cleanup, API RBAC |
| `test_comb.py` | Magic/mismatch, inventory, carving, MBR parsing, Chrome/Firefox history, EXIF GPS round-trip, scan pipeline |
| `test_field_features.py` | MBTiles serving + Y-flip, map points, reference catalog/docs, markdown escaping, AI (available + fallback), field photo upload into the chain, QR labels |

### 📚 Documentation — `docs/` and root

`README.md`, `docs/ARCHITECTURE.md`, `docs/DEPLOYMENT.md` (Pi + Kali workflow),
`docs/API.md`, `docs/COMB.md`, and this `JOURNAL.md`.

---

## Key design decisions & constraints honoured

- **One write path.** MQTT and REST ingest both funnel through
  `process_raw_event` → `store_event`; nothing else appends to the events
  table. This is what makes the hash chain trustworthy.
- **Hash chain, not per-event hashes.** A per-event hash proves a single event
  wasn't corrupted; chaining proves nothing was deleted or reordered either.
  Editing any past event breaks verification from that row forward.
- **SQLite on 1 GB RAM.** WAL mode, a single lock, event-driven correlation
  (no batch jobs). Backup is a file copy plus a `verify` run.
- **Stdlib-first.** Auth (PBKDF2, tokens), the Queen client, the map viewer,
  and the AI/reference fallbacks avoid heavy dependencies so the air-gapped Pi
  and a bare Kali install both "just work."
- **Fully offline.** Maps (MBTiles), reference (ZIM/Wikipedia), and AI (local
  Ollama) all run on the LAN with no internet; each degrades gracefully when
  its optional data/model isn't installed.
- **Graceful hardware gating.** The Scout's USB acquisition path and the
  offline-Wikipedia/AI extras are clearly marked as needing hardware or an
  optional dependency; the simulator + rule-based fallbacks keep everything
  demonstrable today.
- **Evidence hygiene.** Browser DBs are copied and the copy shredded; the
  target is never opened read-write; every analyst action is audit-logged.

---

## What HexBee does when done

A complete, field-deployable DFIR platform where:

1. A **Scout** plugged into a suspect machine detects USB activity, catalogues
   files, spots executables, and streams signed-ready JSON events over Wi-Fi —
   buffering offline and flushing when the link returns.
2. The **Hive** receives every event, normalises it, appends it to a
   **tamper-evident hash-chained evidence log**, and automatically
   **correlates** related events into **incidents** with reconstructed
   **timelines** — all headless on a Raspberry Pi that boots and runs itself.
3. **IOC** watchlists auto-escalate known-bad hashes/files/IPs/domains the
   moment they appear.
4. On the **Queen** (Kali), **Comb** performs full triage of seized disk
   images — inventory, carving, partition maps, EXIF/GPS, browser history,
   Sleuth Kit walks — and pushes findings straight into the same evidence
   chain.
5. Analysts work cases through a branded web dashboard **and** a CLI: manage
   cases, tag evidence, search, plot recovered **GPS coordinates on an offline
   map**, consult an **offline Wikipedia / reference library**, ask a **local
   AI** to summarise a case, and export court-ready **HTML/JSON/CSV reports** —
   with the evidence chain verifiable end-to-end at any moment.
6. In the field, an **iPhone XR** acts as a companion: an install-to-home-screen
   web app for viewing open incidents, photographing physical evidence directly
   into the hash chain, and scanning **QR labels** on evidence bags to jump to
   the right case.

Every layer separates one responsibility — collection (Scout), aggregation and
integrity (Hive), and investigation (Queen/Comb) — while keeping the entire
platform self-contained and offline, from acquisition to signed report.
