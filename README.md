# HexBee Forensics

**Distributed digital forensics & incident response (DFIR) platform.**
*Detect · Isolate · Analyse.*

A field-deployable alternative to bench tools like Autopsy and Magnet AXIOM,
built around a distributed hive of purpose-built devices instead of a single
workstation — with everything (analysis, maps, reference, AI) running fully
**offline** and every artifact preserved in a tamper-evident hash chain.

> **New here?** Start with **[docs/INSTALL.md](docs/INSTALL.md)** to install it,
> then [docs/OVERVIEW.md](docs/OVERVIEW.md) for how it all works and what it can
> acquire evidence from. Deploying in the field? See the
> **[Field Guide](docs/FIELD-GUIDE.md)**.

```
Target Computer ──USB──> Scout (ESP32-S3 agent)
                              │ Wi-Fi / MQTT
                              ▼
                         Hive (Raspberry Pi 3B+ evidence hub)
                              │ Wi-Fi / REST
             ┌────────────────┼────────────────┐
             ▼                ▼                 ▼
     Queen (Kali/T470)     iPhone XR         Hive Mind
     analysis + Comb       field companion   local AI (offline)
```

## What it does (vs. Autopsy / AXIOM)

- **Comb triage toolkit** (Queen-side): file inventory with SHA-256 + magic-byte
  typing, **extension-mismatch detection** (an .exe hiding as .jpg), signature
  **file carving** from raw images, **MBR/GPT** partition parsing, **EXIF/GPS**
  extraction, **browser history** (Chrome/Firefox), and Sleuth Kit integration
  when present. Its unique twist: findings upload straight into the Hive's
  **hash-chained evidence log**, so analysis artifacts get the same
  chain-of-custody as live acquisitions.
- **Offline evidence map**: a self-hosted slippy map (zero external JS) serving
  standard **MBTiles**, plotting GPS coordinates recovered from evidence.
- **Offline reference library**: serves **ZIM archives** (offline Wikipedia via
  Kiwix) plus local HTML/Markdown/PDF field docs.
- **Hive Mind local AI**: case summaries and evidence Q&A via a local Ollama
  model — never touches the internet — with a deterministic rule-based fallback
  when no model is installed.
- **iPhone XR field companion**: an install-to-home-screen PWA (no App Store),
  camera evidence photos hashed into the chain, and per-case **QR labels** the
  iPhone camera scans to open a case.
- **Forager autonomous collector**: a read-only live-response agent that
  forages forensic artifacts from a host (processes, network connections with
  process attribution, logons, persistence/autoruns, USB history, recent files)
  and streams them into the evidence chain **with no interactive input** —
  one-shot triage or a continuous `watch` mode that emits `*_new` events when
  something appears. Auto-discovers the Hive; spools offline and retries.
- Plus the platform core: incident **correlation**, **timeline** reconstruction,
  **case management**, **IOC** matching, RBAC, search, and branded reports.

## Repository layout

| Path | What it is |
|------|------------|
| [hive/](hive/) | Hive server: MQTT+REST ingest, hash-chained SQLite evidence log, correlation, timeline, cases, IOC engine, offline map, reference library, Hive Mind AI, iPhone field PWA, QR labels, Flask dashboard + REST API |
| [comb/](comb/) | **Comb** forensic triage toolkit (`hexbee-comb`) — inventory, carving, partitions, EXIF/GPS, browser history, Sleuth Kit, uploads findings to the Hive |
| [forager/](forager/) | **Forager** autonomous live-response collector (`hexbee-forager`) — read-only agent that gathers processes, network, logons, autoruns, USB & recent files from a live host and streams them into the evidence chain; runs unattended with a continuous `watch` mode |
| [queen/](queen/) | Queen analyst CLI (`hexbee-queen`) — cases, incidents, search, IOCs, AI, reports over the Hive REST API, stdlib-only |
| [scout/firmware/](scout/firmware/) | ESP32-S3 ESP-IDF firmware: Wi-Fi, MQTT QoS 1, offline event buffering, heartbeat, USB watch (simulation mode until hardware validation) |
| [scout/simulator/](scout/simulator/) | Python Scout simulator — drives the whole platform with realistic scenarios, no hardware needed |
| [docs/](docs/) | [Overview](docs/OVERVIEW.md), architecture, deployment, Comb, forensics, and API reference |
| [tests/](tests/) | pytest suite (48 tests) across Hive core, IOC, Comb, and field features |

## Quick start (development, any OS)

```sh
cd hive
py -m venv .venv && .venv\Scripts\pip install -e .        # Windows
# python3 -m venv .venv && .venv/bin/pip install -e .     # Linux/macOS

# Configure a data dir + REST ingest key, create a user, start the web app
set HEXBEE_DATA_DIR=%CD%\..\dev-data
set HEXBEE_INGEST_KEY=devkey
.venv\Scripts\hexbee-hive init
.venv\Scripts\hexbee-hive user add admin administrator
.venv\Scripts\hexbee-hive web
```

Then in another terminal, fire a simulated incident at it:

```sh
py scout\simulator\scout_sim.py --rest http://127.0.0.1:8080 --key devkey --scenario incident
```

Open http://127.0.0.1:8080 — the dashboard shows the events, an
auto-correlated incident, and a verified evidence hash chain. Create a case,
assign the incident to it, and export an HTML/CSV/JSON report.

### Run a Comb analysis and see it flow in

```sh
cd comb
py -m pip install -e .
# Point it at a mounted image or extracted folder; upload findings to the Hive
hexbee-comb scan /path/to/mounted_evidence \
    -o report.html --hive http://127.0.0.1:8080 --key devkey
```

Executables, extension mismatches, GPS-tagged photos, and browser history now
appear as correlated evidence in the Hive — GPS images land on the **Map**
page. Ask **Hive Mind** to summarise the case, and print a **QR label** for the
physical evidence bag.

### Offline data (all optional, all local)

| Feature | Drop files into | Get from (on any online machine) |
|---------|-----------------|----------------------------------|
| Maps | `<data>/maps/*.mbtiles` | OpenMapTiles, Mobile Atlas Creator, QGIS |
| Wikipedia | `<data>/reference/*.zim` | `download.kiwix.org/zim/` (needs `pip install libzim`) |
| Field docs | `<data>/reference/*.{html,md,pdf}` | your own SOPs / statutes / manuals |
| Local AI | — | `ollama pull llama3.2` on the Queen, set `HEXBEE_AI_URL` |

### iPhone XR field companion

On the iPhone (same network as the Hive), open `http://<hive>:8080/field` in
Safari → Share → **Add to Home Screen**. You get a standalone app for viewing
open incidents, photographing evidence straight into the hash chain, and
scanning case QR labels.

## Production (Raspberry Pi 3B+)

```sh
cd hive
sudo bash install.sh
```

Installs Mosquitto, a dedicated `hexbee` user, a virtualenv under
`/opt/hexbee`, data under `/var/lib/hexbee`, and systemd units
(`hexbee-engine`, `hexbee-web`) that start on boot — fully headless. See
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Evidence integrity & security

Every event is appended to a SHA-256 **hash chain**
(`event_hash = sha256(prev_hash ‖ canonical_event)`). Any retroactive edit
or deletion breaks verification from that point forward.

```sh
hexbee-hive verify                    # verify the whole chain
hexbee-hive anchor > start.json       # signed point-in-time tamper receipt
hexbee-queen export 1                 # signed, court-ready evidence bundle
hexbee-hive verify-bundle <dir>       # re-verify a bundle offline
hexbee-hive security-check            # report security posture
```

- **Signed chain anchors** pin a point-in-time head so history can't be
  silently rewound; **signed evidence bundles** (HMAC-SHA256 + per-file hashes
  + audit trail) are verifiable offline with only the signing key.
- **OWASP Top 10 hardening**: RBAC, HMAC CSRF tokens, strict Content-Security-
  Policy with per-response script nonces, security headers, brute-force
  lockout, constant-time secret comparison, PBKDF2 passwords with a strong
  policy, and IP-stamped append-only audit logging.

See **[SECURITY.md](SECURITY.md)** for the full OWASP mapping and
**[docs/FORENSICS.md](docs/FORENSICS.md)** for the chain-of-custody model.

## Roles

| Role | Can |
|------|-----|
| viewer | read everything: dashboard, search, timelines, reports |
| investigator | + create/close cases, notes, tag evidence, triage incidents |
| administrator | + user management, audit log |

## Status

Working today: full Hive platform (ingest → normalize → chain → correlate →
timeline → case → report), IOC engine, Comb forensic toolkit with Hive upload,
offline evidence map, offline reference/Wikipedia library, Hive Mind local AI
(with rule-based fallback), iPhone field PWA with camera-to-chain uploads and
QR labels, Queen CLI, and the Scout simulator. **48 passing tests.**

Hardware/optional-dependency gated: the Scout's TinyUSB acquisition path, MSC
triage, device identity/event signing, and MQTT TLS (firmware skeleton runs in
simulation mode); offline Wikipedia needs `libzim`; conversational AI needs a
local Ollama model (the rule-based summariser works without one); MBTiles/ZIM
content is user-supplied.
