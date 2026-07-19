# HexBee Forensics — System Overview

How the whole platform works, how to use each part, and exactly what it can
acquire evidence from.

## The big picture

HexBee is a **distributed** forensics platform: instead of one workstation
doing everything, the work is split across devices, each with one job, and
everything runs **offline** with tamper-evident integrity.

```
  EVIDENCE SOURCES              COLLECTION                AGGREGATION              INVESTIGATION
  ────────────────             ──────────                ───────────              ─────────────
  live computer  ───────────▶  🐝 Forager ─┐
  (Win/Lin/mac)                            │
                                           ├── REST ──▶  🏠 HIVE ──── Wi-Fi ──▶  👑 QUEEN
  disk image / ─────────────▶  🔬 Comb ────┤            (Raspberry Pi 3B+)       (Kali T470)
  USB / drive                              │            hash-chained            dashboard + CLI
                                           │            evidence log            Comb + Hive Mind
  target PC (USB) ──────────▶  🐝 Scout ───┘            correlation, IOC,
  (ESP32-S3 hardware)                                   timeline, cases          📱 iPhone XR
                                                        maps, reference, AI      field companion
```

Everything a collector finds flows through **one ingest path** into the Hive,
where it is normalized, checked against IOC watchlists, appended to a
**SHA-256 hash chain**, and auto-correlated into incidents.

## Components — what each is and how to use it

### 🏠 Hive — evidence hub (Raspberry Pi 3B+)

The always-on server. Receives events, preserves them tamper-evidently,
correlates them into incidents, and serves the dashboard + REST API on
port **8080**.

```sh
sudo bash hive/install.sh          # one-shot Pi install (Mosquitto, DB, systemd)
hexbee-hive user add admin administrator
hexbee-hive verify                 # verify the whole evidence chain
hexbee-hive anchor > start.json    # signed tamper-evidence receipt
hexbee-hive export 42              # signed, court-ready evidence bundle for case 42
hexbee-hive verify-bundle <dir>    # re-verify a bundle offline
hexbee-hive security-check         # security posture report
```

Open `http://<hive>:8080` for the dashboard: incidents, cases, search, devices,
IOCs, map, reference, Hive Mind, field, audit.

### 👑 Queen — analyst workstation (Kali ThinkPad T470)

Where you investigate. Two tools, installed with `bash queen/setup-kali.sh`.

**`hexbee-queen`** — REST client for the Hive:

```sh
hexbee-queen connect http://hive.local:8080 -u analyst
hexbee-queen status | incidents | cases | search --text evil.exe
hexbee-queen case new "USB malware" -d "front desk"
hexbee-queen ioc add sha256 <hash> -n "known dropper"
hexbee-queen ai ask "what happened on Scout01?"     # local AI
hexbee-queen export 42                               # signed bundle
```

**`hexbee-comb`** — the disk/media triage engine (see below).

### 🐝 Forager — autonomous live collector (software agent)

Runs on a live host and gathers evidence **on its own**:

```sh
hexbee-forager config --hive http://hive.local:8080 --key <KEY>   # once
hexbee-forager collect              # one-shot triage snapshot
hexbee-forager watch --interval 60  # continuous; emits *_new events on change
```

Auto-discovers the Hive, spools offline if unreachable, runs unattended as a
systemd service. Read-only: it inspects the host, never modifies it.

### 🔬 Comb — disk/media triage (Queen-side)

The Autopsy/Magnet-AXIOM-class analysis engine. Analyzes storage and pushes
findings into the evidence chain:

```sh
hexbee-comb partitions evidence.dd                    # MBR/GPT map
hexbee-comb carve evidence.dd ./carved                # recover deleted files
hexbee-comb tsk-ls evidence.dd --offset 2048          # Sleuth Kit file listing
hexbee-comb scan /mnt/evidence -o report.html \
    --hive http://hive.local:8080 --key <KEY>         # full triage + upload
```

What Comb does:

- **File inventory** — every file hashed (MD5 + SHA-1 + SHA-256) and typed by
  magic bytes, with MAC timestamps.
- **Extension-mismatch detection** — catches an executable renamed `holiday.jpg`.
- **File carving** — recovers deleted/unallocated files (JPEG, PNG, PDF, ZIP,
  SQLite…) from raw images.
- **Partition parsing** — MBR and GPT, pure Python.
- **Filesystem walk** — via The Sleuth Kit when installed, including deleted
  entries (NTFS/ext/HFS+/APFS…).
- **EXIF/GPS** — camera and coordinates from images (plotted on the Hive map).
- **Browser history** — Chrome/Chromium/Edge and Firefox.

Its unique twist: findings upload through the same `/ingest` path as live
acquisitions, so analysis artifacts get the **same hash-chained
chain-of-custody** as everything else. See [COMB.md](COMB.md) for detail.

### 🐝 Scout — hardware USB agent (ESP32-S3)

The physical field device. Firmware (Wi-Fi + MQTT + offline buffering) is
built; the USB acquisition path is **simulation-mode until hardware bring-up**.
Exercise the full pipeline without hardware:

```sh
python scout/simulator/scout_sim.py --rest http://127.0.0.1:8080 --key <KEY> --scenario incident
```

### 📱 iPhone XR — field companion (PWA)

Add `http://<hive>:8080/field` to the home screen. Photograph physical evidence
(hashed into the chain), view incidents, scan case QR labels. Not a
device-extraction tool.

## What it can perform forensic acquisition on

| Source | Via | What's acquired | Status |
|--------|-----|-----------------|--------|
| **Live computers** (Windows, Linux, macOS) | Forager | Volatile: processes, network connections (with owning process), logons. Persistent: autoruns/persistence, USB history, recent files | ✅ Working |
| **Disk images** (raw/dd, E01 via ewfmount) | Comb | Partition maps, carved files, full filesystem listing (incl. deleted), hashes, EXIF/GPS, browser history | ✅ Working |
| **Mounted storage** — internal HDD/SSD, external USB drives, SD/memory cards, network shares | Comb | Same as above (anything you can mount read-only on Kali; NTFS/FAT/exFAT/ext/HFS+/APFS) | ✅ Working |
| **Target PC via USB** | Scout (ESP32-S3) | USB insertion detection, host triage, file metadata from attached storage | 🔧 Hardware-gated (firmware skeleton; simulation works) |
| **Physical scene/evidence** | iPhone | Photographs hashed into the evidence chain | ✅ Working |

**Out of scope** (important for real casework):

- **Mobile phone extraction** (iOS/Android logical or chip-off) — the iPhone is
  a companion, not a target we extract from.
- **Full RAM/memory imaging** — Forager reads live process/network *metadata*,
  not a memory dump.
- **Network packet capture**, cloud acquisition, or defeating
  encryption/locks without credentials.
- Acquisition still requires a **hardware write-blocker** when imaging original
  media — Comb protects working copies, not the original device.

## End-to-end, in practice

**Incident triage.** Forager on a suspect machine (or a Scout) streams events →
the Hive hash-chains them → severity-2+ events or IOC hits auto-open an
**incident** with a reconstructed **timeline** → you open a **case** on the
Queen, add notes, tag evidence → `verify` the chain → `export` a **signed
bundle** for hand-off.

**Disk investigation.** Image the drive through a write-blocker →
`hexbee-comb scan` the mount → executables, extension mismatches, GPS photos
(onto the offline **map**), and browser history flow in as correlated evidence
→ ask **Hive Mind** to summarize → export.

## Integrity & security

Every event joins a **SHA-256 hash chain** — any edit/deletion breaks
verification. **Signed anchors** prove the log wasn't rewound; **signed
bundles** are verifiable offline. The dashboard is hardened against the
**OWASP Top 10** (RBAC, CSRF, strict CSP, brute-force lockout, audit logging).
Full detail in [../SECURITY.md](../SECURITY.md) and [FORENSICS.md](FORENSICS.md).
