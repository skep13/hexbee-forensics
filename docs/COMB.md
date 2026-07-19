# HexBee Comb — forensic triage toolkit

Comb is the Queen-side analysis cell: an Autopsy/AXIOM-class triage tool that
runs on the analyst laptop and pushes its findings into the Hive's
hash-chained evidence log.

## Install

```sh
cd comb
pip install -e .        # pulls in Pillow for EXIF
```

Optional: install **The Sleuth Kit** for filesystem walks inside images
(`sudo apt install sleuthkit` on Kali). Comb detects it automatically.

## Point-and-click UI

Prefer not to type commands? Launch the browser UI:

```sh
hexbee-comb serve            # opens http://127.0.0.1:8091
```

Enter or paste the target path, click **Scan**, view the report in the browser,
and optionally tick "upload to the Hive". Stdlib-only, local-only, no extra
dependencies.

## Commands

### `scan` — inventory + artifacts from a directory or mount point

```sh
hexbee-comb scan TARGET [-o report.html] [--json out.json] [--max-files N]
                        [--hive URL --key INGEST_KEY --device Comb01]
```

Walks every file under `TARGET` (a mounted image, a data extraction, or a live
folder) and produces:

- **File inventory** — SHA-256, magic-byte type, MAC timestamps
- **Extension mismatches** — magic type disagrees with the extension (e.g. a
  PE executable named `holiday.jpg`)
- **Executables** — PE and ELF binaries
- **EXIF/GPS** — camera make/model, capture time, and coordinates from images
- **Browser history** — Chrome/Chromium/Edge and Firefox profiles found under
  the target

With `--hive`, the interesting findings are converted to events and uploaded to
the Hive's REST ingest endpoint, where they correlate into incidents and
GPS-tagged images appear on the offline evidence map. Databases are copied
before reading, and the target is only ever opened read-only.

### `carve` — recover files from a raw image

```sh
hexbee-comb carve disk.raw carved_out/
```

Signature-based carving (JPEG, PNG, GIF, PDF, ZIP, SQLite) using mmap, so
multi-GB images don't need to fit in RAM. Each recovered file is hashed.

### `partitions` — MBR/GPT partition table

```sh
hexbee-comb partitions disk.raw
```

Pure-Python parser; understands MBR, GPT (via the protective MBR), and common
partition type GUIDs. Use the reported start LBA as the `--offset` for `tsk-ls`.

### `tsk-ls` — filesystem listing via Sleuth Kit

```sh
hexbee-comb tsk-ls disk.raw --offset 2048
```

Recursive listing including deleted entries, when Sleuth Kit is installed.

## How it fits the platform

```
raw image / mount ──> hexbee-comb scan ──REST /ingest──> Hive evidence chain
                              │                                   │
                              ├─ HTML report (standalone)         ├─ correlation → incidents
                              └─ JSON (full inventory)            ├─ GPS images → offline map
                                                                  └─ chain-of-custody + audit
```

Because findings enter through the same ingest path as Scout acquisitions,
they are hashed into the same append-only log and covered by
`hexbee-hive verify`.
