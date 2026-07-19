# Deploying the Hive (Raspberry Pi 3B+)

## Prerequisites

- Raspberry Pi OS Lite 64-bit, booted from USB SSD/flash
- Network reachable from Scouts (Wi-Fi or Ethernet)
- This repository copied to the Pi (e.g. `scp -r HEXBEE pi@hive.local:`)

## Install

```sh
cd HEXBEE/hive
sudo bash install.sh
```

The installer:

1. Installs Mosquitto + Python venv tooling via apt
2. Creates a no-login `hexbee` system user
3. Installs the Hive package into `/opt/hexbee/venv`
4. Writes `/etc/hexbee/hive.env` (data dir, ports, generated REST ingest key)
5. Configures a Mosquitto listener on 1883
6. Initializes the database at `/var/lib/hexbee/hive.db`
7. Enables `mosquitto`, `hexbee-engine`, and `hexbee-web` via systemd

Everything starts automatically after power-on; no monitor or keyboard
needed.

## First login

```sh
sudo -u hexbee HEXBEE_DATA_DIR=/var/lib/hexbee \
    /opt/hexbee/venv/bin/hexbee-hive user add admin administrator
```

Dashboard: `http://<pi-address>:8080` — sign in with that user. Add
investigator/viewer accounts the same way.

## Configuration reference (`/etc/hexbee/hive.env`)

| Variable | Default | Meaning |
|----------|---------|---------|
| `HEXBEE_DATA_DIR` | `~/hexbee-data` | database + exports location |
| `HEXBEE_MQTT_HOST` / `_PORT` | `127.0.0.1` / `1883` | broker the engine subscribes to |
| `HEXBEE_MQTT_TOPIC` | `hexbee/events/#` | subscription filter |
| `HEXBEE_MQTT_USERNAME` / `_PASSWORD` | empty | broker credentials |
| `HEXBEE_MQTT_TLS_CA` | empty | path to CA cert; set to enable MQTT TLS |
| `HEXBEE_WEB_HOST` / `_PORT` | `0.0.0.0` / `8080` | dashboard/API bind |
| `HEXBEE_INGEST_KEY` | empty (disabled) | shared key for REST ingest |
| `HEXBEE_CORRELATION_WINDOW` | `600` | correlation window, seconds |
| `HEXBEE_TOKEN_TTL_HOURS` | `12` | login token lifetime |

Restart after changes: `sudo systemctl restart hexbee-engine hexbee-web`

## Operations

```sh
systemctl status hexbee-engine hexbee-web     # health
journalctl -u hexbee-engine -f                # live ingest log
sudo -u hexbee /opt/hexbee/venv/bin/hexbee-hive verify      # chain check
sudo -u hexbee /opt/hexbee/venv/bin/hexbee-hive correlate   # backfill
```

**Backup:** stop the engine, copy `/var/lib/hexbee/hive.db*` (the WAL and
SHM files too), restart, and run `hexbee-hive verify` against the copy.

## Queen setup (Kali Linux — ThinkPad T470)

The Queen is a Kali Linux workstation. One script installs both the analyst
CLI and the Comb forensic toolkit and pulls in the system forensics tools:

```sh
bash queen/setup-kali.sh
hexbee-queen connect http://hive.local:8080 -u analyst
hexbee-queen status
```

This installs `hexbee-queen` and `hexbee-comb` via **pipx** (isolated venvs,
so they don't disturb Kali's system Python) and installs **Sleuth Kit**
(`mmls`/`fls`), which Comb auto-detects to enable `hexbee-comb tsk-ls`. Kali's
`forensics` metapackage usually already provides these.

### Analysing a disk image on Kali

Comb scans a directory tree, so mount the evidence read-only first — standard
Kali workflow:

```sh
# 1. See the layout, note the partition's start sector
hexbee-comb partitions evidence.dd

# 2. Read-only loop-mount that partition (start_LBA × 512 = offset bytes)
sudo mkdir -p /mnt/evi
sudo mount -o ro,loop,offset=$((2048*512)) evidence.dd /mnt/evi

# 3. Triage it and stream findings into the Hive's evidence chain
hexbee-comb scan /mnt/evi -o case-report.html \
    --hive http://hive.local:8080 --key "$INGEST_KEY" --device Comb01

# For raw carving of unallocated space, no mount needed:
hexbee-comb carve evidence.dd ./carved
```

E01 images: mount with `ewfmount evidence.E01 /mnt/ewf` first, then point the
above at `/mnt/ewf/ewf1`. GPS-tagged photos Comb finds appear on the Hive's
offline **Map**; ask **Hive Mind** to summarise the resulting case.

### Local AI (optional, stays on the laptop)

```sh
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2
# then point the Hive at this laptop:  HEXBEE_AI_URL=http://<t470-ip>:11434
```

Without Ollama, Hive Mind still works via its rule-based summariser.
