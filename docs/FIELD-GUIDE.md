# HexBee Field Guide — using the full forensics kit

A start-to-finish runbook for deploying the kit and working a case. For what
each part is, see [OVERVIEW.md](OVERVIEW.md).

## The kit

| Device | Role | You bring |
|--------|------|-----------|
| 🏠 **Hive** | Raspberry Pi 3B+ evidence hub (server) | Pi + USB SSD + power |
| 👑 **Queen** | Kali ThinkPad T470 analyst laptop | the laptop |
| 🐝 **Forager USB** | run-from-stick live collector | a USB stick |
| 🔬 **Comb** | disk/media triage (on the Queen) | write-blocker + cables |
| 🐝 **Scout** | ESP32-S3 USB field agent (hardware bring-up in progress) | the board |
| 📱 **iPhone XR** | field companion / evidence photos | the phone |

---

## Part 1 — One-time setup (before deployment)

### Stand up the Hive
```sh
# On the Raspberry Pi (Raspberry Pi OS Lite 64-bit, booting from the USB SSD):
cd HEXBEE/hive
sudo bash install.sh
sudo -u hexbee HEXBEE_DATA_DIR=/var/lib/hexbee \
    /opt/hexbee/venv/bin/hexbee-hive user add admin administrator
hexbee-hive security-check          # review posture
```
Note the **ingest key** printed by the installer (in `/etc/hexbee/hive.env`) —
the Forager and Comb use it. Dashboard is at `http://<pi-ip>:8080`.

### Set up the Queen
```sh
cd HEXBEE && bash queen/setup-kali.sh          # installs hexbee-queen + hexbee-comb + Sleuth Kit
hexbee-queen connect http://<pi-ip>:8080 -u admin
```

### Build the Forager USB stick
```sh
# On any Windows machine with Python:
pip install pyinstaller psutil
powershell -ExecutionPolicy Bypass -File forager\usb\build_windows.ps1
```
Copy `forager/usb/dist/HexBee-Forager-USB/` onto the stick. To auto-ship to the
Hive, rename `forager.example.json` → `forager.json` and fill in your Hive URL +
ingest key. (Leave it out to capture offline onto the stick only.)

### Take a starting anchor
```sh
hexbee-queen anchor -o engagement-start.anchor.json
```
This signed receipt proves later that nothing in the log was rewound.

---

## Part 2 — At the scene

### A. Collect from a LIVE computer — the Forager USB (no install)
Plug the stick into the target and run the launcher — it shows a **menu**
(Collect / Monitor / Status), so no commands to type:

- **Windows:** right-click `RUN-WINDOWS.bat` → **Run as administrator**
- **Linux/macOS:** `sudo ./run-linux.sh`

It captures processes, network connections (with owning process), logons,
autoruns/persistence, USB history, and recent files to
`collections\<HOST>_<time>.json` **on the stick** — and, if a Hive is
configured and reachable, ships it straight into the evidence chain. It is
**read-only** and leaves nothing on the target's disk.

For ongoing monitoring instead of a one-shot snapshot:
```
forager.exe watch --interval 60      # emits *_new events as activity appears
```

### B. Photograph physical evidence — the iPhone
On the same network, open `http://<pi-ip>:8080/field` in Safari → **Add to Home
Screen**. Use it to photograph seized items (each photo is hashed into the
chain) and to scan case **QR labels**.

### C. The Scout (when hardware is validated)
Plug the ESP32-S3 Scout into a target's USB; it reports USB/host activity over
Wi-Fi to the Hive. Until bring-up, use the simulator to rehearse the pipeline.

---

## Part 3 — Back at base

### Import any offline USB captures
```sh
# From the Queen (or any networked machine), with the stick mounted:
forager.exe --hive http://<pi-ip>:8080 --key <KEY> submit "collections\*.json"
```

### Triage seized media with Comb
Image the drive **through a hardware write-blocker**, mount it read-only, then
either use the browser UI or the command line:
```sh
hexbee-comb serve                                 # point-and-click: paste path, click Scan
# or, from the command line:
hexbee-comb partitions evidence.dd
sudo mount -o ro,loop,offset=$((2048*512)) evidence.dd /mnt/evi
hexbee-comb scan /mnt/evi -o triage.html --hive http://<pi-ip>:8080 --key <KEY>
```
Executables, extension mismatches, GPS photos (→ the offline **map**), and
browser history flow in as correlated evidence.

---

## Part 4 — Investigate (on the Queen)

By now the Hive has auto-correlated related events into **incidents** with
**timelines**. Work the case:
```sh
hexbee-queen incidents
hexbee-queen case new "Front-desk USB malware" -d "walk-in report"
hexbee-queen assign 3 1                 # incident 3 -> case 1
hexbee-queen ioc add sha256 <hash> -n "known dropper"
hexbee-queen search --text invoice_viewer.exe
hexbee-queen ai summarize 1             # local AI case summary
```
Or use the dashboard (`/incidents`, `/cases`, `/map`, `/iocs`, `/assistant`).

---

## Part 5 — Preserve & hand off

```sh
hexbee-queen verify                                   # chain intact?
hexbee-queen anchor-verify engagement-start.anchor.json   # nothing rewound?
hexbee-queen export 1                                  # signed evidence bundle
# later, anywhere, offline:
hexbee-hive verify-bundle <bundle-dir>
```
The signed bundle contains the case, full timeline, chain verification, a chain
anchor, the **complete audit trail**, and every evidence file with its hash —
verifiable offline with only the signing key.

---

## Chain-of-custody checklist

- [ ] Anchor the log at the **start** of the engagement.
- [ ] Use a **hardware write-blocker** on any original media before imaging.
- [ ] Run the Forager as **admin/root** (full process/network visibility);
      it writes only to the USB, never the target's disk.
- [ ] Keep the kit **off the internet** (air-gapped LAN).
- [ ] `verify` the chain and `anchor-verify` before and after key steps.
- [ ] Export a **signed bundle** for hand-off; back up the signing key.
- [ ] Only collect from systems you are **authorized** to investigate.
