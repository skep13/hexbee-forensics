# Installing HexBee

HexBee is several components. You don't need all of them — install what each
device in your kit needs. Start with the **Quick local install** to try the
whole thing on one computer, then deploy the real kit.

- [Prerequisites](#prerequisites)
- [Get the code](#get-the-code)
- [Quick local install](#quick-local-install-one-machine-any-os) — try it in 2 minutes
- [Full kit](#full-kit-install)
  - [Hive](#hive--raspberry-pi-3b) · [Queen](#queen--kali-laptop) ·
    [Forager](#forager--collector-agent--usb-stick) · [Comb](#comb--disk-triage) ·
    [Scout](#scout--esp32-s3-firmware)
- [Optional offline data](#optional-offline-data)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

| For | You need |
|-----|----------|
| Any component (Python) | **Python 3.9+** (3.11+ recommended) and **git** |
| Hive server | Raspberry Pi OS Lite 64-bit (production) — or any OS for dev |
| Queen | Kali Linux (the analyst laptop) |
| Comb deep filesystem walks | The Sleuth Kit (`sleuthkit`) — optional |
| Scout firmware | ESP-IDF v5.x + an ESP32-S3 board — optional (hardware) |
| Building the Forager USB `.exe` | PyInstaller (on your build machine) |

Component dependencies (installed automatically by `pip`):
`hive` → Flask, paho-mqtt, segno · `comb` → Pillow · `queen` → none (stdlib) ·
`forager` → none (stdlib; `psutil` optional for richer data).

## Get the code

```sh
git clone https://github.com/skep13/hexbee-forensics.git
cd hexbee-forensics
```

---

## Quick local install (one machine, any OS)

Runs the whole Hive on your computer so you can log in and click around.

> **Windows one-command test:** from the repo folder just run
> `powershell -ExecutionPolicy Bypass -File try-hexbee.ps1`.
> It sets up a virtualenv, installs everything, starts the Hive, loads a demo
> incident, and opens the dashboard — log in with **admin / hexbee-demo-1**.
> (Then stop it with the `Stop-Process -Id …` line it prints.)

**Windows (PowerShell):**
```powershell
py -m venv .venv
.venv\Scripts\pip install -e hive
$env:HEXBEE_DATA_DIR = "$PWD\dev-data"
$env:HEXBEE_INGEST_KEY = "devkey"
.venv\Scripts\hexbee-hive init
.venv\Scripts\hexbee-hive user add admin administrator
.venv\Scripts\hexbee-hive web
```

**Linux / macOS:**
```sh
python3 -m venv .venv
.venv/bin/pip install -e hive
export HEXBEE_DATA_DIR=$PWD/dev-data HEXBEE_INGEST_KEY=devkey
.venv/bin/hexbee-hive init
.venv/bin/hexbee-hive user add admin administrator
.venv/bin/hexbee-hive web
```

Open **http://127.0.0.1:8080** and sign in with the user you just created.

Add the analyst + collection tools into the same virtualenv if you want them:
```sh
.venv/bin/pip install -e comb -e queen -e forager
```

Feed it some demo data (in a second terminal):
```sh
python scout/simulator/scout_sim.py --rest http://127.0.0.1:8080 --key devkey --scenario incident
```

---

## Full kit install

### Hive — Raspberry Pi 3B+

The always-on evidence hub. On the Pi (Raspberry Pi OS Lite 64-bit, ideally
booting from a USB SSD):

```sh
git clone https://github.com/skep13/hexbee-forensics.git
cd hexbee-forensics/hive
sudo bash install.sh
```

The installer does everything: installs the Mosquitto MQTT broker, creates a
locked-down `hexbee` system user, builds a virtualenv at `/opt/hexbee`, puts
data in `/var/lib/hexbee`, initialises the database, and enables **systemd
services** (`hexbee-engine`, `hexbee-web`) that start on boot — fully headless.

It prints a generated **ingest key** (also in `/etc/hexbee/hive.env`) — you'll
need it for the Forager, Comb and Scout. Then create your first login:

```sh
sudo -u hexbee HEXBEE_DATA_DIR=/var/lib/hexbee \
    /opt/hexbee/venv/bin/hexbee-hive user add admin administrator
```

Dashboard: **http://\<pi-ip\>:8080**. Full detail and hardening in
[DEPLOYMENT.md](DEPLOYMENT.md).

### Queen — Linux laptop (Kali, Fedora, Asahi, Arch)

Installs both the analyst CLI and the Comb triage toolkit in one step:

```sh
cd hexbee-forensics
bash queen/setup-linux.sh
hexbee-queen connect http://<pi-ip>:8080 -u admin
hexbee-queen status
```

`setup-linux.sh` uses **pipx** (isolated installs) for `hexbee-queen` and
`hexbee-comb`, and your distribution's package manager for **Sleuth Kit** —
apt, dnf, pacman or zypper, detected by which one is present rather than by
parsing `/etc/os-release`, so derivatives work with no special case. Most
investigation happens in the Hive dashboard; the CLI is for scripting and
quick queries.

`bash queen/setup-kali.sh` still works — it is a thin wrapper around the same
script.

Flags: `--minimal`, `--with-netmon`, `--with-ai`, `--no-yara`.

**On Asahi Linux (Apple Silicon)** the script detects the hardware and prints
what is specific to it. The short version:

- **Netmon works here**, unlike macOS — Linux gives you raw packet capture.
  Install it with `--with-netmon`, then grant the capability the README
  describes.
- **Memory acquisition** needs a LiME module built against the Asahi kernel
  (`sudo dnf install kernel-devel-$(uname -r) gcc make`), then point
  `HEXBEE_LIME_MODULE` at the resulting `.ko`.
- **Asahi kernels use 16K pages.** Python wheels are fine; check any prebuilt
  third-party binary you add is not 4K-page-only.
- **wkhtmltopdf is not packaged for Fedora**, so `--pdf` is unavailable. The
  HTML engagement report is the deliverable — print it to PDF from a browser.

#### Run it as a desktop app

```sh
bash scripts/make-linux-app.sh
```

Adds a **HexBee Forensics** launcher (and a **Stop HexBee** entry) to your
applications menu, backed by systemd **user** services — the Linux equivalent
of an app owning its own processes: tied to your login session, no root
involved. Also installs `hexbee-ctl {start|stop|restart|status|logs}`.

Evidence lives in `~/.local/share/hexbee`; logs go to the journal
(`journalctl --user -u hexbee-hive.service`). Remove it all with
`bash scripts/make-linux-app.sh --uninstall`.

### Queen — macOS laptop

The macOS counterpart, same two commands plus the system tooling, via
**Homebrew** and **pipx**:

```sh
cd hexbee-forensics
bash queen/setup-macos.sh
hexbee-queen connect http://<pi-ip>:8080 -u admin
hexbee-queen status
```

Flags: `--minimal` (HexBee commands only, no system tooling), `--with-ai`
(also install Ollama for Hive Mind), `--no-yara`.

Homebrew must already be installed — the script tells you how rather than
changing system directories on your behalf. If a command is not found
afterwards, open a new terminal; pipx puts its binaries in `~/.local/bin`.

Three things macOS cannot do, worth planning around rather than debugging:

| Not available | Why | What to do instead |
|---|---|---|
| Memory capture | Apple blocks the access it needs | Acquire from Windows/Linux targets |
| `hexbee-netmon` | Raw capture needs extra drivers | Run it on the Pi, where it belongs |
| `--pdf` report export | Homebrew no longer packages wkhtmltopdf | Open the HTML report, **Print → Save as PDF** |

`hexbee-queen responder` still works — it reads a Responder log directory, so
run Responder itself on the Pi or a Kali box and point the importer at its
`Logs/`.

#### Run it as a Mac app

To use HexBee without keeping a terminal open, build a double-clickable app:

```sh
pipx install ./hive && bash scripts/make-macos-app.sh
```

That produces `~/Applications/HexBee.app`. Opening it starts the Hive
dashboard and the Comb UI and opens your browser; **quitting it stops both**.
Drag it to the Dock and HexBee behaves like any other Mac app.

Two macOS specifics decide how this is built, and both are worth knowing:

- **Evidence lives in `~/Library/Application Support/HexBee`, not the repo.**
  macOS (TCC) denies a double-clicked app access to `~/Downloads`, `~/Desktop`
  and `~/Documents`, and denies it *silently* — the failure surfaces as
  `Operation not permitted` with no prompt. `pipx install ./hive` matters for
  the same reason: it puts the Hive's code somewhere the app can always read.
  If you keep the project in one of those folders, install via pipx or move
  the project out.
- **It is an AppleScript applet, not a shell script in a bundle.** Only a real
  applet receives the Dock's Quit event. A bundled shell script cannot be
  quit — macOS falls back to Force Quit, which kills the launcher and leaves
  the servers running.

Useful paths:

```sh
~/Applications/HexBee.app/Contents/Resources/hexbee-ctl.sh status   # start|stop|status
```

Logs are in `~/Library/Logs/HexBee/`. To use a real ingest key instead of the
demo one, put `HEXBEE_INGEST_KEY=...` in `~/.hexbee-app.env`.

### Forager — collector agent / USB stick

**Install as a tool** (on a machine you'll collect from, or the Queen):
```sh
pip install ./forager               # or: pipx install ./forager
# richer process/network data:  pip install "./forager[rich]"
hexbee-forager config --hive http://<pi-ip>:8080 --key <INGEST_KEY>
hexbee-forager collect              # one-shot   (or: watch)
```

**Build a run-from-USB stick** (no Python needed on the target) — on any
Windows machine with Python:
```powershell
pip install pyinstaller psutil
powershell -ExecutionPolicy Bypass -File forager\usb\build_windows.ps1
```
Copy `forager/usb/dist/HexBee-Forager-USB/` onto a stick. At the scene, run
`RUN-WINDOWS.bat` and pick **Collect**. See
[../forager/README.md](../forager/README.md).

### Comb — disk triage

Installed by `setup-kali.sh`. To install it standalone:
```sh
pip install ./comb                  # pulls in Pillow
sudo apt install sleuthkit          # optional: deep filesystem walks
hexbee-comb serve                   # point-and-click UI at http://127.0.0.1:8091
```

### Scout — ESP32-S3 firmware

Hardware-optional. Without a board, use the simulator (Quick-local section
above). With ESP-IDF v5.x installed and a board attached:
```sh
cd scout/firmware
idf.py set-target esp32s3
idf.py menuconfig        # HexBee Scout: device name, Wi-Fi, MQTT broker
idf.py build flash monitor
```

---

## Optional offline data

All fully offline; each degrades gracefully if absent. Drop files into the
Hive's data directory (`/var/lib/hexbee` on the Pi):

| Feature | Put files in | Get them from |
|---------|--------------|---------------|
| Offline maps | `maps/*.mbtiles` | OpenMapTiles, Mobile Atlas Creator, QGIS |
| Offline Wikipedia | `reference/*.zim` + `pip install libzim` | download.kiwix.org/zim/ |
| Field docs | `reference/*.{html,md,pdf}` | your own SOPs/manuals |
| Local AI (Hive Mind) | — | `ollama pull llama3.2` on the Queen; set `HEXBEE_AI_URL` |

---

## Troubleshooting

- **`hexbee-hive: command not found`** — activate the venv, or call it by path
  (`.venv/bin/hexbee-hive` / `.venv\Scripts\hexbee-hive`).
- **Dashboard won't load** — check the service: `systemctl status hexbee-web`
  (Pi) or that `hexbee-hive web` is still running (dev).
- **Collectors can't submit** — confirm the ingest key matches the Hive's
  (`/etc/hexbee/hive.env`) and the Hive URL is reachable on port 8080.
- **Password rejected creating a user** — minimum 12 characters, not a common
  password (policy is intentional).
- **Check overall health** — `hexbee-hive security-check`.
- **Run the tests** — from the repo root: `pip install pytest && pytest`.
