# HexBee Hardware

HexBee is a *distributed* hardware project: four devices, each with one job.
This document is the bill of materials, wiring, and assembly reference for
building the physical kit.

> Status note: the Scout firmware currently runs its USB-acquisition path in
> **simulation mode** (it emits events on a timer so the whole pipeline can be
> demonstrated). Bringing up the real TinyUSB acquisition on the ESP32-S3 is
> the active hardware task — see [JOURNAL.md](../JOURNAL.md).

---

## System diagram

```
   Target PC                  Field Wi-Fi
   ┌────────┐   USB-C    ┌──────────────────┐   Wi-Fi   ┌───────────────┐
   │ suspect│──────────▶│ 🐝 Scout          │──────────▶│ 🏠 Hive        │
   │ machine│   (OTG)   │ ESP32-S3          │   MQTT    │ Raspberry Pi   │
   └────────┘           │ + LiPo (optional) │           │ 3B+ + USB SSD  │
                        └──────────────────┘           └───────┬───────┘
                                                                │ Wi-Fi / REST
                                                    ┌───────────┴───────────┐
                                                    ▼                       ▼
                                            👑 Queen (Kali T470)      📱 iPhone XR
                                            analyst laptop            field companion
```

---

## 🐝 Scout — Bill of Materials

| # | Component | Qty | Notes |
|---|-----------|-----|-------|
| 1 | ESP32-S3 dev board with **native USB** (e.g. ESP32-S3-DevKitC-1, or a board exposing the USB-OTG port such as the S3 "SuperMini") | 1 | Must be **S3** — native USB-OTG is required for the acquisition interface. Classic ESP32/ESP8266 will not work. |
| 2 | USB-C data cable | 1 | Data-capable, not charge-only |
| 3 | 3.7 V LiPo cell, 500–1200 mAh + JST-PH | 1 | *Optional* — untethered field use. Many S3 boards have an onboard charger/JST. |
| 4 | Slide switch | 1 | *Optional* — battery cutoff |
| 5 | Status LED (if board lacks an addressable one) | 1 | *Optional* — most S3 boards include a WS2812 |
| 6 | 3D-printed / project-box enclosure | 1 | *Optional* — tamper-evident field housing |

Approximate cost: **≈ $8–15** for the board + cable; **≈ $20–25** with
battery and enclosure.

### Scout pinout / wiring

The ESP32-S3 does the USB work over its **native USB peripheral** — no extra
transceiver needed. On the S3, the native USB D-/D+ lines are fixed:

| Signal | ESP32-S3 GPIO | Goes to |
|--------|---------------|---------|
| USB D− | GPIO 19 | USB-C D− (to target PC) |
| USB D+ | GPIO 20 | USB-C D+ (to target PC) |
| 5 V / VBUS | 5V pin | USB-C VBUS (bus-powered mode) |
| GND | GND | USB-C GND |
| Battery + | BAT / VBAT (JST) | LiPo + *(optional)* |

If your dev board already terminates its USB-OTG port in a connector, no
hand-wiring is required — the pins above are what the silicon uses internally.
Wi-Fi is on-chip (PCB antenna), so there is nothing to wire for networking.

### Scout firmware flashing

```sh
cd scout/firmware
idf.py set-target esp32s3
idf.py menuconfig      # HexBee Scout Configuration: device name, Wi-Fi SSID/pass, MQTT broker
idf.py build flash monitor
```

See [scout/firmware/README.md](../scout/firmware/README.md) for what is
implemented vs. hardware-gated.

---

## 🏠 Hive — Bill of Materials

| # | Component | Qty | Notes |
|---|-----------|-----|-------|
| 1 | Raspberry Pi 3B+ | 1 | 1 GB RAM; the whole platform is tuned for it |
| 2 | USB SSD or high-endurance USB flash drive (≥ 32 GB) | 1 | Boots from USB; SSD preferred for the evidence DB |
| 3 | USB-A ↔ SATA adapter (if using a bare 2.5" SSD) | 1 | — |
| 4 | 5 V / 2.5 A micro-USB power supply | 1 | Official supply avoids brownouts |
| 5 | Case with passive/active cooling | 1 | Headless, always-on |
| 6 | (Optional) Ethernet cable | 1 | If not using Wi-Fi |

Approximate cost: **≈ $35–60** depending on SSD.

### Hive setup

```sh
# Flash Raspberry Pi OS Lite 64-bit to the USB SSD, boot headless, then:
cd HEXBEE/hive
sudo bash install.sh
```

The installer sets up Mosquitto (MQTT broker), a dedicated `hexbee` user, a
virtualenv, the SQLite evidence database, and systemd services that start on
boot. See [docs/DEPLOYMENT.md](DEPLOYMENT.md).

---

## 👑 Queen — analyst workstation

| Component | Notes |
|-----------|-------|
| Lenovo ThinkPad T470 running **Kali Linux** | Existing laptop; no build required |

Setup: `bash queen/setup-kali.sh` (installs `hexbee-queen` + `hexbee-comb` +
Sleuth Kit). Optional local AI via Ollama on the same laptop.

---

## 📱 iPhone XR — field companion

| Component | Notes |
|-----------|-------|
| iPhone XR (or any iOS device on the same LAN) | Existing phone; no build required |

Setup: on the same network as the Hive, open `http://<hive>:8080/field` in
Safari → **Share → Add to Home Screen**. Installs as a standalone PWA for
viewing incidents, photographing evidence into the hash chain, and scanning
case QR labels.

---

## Full-kit cost estimate

| Device | Build cost | Notes |
|--------|-----------|-------|
| Scout (ESP32-S3) | ~$15–25 | The only part that is *built* from components |
| Hive (Pi 3B+ + SSD) | ~$35–60 | Assembly/flash, no soldering |
| Queen (T470) | — | Existing hardware |
| iPhone XR | — | Existing hardware |
| **Total new outlay** | **≈ $50–85** | |

The Scout is the core custom-hardware element; the Hive is an
assemble-and-flatpack node; Queen and iPhone are existing devices repurposed
by software.
