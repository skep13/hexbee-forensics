# HexBee Scout firmware (ESP32-S3)

ESP-IDF (v5.x) project for the Scout field agent.

## What works in this skeleton

- Wi-Fi station with auto-reconnect
- SNTP time sync (events carry epoch timestamps the Hive accepts)
- MQTT publish to `hexbee/events/<device>` at QoS 1
- `scout_online` announcement + periodic heartbeat
- Offline buffering: events queue in a RAM ring buffer while the broker is
  unreachable and flush in order on reconnect
- **USB MSC host acquisition** (`CONFIG_HEXBEE_USB_HOST`): a stick plugged
  into the Scout is enumerated, mounted, and walked — per-file size,
  mtime, prefix hash, and executable-extension flagging, streamed out as
  `file_metadata` events
- `usb_watch` falls back to **simulation mode** when that option is off, so
  the pipeline can still be demoed without hardware

## USB acquisition

The S3 acts as USB **host**, not device: the stick goes into the Scout. That
is the forensically useful direction — the Scout is the collector.

```sh
idf.py menuconfig    # HexBee Scout Configuration -> Enable USB MSC host acquisition
```

Design constraints, all forced by 520 KB of SRAM:

| Constraint | Why |
|---|---|
| SHA-256 covers the first 4 KB of each file (`CONFIG_HEXBEE_USB_HASH_BYTES`) | Full-file hashing on the S3 against a 64 GB stick would take hours and gains nothing the Queen cannot do later. 4 KB fingerprints a file and catches header/extension mismatches. Comb computes full hashes on the Queen. |
| One event per file, streamed | No directory listing is ever assembled in RAM. |
| 512-file cap (`CONFIG_HEXBEE_USB_MAX_FILES`), depth 6 | Bounds both the walk and how much one stick can flood the Hive. |
| Yield every 8 files | Otherwise the walk starves the Wi-Fi and MQTT tasks and the event buffer overflows. |
| `format_if_mount_failed = false` | An unrecognised filesystem is evidence. Formatting it destroys what you came for. |

Events carry `"partial_hash": true` so nothing downstream mistakes a prefix
hash for a full-file hash.

### Hardware wiring

Host mode needs the S3's USB OTG pins wired for it: a 5 V supply switched
onto VBUS, and D+/D- on GPIO19/GPIO20. Most dev boards ship device-only and
cannot power a stick without that supply added.

## Not yet implemented (hardware-validation gated)

- TinyUSB **device**-mode enumeration (Scout appearing as a peripheral on a
  target computer) — the host path above is the implemented direction
- Cryptographic device identity / event signing
- NVS-persisted offline buffer (survives reboot)

## Forensic caveat

FATFS is mounted read-write by the MSC driver. HexBee never writes to the
evidence volume, but "the software promises not to" is not a write blocker.
For acquisition intended to stand up in court, use a hardware write blocker
and image the device — the Scout's role is field triage, not seizure.

## Build & flash

```sh
idf.py set-target esp32s3
idf.py menuconfig        # HexBee Scout Configuration: device name, Wi-Fi, broker, USB
idf.py build flash monitor
```

Without hardware on the bench, `scout/simulator/scout_sim.py` exercises the
Hive with the exact same event shapes.
