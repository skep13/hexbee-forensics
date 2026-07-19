# HexBee Scout firmware (ESP32-S3)

ESP-IDF (v5.x) project for the Scout field agent.

## What works in this skeleton

- Wi-Fi station with auto-reconnect
- SNTP time sync (events carry epoch timestamps the Hive accepts)
- MQTT publish to `hexbee/events/<device>` at QoS 1
- `scout_online` announcement + periodic heartbeat
- Offline buffering: events queue in a RAM ring buffer while the broker is
  unreachable and flush in order on reconnect
- `usb_watch` module in **simulation mode** — emits one fake `usb_inserted`
  10 s after boot so the full pipeline can be demoed from real firmware

## Not yet implemented (hardware-validation gated)

- TinyUSB device-mode enumeration on the target computer
- MSC-host triage of attached USB storage (file metadata, executable
  detection) — these events currently come from the Python simulator
- Cryptographic device identity / event signing
- NVS-persisted offline buffer (survives reboot)

## Build & flash

```sh
idf.py set-target esp32s3
idf.py menuconfig        # HexBee Scout Configuration: device name, Wi-Fi, broker
idf.py build flash monitor
```

Until hardware is on the bench, use `scout/simulator/scout_sim.py` to
exercise the Hive with the exact same event shapes.
