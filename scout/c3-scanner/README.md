# HexBee C3 Scanner

Passive wireless sighting sensor for the otherwise-idle ESP32-C3. MicroPython,
no extra hardware, no extra cost.

It listens. It does not probe, does not associate with anything it observes,
and transmits only its findings — over your own uplink network — to the Hive.

## What it sees

| Source | Detail captured |
|---|---|
| Wi-Fi beacons | SSID (or "hidden"), BSSID, channel, RSSI, security mode, open-network flag |
| BLE advertisements | address, address type, advertised name, 16-bit service UUIDs, RSSI |

Every sighting is flagged with `randomised_mac` when the address is
locally-administered or a BLE random address, because a randomised MAC cannot
be used to track a device across sessions and a report should not imply that
it can.

Sightings become `wireless_sighting` events in the Hive (ATT&CK T1040) and
plot on the offline evidence map when `lat`/`lon` are configured.

## Install

```bash
esptool.py --chip esp32c3 erase_flash
esptool.py --chip esp32c3 write_flash -z 0 ESP32_GENERIC_C3-*.bin

cp config.example.py config.py     # edit device name, Hive URL, ingest key, uplink Wi-Fi
mpremote connect /dev/ttyACM0 fs cp config.py :config.py
mpremote connect /dev/ttyACM0 fs cp main.py :main.py
mpremote connect /dev/ttyACM0 reset
```

## Memory

The C3 has 400 KB of SRAM and MicroPython leaves roughly 100 KB of usable
heap, so everything here is explicitly bounded:

* the dedup table caps at 400 devices and is cleared wholesale when full —
  cheap, and the worst case is one duplicated round of sightings;
* each device is reported once per 15-minute window, not once per beacon;
* uploads batch at 25 events, and the outbound queue is trimmed to 200 if the
  Hive stays unreachable;
* `gc.collect()` runs every cycle, because MicroPython does not compact
  aggressively on its own.

A busy street produces thousands of frames an hour. Without these bounds the
board runs out of heap in minutes; with them it runs indefinitely.

## Limitations

* **No monitor mode.** MicroPython's `WLAN.scan()` returns access-point
  beacons only. Client probe requests — the SSID-preference harvesting that
  makes passive Wi-Fi recon interesting — need raw 802.11 monitor mode, which
  the MicroPython port does not expose. For probe requests, use
  `hexbee-netmon run --monitor` with a monitor-capable USB adapter, or write
  the C3 firmware against ESP-IDF's `esp_wifi_set_promiscuous()`.
* **Scan is not continuous.** The radio scans, then sleeps until the next
  cycle. A device that appears and leaves between cycles is missed. Shorten
  `scan_interval` at the cost of power.
* **No BLE 5 extended advertising.** MicroPython's `bluetooth` module handles
  legacy advertisements. Devices using extended-advertising PDUs only will not
  appear.
* **No position.** There is no GNSS on the C3. `lat`/`lon` in the config are a
  static deployment position; sightings from a scanner carried around are not
  individually located.
