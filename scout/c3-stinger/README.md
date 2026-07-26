# HexBee Stinger — ESP32-C3 wireless implant

One £4 board, three jobs. MicroPython, no extra hardware.

| Mode | Transmits? | What it does |
|---|---|---|
| `scan` | **no** | Passive recon — Wi-Fi beacons and BLE advertisements into the evidence chain |
| `portal` | yes | Rogue access point with a captive portal, harvesting typed credentials |
| `hid` | yes | Bluetooth keyboard, injecting DuckyScript into a paired host |

Set `mode` in `config.py`. Only the module for the active mode is imported,
which matters on a board with roughly 100 KB of usable heap.

## Why BLE and not USB

The C3 cannot be a USB BadUSB. Its USB peripheral is a fixed-function
Serial/JTAG controller — CDC-ACM and JTAG only — so it physically cannot
enumerate as a USB HID keyboard. No firmware fixes that; it is silicon.

What it does have is BLE 5.0, and HID-over-GATT gives the same capability
without the cable. The target sees a Bluetooth keyboard. That difference cuts
both ways, and the engagement report should say which applies:

* You do not need physical access to a port — you need radio range.
* The target must pair, or must already trust a keyboard. **A host that
  accepts an unauthenticated HID connection is the finding.** A host that
  demands confirmed pairing is not vulnerable to this, and saying so is part
  of the deliverable.

## Install

```bash
esptool.py --chip esp32c3 erase_flash
esptool.py --chip esp32c3 write_flash -z 0 ESP32_GENERIC_C3-*.bin

cp config.example.py config.py     # edit device, mode, hive_url, ingest_key
for f in config.py main.py link.py scanner.py portal.py hid.py; do
    mpremote connect /dev/ttyACM0 fs cp $f :$f
done
mpremote connect /dev/ttyACM0 reset
```

On macOS the port is `/dev/cu.usbmodem*`.

## scan — passive recon

Listens only. Never probes, never associates with what it observes, and
connects only to your own uplink to report. Wi-Fi beacons give SSID, BSSID,
channel, RSSI and security mode; BLE gives address, address type, advertised
name and service UUIDs.

Every sighting is flagged `randomised_mac` when the address is
locally-administered or a BLE random address — a randomised MAC cannot be
used to track a device across sessions, and a report should not imply it can.

Sightings become `wireless_sighting` events (ATT&CK T1040) and plot on the
offline map when `lat`/`lon` are set.

## portal — rogue access point

Broadcasts an open AP, answers every DNS query with its own address so any
request trips the target's captive-portal check, and serves a login page.
Demonstrates one finding: that people will type credentials into a network
that merely looks familiar.

Captures become `credential_capture` events. **By default only a SHA-256
fingerprint is stored**, not the password — enough to prove someone typed a
real credential without putting it in an evidence log you will hand over.
Set `portal_include_material` only if your rules of engagement require the
material itself; the event records that you chose to.

The portal template ships generic. Building a convincing replica of a
specific organisation's login page is a decision for your engagement and your
authorisation, not something the toolkit should ship ready to run.

## hid — Bluetooth keystroke injection

Advertises as a keyboard, waits for a host to pair, then types a DuckyScript
payload from `payload.txt`. Deployments report themselves to the Hive over
Wi-Fi as `hid_deployment` events (T1200 + T1059) — nothing to import
afterwards.

Supported DuckyScript: `REM`, `DELAY`, `DEFAULT_DELAY`, `STRING`, `STRINGLN`,
`REPEAT`, and modifier combinations (`GUI r`, `CTRL ALT DELETE`, `SHIFT F10`),
`F1`–`F12`, arrows, and the usual named keys. `REPEAT` is capped at 500 so a
typo cannot lock a target up.

The supplied payloads are demonstrative — proof-of-execution, read-only host
enumeration, workstation lock. The interpreter runs any DuckyScript you
write; payloads that only make sense as live attack tooling belong in your own
engagement notes, alongside the authorisation that covers them.

## The clock

The C3 has no battery-backed RTC. It tries NTP on start and retries when the
uplink returns, but on an air-gapped job that will fail — so it only sets
`occurred_at` when the clock was actually set, and otherwise lets the Hive
record its own receipt time. Every event carries `time_synced` so an analyst
knows which timestamps came from the board.

Stamping everything 2000-01-01 would be worse than admitting it did not know.

## Limitations

* **No USB HID.** Silicon, not firmware. See above.
* **BLE HID needs pairing.** Against a host that requires confirmed pairing,
  this gets you an advertisement and nothing else. That result is a finding,
  not a failure.
* **Wi-Fi scan sees access points, not clients.** MicroPython's `WLAN.scan()`
  returns beacons only. Probe-request harvesting needs raw 802.11 monitor
  mode, which the MicroPython port does not expose — use
  `hexbee-netmon run --monitor` with a capable adapter instead.
* **Scan is cyclical, not continuous.** A device that appears and leaves
  between sweeps is missed.
* **No BLE 5 extended advertising** — MicroPython's `bluetooth` module handles
  legacy advertisements only.
* **AP mode and uplink share one radio.** In `portal` mode the board reports
  after the portal stops; anything it cannot deliver spools to flash and
  uploads on the next run.
* **Not validated on hardware.** Everything here is written and contract-
  tested against the Hive, but no board has run it. Expect to debug pairing
  and BLE IRQ constants for your particular MicroPython build.
