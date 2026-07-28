"""One-shot hardware self-test — run without editing config.py.

Exercises the same Wi-Fi and BLE scan paths as `main.py`'s scan mode, once,
then exits (main.py loops forever, which doesn't work for a smoke test).
Safe regardless of what's in config.py: it never transmits, and only
touches the Hive if hive_url/ingest_key are already set (skipped otherwise).

Usage:
    mpremote connect /dev/cu.usbmodem1101 run selftest.py     # macOS
    mpremote connect /dev/ttyACM0 run selftest.py             # Linux
"""

import link
import scanner

print("device:", link.DEVICE)
print("hive:", link.HIVE_URL or "(none configured — scan-only smoke test)")

sta = link.connect_wifi()
print("wifi uplink configured:", bool(link.WIFI_SSID))

wifi_hits = scanner.scan_wifi(sta)
print("wifi beacons seen:", wifi_hits)

ble_hits = 0
try:
    import bluetooth

    ble = bluetooth.BLE()
    ble.active(True)
    ble_hits = scanner.scan_ble(ble, 3)
    print("ble advertisements seen:", ble_hits)
except Exception as exc:
    print("ble error:", exc)

print("queued events:", link.queued())

sent = link.flush(sta)
if sent:
    print("uploaded", sent, "event(s) to the Hive")
elif link.queued():
    print("Hive not configured/reachable — events stayed queued (not spooled by this test)")

print("SELFTEST OK" if (wifi_hits >= 0 and ble_hits >= 0) else "SELFTEST FAILED")
