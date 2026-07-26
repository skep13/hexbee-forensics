"""HexBee C3 Scanner — passive wireless sighting sensor (MicroPython).

Runs on the otherwise-idle ESP32-C3. It listens; it never probes, never
associates, never transmits anything except its findings to the Hive.

Two sources:

  * **Wi-Fi**  — `WLAN.scan()` in station mode without connecting. This is a
    passive scan of beacon frames: SSID, BSSID, RSSI, channel, and the
    security mode of every access point in earshot.
  * **BLE**    — passive advertisement scanning via `bluetooth.BLE`. Device
    address, address type (which tells you whether the MAC is randomised),
    RSSI, the advertised name, and any service UUIDs.

Sightings POST to the Hive's `/api/v1/ingest` as `wireless_sighting` events
and plot on the offline evidence map when a fix is available.

Memory: the C3 has 400 KB of SRAM and MicroPython leaves roughly 100 KB of
heap. Everything here is bounded — a fixed-size dedup table, batched uploads
with a hard cap, and no accumulation of history. `gc.collect()` runs after
every cycle because MicroPython does not compact aggressively on its own.

Install:
    mpremote connect /dev/ttyACM0 fs cp config.py :config.py
    mpremote connect /dev/ttyACM0 fs cp main.py :main.py
"""

import gc
import time

import network
import ubinascii
import ujson
import urequests

try:
    import bluetooth
    HAVE_BLE = True
except ImportError:                       # BLE-less MicroPython build
    HAVE_BLE = False

try:
    from config import CONFIG
except ImportError:
    CONFIG = {}

DEVICE = CONFIG.get("device", "C3-Scanner")
HIVE_URL = CONFIG.get("hive_url", "")
INGEST_KEY = CONFIG.get("ingest_key", "")
WIFI_SSID = CONFIG.get("wifi_ssid", "")
WIFI_PASSWORD = CONFIG.get("wifi_password", "")
SCAN_INTERVAL = CONFIG.get("scan_interval", 60)
BLE_SECONDS = CONFIG.get("ble_seconds", 8)
LAT = CONFIG.get("lat")
LON = CONFIG.get("lon")

# Bounded state. A busy street produces thousands of sightings an hour; we
# report each device once per RESEEN_AFTER window and nothing more.
MAX_TRACKED = 400
RESEEN_AFTER = 900          # seconds before the same device is reported again
MAX_BATCH = 25

AUTH_MODES = {0: "open", 1: "wep", 2: "wpa-psk", 3: "wpa2-psk",
              4: "wpa/wpa2-psk", 5: "wpa2-enterprise", 6: "wpa3-psk",
              7: "wpa2/wpa3-psk", 8: "wapi-psk"}

_seen = {}
_queue = []

# The C3 has no battery-backed clock. Until NTP succeeds, time.time() counts
# from the MicroPython epoch starting at zero — so converting it would stamp
# every sighting 2000-01-01. Track whether the clock was ever set, and only
# claim a time when it was.
_time_synced = False
# Seconds between the MicroPython epoch (2000-01-01) and the unix epoch.
_EPOCH_OFFSET = 946684800


def sync_time():
    """Set the clock from NTP. Returns True when the time can be trusted.

    Failure is expected and fine: the kit is built to run air-gapped, and a
    scanner with no clock is still useful — the Hive records its own receipt
    time for anything that arrives without one.
    """
    global _time_synced
    try:
        import ntptime

        ntptime.settime()
        _time_synced = True
        print("clock synced from NTP")
    except Exception as exc:
        _time_synced = False
        print("no NTP (", exc, ") — the Hive will timestamp on receipt")
    return _time_synced


def _mac(raw):
    return ubinascii.hexlify(raw, ":").decode()


def _randomised(mac):
    """Locally-administered bit set — the marker of a privacy-randomised MAC.

    Worth recording: a randomised address means the sighting cannot be used
    to track that device across sessions, and a report should say so rather
    than implying a stable identity.
    """
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def _should_report(key, now):
    last = _seen.get(key)
    if last is not None and (now - last) < RESEEN_AFTER:
        return False
    if len(_seen) >= MAX_TRACKED:
        # Cheap bound: drop the whole table rather than doing LRU bookkeeping
        # we have no RAM for. Worst case is one duplicate round of sightings.
        _seen.clear()
    _seen[key] = now
    return True


def _enqueue(payload):
    payload["device_name"] = DEVICE
    # Say plainly whether the board knew what time it was. An analyst reading
    # the case timeline needs to know which timestamps came from the sensor
    # and which the Hive supplied on receipt.
    payload["time_synced"] = _time_synced
    if LAT is not None and LON is not None:
        payload["lat"] = LAT
        payload["lon"] = LON
    event = {
        "device": DEVICE,
        "event_type": "wireless_sighting",
        "payload": payload,
    }
    if _time_synced:
        event["occurred_at"] = time.time() + _EPOCH_OFFSET
    # Otherwise occurred_at is omitted and the Hive stamps its receipt time.
    _queue.append(event)


# -- Wi-Fi passive scan ---------------------------------------------------

def scan_wifi(sta):
    """Beacon-frame scan. Does not associate with anything."""
    found = 0
    now = time.time()
    try:
        results = sta.scan()
    except OSError as exc:
        print("wifi scan failed:", exc)
        return 0
    for entry in results:
        ssid_raw, bssid, channel, rssi, authmode, hidden = entry[:6]
        bssid_str = _mac(bssid)
        if not _should_report("wifi:" + bssid_str, now):
            continue
        try:
            ssid = ssid_raw.decode()
        except UnicodeError:
            ssid = repr(ssid_raw)
        _enqueue({
            "kind": "wifi_ap",
            "bssid": bssid_str,
            "ssid": ssid if ssid else "(hidden)",
            "hidden": bool(hidden),
            "channel": channel,
            "rssi": rssi,
            "security": AUTH_MODES.get(authmode, str(authmode)),
            "open_network": authmode == 0,
            "randomised_mac": _randomised(bssid_str),
        })
        found += 1
    return found


# -- BLE passive scan -----------------------------------------------------

_ADV_IND, _SCAN_RSP = 0x00, 0x04


def _parse_adv(data):
    """Pull the name and service UUIDs out of an advertisement payload.

    Hand-rolled because MicroPython has no AD-structure parser and pulling in
    aioble costs more heap than the C3 can spare.
    """
    name, uuids = "", []
    i = 0
    data = bytes(data)
    while i + 1 < len(data):
        length = data[i]
        if length == 0 or i + length >= len(data) + 1:
            break
        ad_type = data[i + 1]
        chunk = data[i + 2:i + 1 + length]
        if ad_type in (0x08, 0x09):                    # shortened / complete name
            try:
                name = chunk.decode()
            except UnicodeError:
                name = repr(chunk)
        elif ad_type in (0x02, 0x03):                  # 16-bit service UUIDs
            for j in range(0, len(chunk) - 1, 2):
                uuids.append("%04x" % (chunk[j] | (chunk[j + 1] << 8)))
        i += 1 + length
    return name, uuids[:6]


def scan_ble(ble, seconds):
    if not HAVE_BLE:
        return 0
    hits = {"n": 0}

    def on_event(event, data):
        # 5 = _IRQ_SCAN_RESULT, 6 = _IRQ_SCAN_DONE
        if event != 5:
            return
        addr_type, addr, adv_type, rssi, adv_data = data
        if adv_type not in (_ADV_IND, _SCAN_RSP, 0x02, 0x03):
            return
        mac = _mac(bytes(addr))
        now = time.time()
        if not _should_report("ble:" + mac, now):
            return
        name, uuids = _parse_adv(adv_data)
        _enqueue({
            "kind": "ble_device",
            "address": mac,
            # addr_type 1 = random; 0 = public (a stable, traceable identity)
            "address_type": "random" if addr_type else "public",
            "randomised_mac": bool(addr_type) or _randomised(mac),
            "name": name,
            "service_uuids": uuids,
            "rssi": rssi,
        })
        hits["n"] += 1

    ble.irq(on_event)
    try:
        # interval_us/window_us tuned for passive listening rather than fast
        # discovery: a wider window catches more beacons per unit of radio time.
        ble.gap_scan(seconds * 1000, 30000, 30000, False)
        time.sleep(seconds + 1)
        ble.gap_scan(None)
    except OSError as exc:
        print("ble scan failed:", exc)
    return hits["n"]


# -- upload ---------------------------------------------------------------

def flush(sta):
    """Send queued sightings. Failures keep the queue for the next cycle."""
    if not _queue or not (HIVE_URL and INGEST_KEY):
        return 0
    if not sta.isconnected():
        return 0
    sent = 0
    while _queue:
        batch = _queue[:MAX_BATCH]
        try:
            resp = urequests.post(
                HIVE_URL.rstrip("/") + "/api/v1/ingest",
                data=ujson.dumps(batch),
                headers={"Content-Type": "application/json",
                         "X-HexBee-Ingest-Key": INGEST_KEY})
            ok = resp.status_code == 200
            resp.close()
        except Exception as exc:
            print("upload failed:", exc)
            break
        if not ok:
            break
        sent += len(batch)
        del _queue[:MAX_BATCH]
        gc.collect()
    # Never let an unreachable Hive grow the queue without bound.
    if len(_queue) > 200:
        del _queue[:len(_queue) - 200]
    return sent


def connect_wifi(sta):
    if sta.isconnected() or not WIFI_SSID:
        return sta.isconnected()
    sta.connect(WIFI_SSID, WIFI_PASSWORD)
    for _ in range(20):
        if sta.isconnected():
            print("wifi:", sta.ifconfig()[0])
            return True
        time.sleep(0.5)
    return False


def main():
    sta = network.WLAN(network.STA_IF)
    sta.active(True)
    ble = None
    if HAVE_BLE:
        ble = bluetooth.BLE()
        ble.active(True)

    print("HexBee C3 scanner:", DEVICE, "->", HIVE_URL or "(no hive configured)")
    print("passive only — this device never probes or associates with targets")

    if connect_wifi(sta):
        sync_time()

    while True:
        cycle_start = time.time()
        if connect_wifi(sta) and not _time_synced:
            sync_time()      # retry once the uplink comes back

        wifi_hits = scan_wifi(sta)
        ble_hits = scan_ble(ble, BLE_SECONDS) if ble else 0
        sent = flush(sta)
        gc.collect()
        print("cycle: wifi=%d ble=%d queued=%d sent=%d free=%d"
              % (wifi_hits, ble_hits, len(_queue), sent, gc.mem_free()))

        elapsed = time.time() - cycle_start
        if elapsed < SCAN_INTERVAL:
            time.sleep(SCAN_INTERVAL - elapsed)


if __name__ == "__main__":
    main()
