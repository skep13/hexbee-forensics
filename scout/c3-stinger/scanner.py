"""Passive wireless reconnaissance.

Listens only: never probes, never associates with anything it observes, and
transmits only over the operator's own uplink. This is the mode you leave
running before an engagement to learn what is there.
"""

import time

import network
import ubinascii

from link import enqueue

try:
    import bluetooth
    HAVE_BLE = True
except ImportError:
    HAVE_BLE = False

# Bounded state — a busy street produces thousands of frames an hour and the
# board has around 100 KB of usable heap.
MAX_TRACKED = 400
RESEEN_AFTER = 900          # seconds before the same device is reported again

AUTH_MODES = {0: "open", 1: "wep", 2: "wpa-psk", 3: "wpa2-psk",
              4: "wpa/wpa2-psk", 5: "wpa2-enterprise", 6: "wpa3-psk",
              7: "wpa2/wpa3-psk", 8: "wapi-psk"}

_seen = {}


def _mac(raw):
    return ubinascii.hexlify(raw, ":").decode()


def _randomised(mac):
    """Locally-administered bit set — the marker of a privacy-randomised MAC.

    Worth recording: a randomised address cannot be used to track that device
    across sessions, and a report should not imply otherwise.
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
        # Cheap bound: clear rather than do LRU bookkeeping we have no RAM
        # for. Worst case is one duplicated round of sightings.
        _seen.clear()
    _seen[key] = now
    return True


def scan_wifi(sta):
    """Beacon-frame scan. Does not associate with anything."""
    found, now = 0, time.time()
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
        enqueue("wireless_sighting", {
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


_ADV_IND, _SCAN_RSP = 0x00, 0x04


def _parse_adv(data):
    """Pull the name and service UUIDs out of an advertisement payload.

    Hand-rolled because MicroPython has no AD-structure parser and aioble
    costs more heap than the C3 can spare.
    """
    name, uuids, i = "", [], 0
    data = bytes(data)
    while i + 1 < len(data):
        length = data[i]
        if length == 0 or i + length >= len(data) + 1:
            break
        ad_type = data[i + 1]
        chunk = data[i + 2:i + 1 + length]
        if ad_type in (0x08, 0x09):                 # shortened / complete name
            try:
                name = chunk.decode()
            except UnicodeError:
                name = repr(chunk)
        elif ad_type in (0x02, 0x03):               # 16-bit service UUIDs
            for j in range(0, len(chunk) - 1, 2):
                uuids.append("%04x" % (chunk[j] | (chunk[j + 1] << 8)))
        i += 1 + length
    return name, uuids[:6]


def scan_ble(ble, seconds=8):
    if not HAVE_BLE or ble is None:
        return 0
    hits = {"n": 0}

    def on_event(event, data):
        if event != 5:          # _IRQ_SCAN_RESULT
            return
        addr_type, addr, adv_type, rssi, adv_data = data
        if adv_type not in (_ADV_IND, _SCAN_RSP, 0x02, 0x03):
            return
        mac = _mac(bytes(addr))
        if not _should_report("ble:" + mac, time.time()):
            return
        name, uuids = _parse_adv(adv_data)
        enqueue("wireless_sighting", {
            "kind": "ble_device",
            "address": mac,
            # addr_type 1 = random; 0 = public, a stable traceable identity
            "address_type": "random" if addr_type else "public",
            "randomised_mac": bool(addr_type) or _randomised(mac),
            "name": name,
            "service_uuids": uuids,
            "rssi": rssi,
        })
        hits["n"] += 1

    ble.irq(on_event)
    try:
        # A wide window favours catching beacons over fast discovery.
        ble.gap_scan(seconds * 1000, 30000, 30000, False)
        time.sleep(seconds + 1)
        ble.gap_scan(None)
    except OSError as exc:
        print("ble scan failed:", exc)
    return hits["n"]
