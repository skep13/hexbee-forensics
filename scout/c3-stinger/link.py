"""Uplink to the Hive: config, Wi-Fi, clock, and the outbound event queue.

Shared by every mode so they all report the same way, spool the same way when
the Hive is unreachable, and are equally honest about whether the board knew
what time it was.
"""

import gc
import time

import network
import ujson
import urequests

try:
    from config import CONFIG
except ImportError:
    CONFIG = {}

DEVICE = CONFIG.get("device", "C3-Stinger")
HIVE_URL = CONFIG.get("hive_url", "")
INGEST_KEY = CONFIG.get("ingest_key", "")
WIFI_SSID = CONFIG.get("wifi_ssid", "")
WIFI_PASSWORD = CONFIG.get("wifi_password", "")
LAT = CONFIG.get("lat")
LON = CONFIG.get("lon")

MAX_BATCH = 25
MAX_QUEUE = 200
SPOOL_FILE = "spool.jsonl"

# The C3 has no battery-backed clock. Until NTP succeeds, time.time() counts
# from zero, so converting it would stamp everything 2000-01-01. Only claim a
# time when the clock was actually set.
_time_synced = False
_EPOCH_OFFSET = 946684800

_queue = []


def time_synced():
    return _time_synced


def sync_time():
    """Set the clock from NTP. Failure is expected on an air-gapped job."""
    global _time_synced
    try:
        import ntptime

        ntptime.settime()
        _time_synced = True
        print("clock synced")
    except Exception as exc:
        _time_synced = False
        print("no NTP (", exc, ") — the Hive will timestamp on receipt")
    return _time_synced


def connect_wifi(timeout=10):
    """Join the operator's own uplink network. Never a target's."""
    sta = network.WLAN(network.STA_IF)
    sta.active(True)
    if sta.isconnected() or not WIFI_SSID:
        return sta
    sta.connect(WIFI_SSID, WIFI_PASSWORD)
    for _ in range(timeout * 2):
        if sta.isconnected():
            print("uplink:", sta.ifconfig()[0])
            return sta
        time.sleep(0.5)
    return sta


def enqueue(event_type, payload, severity_note=None):
    """Frame an event the way the Hive expects and queue it for upload."""
    payload["device_name"] = DEVICE
    payload["time_synced"] = _time_synced
    if LAT is not None and LON is not None:
        payload.setdefault("lat", LAT)
        payload.setdefault("lon", LON)
    event = {"device": DEVICE, "event_type": event_type, "payload": payload}
    if _time_synced:
        event["occurred_at"] = time.time() + _EPOCH_OFFSET
    # Otherwise omit it and let the Hive record its own receipt time.
    _queue.append(event)
    if len(_queue) > MAX_QUEUE:
        del _queue[:len(_queue) - MAX_QUEUE]
    return event


def queued():
    return len(_queue)


def flush(sta=None):
    """Upload queued events. Anything that fails stays queued for next time."""
    if not _queue or not (HIVE_URL and INGEST_KEY):
        return 0
    if sta is not None and not sta.isconnected():
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
    return sent


def spool():
    """Write anything still queued to flash, so a power cycle does not lose it."""
    if not _queue:
        return 0
    try:
        with open(SPOOL_FILE, "a") as handle:
            for event in _queue:
                handle.write(ujson.dumps(event) + "\n")
        count = len(_queue)
        del _queue[:]
        return count
    except OSError as exc:
        print("could not spool:", exc)
        return 0


def unspool():
    """Re-queue anything spooled on a previous run."""
    try:
        with open(SPOOL_FILE, "r") as handle:
            lines = handle.readlines()
    except OSError:
        return 0
    recovered = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            _queue.append(ujson.loads(line))
            recovered += 1
        except ValueError:
            continue
    try:
        import os

        os.remove(SPOOL_FILE)
    except OSError:
        pass
    return recovered
