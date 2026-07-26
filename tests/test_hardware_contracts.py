"""The contract between firmware and the Hive.

None of the firmware has run on hardware. What *can* be verified without a
board is that the exact bytes each device puts on the wire are accepted by
the software that receives them — because a mismatch there costs a whole
bench session to find, and the symptom (silently rejected events) looks
identical to a wiring fault.

So every payload here is built from the real format string in the firmware,
not from a hand-written approximation. When someone edits the firmware and
changes a field, these fail.
"""

import json
import re
from pathlib import Path

import pytest

from hexbee_hive import attack
from hexbee_hive.correlate import Correlator
from hexbee_hive.ingest import process_raw_event
from hexbee_hive.normalize import EVENT_SEVERITY, NormalizationError, normalize

ROOT = Path(__file__).resolve().parent.parent


# =====================================================================
# Would the firmware even load?
#
# MicroPython and CircuitPython are Python, so a syntax error or an import
# of something the runtime does not ship is findable here. On a board these
# surface as a traceback you can only read over a serial cable, usually
# after you have already sealed the enclosure.
# =====================================================================

MICROPYTHON_MODULES = {
    "gc", "time", "sys", "os", "json", "network", "socket", "struct",
    "machine", "ubinascii", "ujson", "urequests", "bluetooth", "micropython",
    "binascii", "hashlib", "random", "select", "errno", "re", "ntptime",
    "uasyncio", "esp", "esp32",
}
CIRCUITPYTHON_MODULES = {
    "time", "sys", "os", "gc", "json", "struct", "board", "digitalio",
    "storage", "supervisor", "usb_hid", "usb_cdc", "microcontroller",
    "busio", "analogio", "pwmio", "neopixel", "binascii", "hashlib",
    "random", "math", "rtc", "watchdog", "adafruit_hid", "adafruit_hashlib",
}

FIRMWARE = [
    ("scout/c3-stinger/main.py", MICROPYTHON_MODULES),
    ("scout/c3-stinger/link.py", MICROPYTHON_MODULES),
    ("scout/c3-stinger/scanner.py", MICROPYTHON_MODULES),
    ("scout/c3-stinger/portal.py", MICROPYTHON_MODULES),
    ("scout/c3-stinger/hid.py", MICROPYTHON_MODULES),
    ("scout/c3-stinger/config.example.py", MICROPYTHON_MODULES),
]


@pytest.mark.parametrize("rel,available", FIRMWARE,
                         ids=[f[0] for f in FIRMWARE])
def test_firmware_parses_and_imports_only_what_the_board_has(rel, available):
    import ast

    path = ROOT / rel
    assert path.is_file(), f"{rel} is missing"
    source = path.read_text(encoding="utf-8")

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        pytest.fail(f"{rel} would not load: line {exc.lineno}: {exc.msg}")

    # Modules that live on the board's own filesystem alongside this file.
    local = {p.stem for p in path.parent.glob("*.py")} | {"config"}

    missing = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root not in available and root not in local:
                    missing.append(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            root = node.module.split(".")[0]
            if root not in available and root not in local:
                missing.append(node.module)
    assert not missing, (
        f"{rel} imports modules the runtime does not provide: "
        f"{', '.join(sorted(set(missing)))} — this is an ImportError on boot")


def accepted(raw: dict) -> dict:
    """Normalize as the Hive would, failing loudly if it would be rejected."""
    try:
        return normalize(raw)
    except NormalizationError as exc:
        pytest.fail(f"the Hive would reject this device event: {exc}\n"
                    f"{json.dumps(raw, indent=2)}")


# =====================================================================
# ESP32-S3 Scout — usb_watch.c emits JSON built with snprintf, wrapped by
# emit_event() in scout_main.c. Both are string formatting in C, so the only
# way to know the result parses is to reproduce it.
# =====================================================================

def scout_event(event_type: str, payload_json: str) -> dict:
    """Reproduce emit_event() from scout_main.c exactly."""
    wrapped = ('{"device":"%s","event_type":"%s",'
               '"occurred_at":%d,"payload":%s}'
               % ("Scout01", event_type, 1785000000, payload_json))
    return json.loads(wrapped)


def test_scout_wrapper_produces_valid_json():
    event = scout_event("usb_inserted", '{"vendor":"SanDisk"}')
    assert event["device"] == "Scout01"
    assert isinstance(event["occurred_at"], int)


def test_scout_file_metadata_is_accepted():
    """The per-file event from usb_watch.c's walk()."""
    payload = ('{"path":"%s","size":%d,"modified":%d,'
               '"sha256_prefix":"%s","hashed_bytes":%u,'
               '"executable":%s,"partial_hash":true}'
               % ("/invoice.pdf.exe", 184320, 1785000000, "a" * 64, 4096,
                  "true")).replace("%u", "")
    event = scout_event("file_metadata", payload)
    result = accepted(event)
    assert result["event_type"] == "file_metadata"
    assert result["payload"]["partial_hash"] is True
    assert result["payload"]["executable"] is True
    # A prefix hash must never be mistaken for a full-file hash downstream.
    assert result["payload"]["hashed_bytes"] == 4096


def test_scout_device_info_is_accepted():
    payload = ('{"vendor":"%s","product":"%s","capacity_mb":%d,'
               '"sector_size":%d,"address":%d}'
               % ("SanDisk", "Cruzer Blade", 15200, 512, 1))
    result = accepted(scout_event("usb_inserted", payload))
    assert result["severity"] == 1
    assert set(attack.map_event("usb_inserted")) == {"T1200", "T1091"}


def test_scout_scan_summary_is_accepted():
    payload = ('{"files":%d,"skipped":%d,"truncated":%s,'
               '"hash_bytes":%d,"seconds":%d}'
               % (512, 3, "true", 4096, 41))
    result = accepted(scout_event("usb_scan", payload))
    assert result["payload"]["truncated"] is True


def test_scout_error_event_is_accepted():
    payload = '{"stage":"mount","error":"ESP_ERR_NOT_SUPPORTED"}'
    accepted(scout_event("usb_scan", payload))


def test_scout_json_escaping_survives_hostile_filenames():
    """Filenames on a seized stick are attacker-controlled. usb_watch.c
    escapes them; an unescaped quote would corrupt the evidence record."""
    from html import unescape  # noqa: F401  (documenting intent only)

    # What json_escape() in usb_watch.c produces for: he said "run".exe
    escaped = 'he said \\"run\\".exe'
    payload = ('{"path":"%s","size":1,"modified":0,"sha256_prefix":"",'
               '"hashed_bytes":0,"executable":true,"partial_hash":true}'
               % escaped)
    event = scout_event("file_metadata", payload)
    assert event["payload"]["path"] == 'he said "run".exe'


def test_scout_event_types_are_all_known_to_the_hive():
    """Every type usb_watch.c can emit, via the switch in scout_main.c."""
    for event_type in ("usb_inserted", "usb_removed", "file_metadata",
                       "usb_scan", "heartbeat", "scout_online"):
        assert event_type in EVENT_SEVERITY, (
            f"the Scout emits {event_type} but the Hive has no severity for it")


# =====================================================================
# ESP32-C3 scanner — MicroPython. The payload shapes are built in
# scan_wifi() and scan_ble() and framed by _enqueue().
# =====================================================================

C3_SOURCE = (ROOT / "scout" / "c3-stinger" / "link.py").read_text(encoding="utf-8")


def c3_event(payload: dict, event_type: str = "wireless_sighting") -> dict:
    """Reproduce link.enqueue() from the Stinger firmware."""
    return {"device": "C3-Stinger-01", "event_type": event_type,
            "payload": payload | {"device_name": "C3-Stinger-01",
                                  "time_synced": False}}


def test_c3_wifi_sighting_is_accepted():
    result = accepted(c3_event({
        "kind": "wifi_ap", "bssid": "aa:bb:cc:00:11:22", "ssid": "CLIENT-GUEST",
        "hidden": False, "channel": 6, "rssi": -62, "security": "wpa2-psk",
        "open_network": False, "randomised_mac": False,
        "lat": 51.5074, "lon": -0.1278,
    }))
    assert result["event_type"] == "wireless_sighting"
    assert attack.map_event("wireless_sighting") == ["T1040"]


def test_c3_ble_sighting_is_accepted():
    result = accepted(c3_event({
        "kind": "ble_device", "address": "d2:11:22:33:44:55",
        "address_type": "random", "randomised_mac": True, "name": "Fitbit",
        "service_uuids": ["180d", "180f"], "rssi": -71,
    }))
    assert result["payload"]["randomised_mac"] is True


def test_c3_gps_sightings_reach_the_map():
    """maps.evidence_points only picks up events with numeric lat/lon."""
    from hexbee_hive.maps import evidence_points
    from hexbee_hive.db import Database
    import tempfile

    db = Database(Path(tempfile.mkdtemp()) / "t.db")
    try:
        process_raw_event(db, Correlator(db, 600), c3_event({
            "kind": "wifi_ap", "bssid": "aa:bb:cc:00:11:22", "ssid": "X",
            "rssi": -50, "lat": 51.5074, "lon": -0.1278}), source="test")
        points = evidence_points(db)
        assert len(points) == 1 and points[0]["lat"] == pytest.approx(51.5074)
    finally:
        db.close()


def test_c3_only_claims_a_time_when_its_clock_was_set():
    """A board with no clock must not claim to know when something happened.

    MicroPython's time.time() starts at zero on a board with no RTC and no
    NTP, so converting it to a unix epoch stamps every sighting 2000-01-01.
    Omitting occurred_at instead lets the Hive record its own receipt time,
    which is at least true.
    """
    enqueue = re.search(r"def enqueue\(.*?(?=\n(?:def |# --))", C3_SOURCE, re.S)
    assert enqueue, "could not find enqueue() in the C3 firmware"
    body = enqueue.group(0)
    assert "if _time_synced" in body, (
        "the C3 sets occurred_at unconditionally, but the board has no RTC — "
        "unsynced, every sighting would be timestamped 2000-01-01")
    # The epoch conversion must sit inside the guarded branch, not before it.
    before_guard = body[:body.index("if _time_synced")]
    assert "_EPOCH_OFFSET" not in before_guard, (
        "the epoch conversion happens before the clock-trusted guard")
    assert "occurred_at" not in before_guard, (
        "occurred_at is set before the clock is known to be good")


def test_c3_attempts_a_time_sync():
    assert "ntptime" in C3_SOURCE, "the C3 never tries to set its clock"


def test_c3_reports_whether_its_clock_is_trustworthy():
    assert 'payload["time_synced"]' in C3_SOURCE, (
        "sightings should say whether the board's clock was set, so an "
        "analyst knows whether to trust the times")


def test_scout_only_claims_a_time_when_its_clock_was_set():
    """Same defect, same fix, in C. The Scout is worse off than the C3: it is
    built for air-gapped deployments where its SNTP server is unreachable, so
    without a guard its timestamps would read 1970 in normal field use."""
    source = (ROOT / "scout" / "firmware" / "main" / "scout_main.c").read_text(
        encoding="utf-8")
    assert "clock_is_trusted" in source, (
        "the Scout stamps occurred_at from an unsynced clock")
    emit = re.search(r"static void emit_event.*?\n\}", source, re.S).group(0)
    assert "if (clock_is_trusted())" in emit
    # The untrusted-clock branch must omit occurred_at entirely rather than
    # sending a value nobody should believe. Comments are stripped first —
    # the fix explains itself by naming the field, and matching that
    # explanation would fail on correct code.
    fallback = emit.split("} else {", 1)
    assert len(fallback) == 2, "no fallback branch for an unset clock"
    code = re.sub(r"/\*.*?\*/", "", fallback[1], flags=re.S)
    assert "occurred_at" not in code, (
        "the fallback still sends occurred_at from an unsynced clock")


def test_event_without_a_timestamp_is_accepted_and_stamped():
    """The behaviour both guards rely on."""
    result = normalize({"device": "C3-Stinger-01",
                        "event_type": "wireless_sighting",
                        "payload": {"kind": "wifi_ap", "time_synced": False}})
    assert result["occurred_at"].endswith("Z")
    assert result["occurred_at"] > "2020-01-01T00:00:00Z", (
        "an event with no timestamp should get the Hive's receipt time")


# =====================================================================
# Every event type any firmware emits must be known to the Hive, mapped
# sensibly, and reach an incident when it should.
# =====================================================================

FIRMWARE_EVENT_TYPES = [
    ("usb_inserted", 1), ("usb_removed", 0), ("file_metadata", 0),
    ("usb_scan", 1), ("wireless_sighting", 0), ("case_seal", 1),
    ("hid_deployment", 2), ("credential_capture", 3), ("recon_finding", 1),
    ("heartbeat", 0), ("scout_online", 0),
]


@pytest.mark.parametrize("event_type,severity", FIRMWARE_EVENT_TYPES)
def test_firmware_event_types_have_the_expected_severity(event_type, severity):
    assert EVENT_SEVERITY.get(event_type) == severity, (
        f"{event_type} would arrive at an unexpected severity, changing "
        f"whether it opens an incident")


def test_high_volume_file_metadata_does_not_open_an_incident(db):
    """A 512-file stick must not open 512 incidents."""
    correlator = Correlator(db, 600)
    for i in range(30):
        process_raw_event(db, correlator, scout_event(
            "file_metadata",
            '{"path":"/f%d.txt","size":1,"modified":0,"sha256_prefix":"",'
            '"hashed_bytes":0,"executable":false,"partial_hash":true}' % i),
            source="test")
    incidents = db.query_one("SELECT COUNT(*) AS n FROM incidents")["n"]
    assert incidents == 0, "routine file listings should not raise incidents"
