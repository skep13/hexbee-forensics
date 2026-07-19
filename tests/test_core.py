"""Hive core: normalization, hash chain, correlation, cases, auth, search."""

import json

import pytest

from hexbee_hive.auth import (
    authenticate,
    check_password,
    create_user,
    hash_password,
    resolve_token,
    role_allows,
)
from hexbee_hive.cases import add_note, assign_incident, create_case, get_case, tag_event
from hexbee_hive.correlate import Correlator
from hexbee_hive.integrity import verify_chain
from hexbee_hive.normalize import NormalizationError, normalize
from hexbee_hive.reports import case_report_data, render_csv, render_html, render_json
from hexbee_hive.search import search_events, stats
from hexbee_hive.store import store_event
from hexbee_hive.timeline import incident_timeline


def make_event(device="Scout01", event_type="heartbeat", at="2026-07-18T10:00:00Z", payload=None):
    return normalize(
        {"device": device, "event_type": event_type, "occurred_at": at,
         "payload": payload or {}}
    )


# -- normalization --------------------------------------------------------

def test_normalize_accepts_epoch_and_iso():
    iso = normalize({"device": "S1", "event_type": "heartbeat",
                     "occurred_at": "2026-07-18T10:00:00+00:00"})
    epoch = normalize({"device": "S1", "event_type": "heartbeat",
                       "occurred_at": 1784368800})
    assert iso["occurred_at"] == "2026-07-18T10:00:00Z"
    assert epoch["occurred_at"].endswith("Z")


def test_normalize_rejects_garbage():
    with pytest.raises(NormalizationError):
        normalize({"event_type": "x"})  # no device
    with pytest.raises(NormalizationError):
        normalize({"device": "S1"})  # no type
    with pytest.raises(NormalizationError):
        normalize({"device": "S1", "event_type": "x", "payload": "not-a-dict"})
    with pytest.raises(NormalizationError):
        normalize({"device": "../etc", "event_type": "x"})


def test_normalize_severity_known_and_unknown():
    assert make_event(event_type="network_beacon")["severity"] == 3
    assert make_event(event_type="brand_new_type")["severity"] == 0


# -- hash chain -----------------------------------------------------------

def test_chain_verifies_and_detects_tampering(db):
    for i in range(5):
        store_event(db, make_event(at=f"2026-07-18T10:00:0{i}Z", payload={"i": i}))
    assert verify_chain(db) == {"ok": True, "checked": 5, "first_bad_id": None}

    # Tamper with event 3's payload behind the store's back.
    db.execute("UPDATE events SET payload = ? WHERE id = 3", (json.dumps({"i": 999}),))
    result = verify_chain(db)
    assert result["ok"] is False
    assert result["first_bad_id"] == 3


def test_chain_detects_deletion(db):
    for i in range(4):
        store_event(db, make_event(at=f"2026-07-18T10:00:0{i}Z", payload={"i": i}))
    db.execute("DELETE FROM events WHERE id = 2")
    assert verify_chain(db)["ok"] is False


# -- correlation ----------------------------------------------------------

def test_incident_scenario_groups_events(db):
    correlator = Correlator(db, window_seconds=600)
    sequence = [
        ("scout_online", "10:00:00"),
        ("usb_inserted", "10:01:00"),
        ("usb_scan", "10:02:00"),
        ("executable_found", "10:03:00"),   # trigger (sev 2)
        ("powershell_launched", "10:04:00"),
        ("network_beacon", "10:05:00"),
    ]
    incident_ids = set()
    for event_type, hms in sequence:
        eid = store_event(db, make_event(event_type=event_type,
                                         at=f"2026-07-18T{hms}Z"))
        result = correlator.process_event(eid)
        if result:
            incident_ids.add(result)

    assert len(incident_ids) == 1
    incident_id = incident_ids.pop()
    timeline = incident_timeline(db, incident_id)
    # Context events before the trigger were swept in retroactively.
    assert [t["event_type"] for t in timeline] == [t for t, _ in sequence]
    incident = db.query_one("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    assert incident["severity"] == 3  # escalated by the beacon


def test_low_severity_alone_opens_no_incident(db):
    correlator = Correlator(db, window_seconds=600)
    for i in range(3):
        eid = store_event(db, make_event(at=f"2026-07-18T10:00:0{i}Z"))
        assert correlator.process_event(eid) is None
    assert db.query_one("SELECT COUNT(*) AS n FROM incidents")["n"] == 0


def test_separate_windows_make_separate_incidents(db):
    correlator = Correlator(db, window_seconds=600)
    first = store_event(db, make_event(event_type="executable_found",
                                       at="2026-07-18T10:00:00Z"))
    second = store_event(db, make_event(event_type="executable_found",
                                        at="2026-07-18T12:00:00Z"))
    a = correlator.process_event(first)
    b = correlator.process_event(second)
    assert a != b and a and b


# -- cases ----------------------------------------------------------------

def test_case_lifecycle(db):
    correlator = Correlator(db, window_seconds=600)
    eid = store_event(db, make_event(event_type="executable_found"))
    incident_id = correlator.process_event(eid)

    case = create_case(db, "USB malware", "front desk PC", "analyst")
    assert case["case_number"].startswith("HB-")
    assert assign_incident(db, incident_id, case["id"], "analyst")
    add_note(db, case["id"], "analyst", "Imaged the stick.")
    tag_event(db, eid, "Malware", "analyst")

    loaded = get_case(db, case["id"])
    assert len(loaded["incidents"]) == 1
    assert loaded["notes"][0]["body"] == "Imaged the stick."

    from hexbee_hive.cases import event_tags
    assert event_tags(db, eid) == ["malware"]  # normalized to lowercase


def test_report_renders_all_formats(db):
    correlator = Correlator(db, window_seconds=600)
    eid = store_event(db, make_event(event_type="executable_found",
                                     payload={"name": "evil.exe"}))
    incident_id = correlator.process_event(eid)
    case = create_case(db, "Report test", "", "analyst")
    assign_incident(db, incident_id, case["id"], "analyst")

    data = case_report_data(db, case["id"])
    assert data["integrity"]["ok"]
    html = render_html(data)
    assert "evil.exe" in html and case["case_number"] in html
    assert "evil.exe" in render_csv(data)
    assert json.loads(render_json(data))["case"]["id"] == case["id"]


# -- auth -----------------------------------------------------------------

def test_password_hash_roundtrip():
    stored = hash_password("hunter22")
    assert check_password("hunter22", stored)
    assert not check_password("wrong", stored)
    assert not check_password("hunter22", "garbage")


def test_authenticate_and_roles(db):
    create_user(db, "alice", "correct-horse-battery", "investigator")
    assert authenticate(db, "alice", "nope") is None
    session = authenticate(db, "alice", "correct-horse-battery")
    assert session["role"] == "investigator"
    resolved = resolve_token(db, session["token"])
    assert resolved["username"] == "alice"
    assert resolve_token(db, "bogus") is None

    assert role_allows("administrator", "viewer")
    assert role_allows("investigator", "viewer")
    assert not role_allows("viewer", "investigator")


def test_create_user_validates(db):
    with pytest.raises(ValueError):
        create_user(db, "bob", "short", "viewer")           # too short
    with pytest.raises(ValueError):
        create_user(db, "bob", "correct-horse-batt", "superuser")  # bad role
    with pytest.raises(ValueError):
        create_user(db, "bob", "password123", "viewer")     # common password
    with pytest.raises(ValueError):
        create_user(db, "bob", "elevenchars", "viewer")     # 11 < 12 chars
    # a strong password is accepted
    assert create_user(db, "bob", "a-strong-passphrase", "viewer")


# -- search ---------------------------------------------------------------

def test_search_filters(db):
    store_event(db, make_event(device="Scout01", event_type="executable_found",
                               payload={"name": "evil.exe"}))
    store_event(db, make_event(device="Scout02", event_type="heartbeat"))

    assert len(search_events(db, text="evil.exe")) == 1
    assert len(search_events(db, device="Scout02")) == 1
    assert len(search_events(db, min_severity=2)) == 1
    assert len(search_events(db)) == 2
    s = stats(db)
    assert s["events"] == 2 and s["devices"] == 2
