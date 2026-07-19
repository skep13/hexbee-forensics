"""IOC engine: validation, matching, ingest escalation, API surface."""

import pytest

from hexbee_hive.cases import event_tags
from hexbee_hive.correlate import Correlator
from hexbee_hive.ingest import process_raw_event
from hexbee_hive.ioc import add_ioc, list_hits, list_iocs, match_iocs, remove_ioc

BAD_HASH = "9f2c8b1a" + "0" * 56


def test_add_ioc_validation(db):
    with pytest.raises(ValueError):
        add_ioc(db, "sha256", "nothex", "", "analyst")
    with pytest.raises(ValueError):
        add_ioc(db, "ip", "not-an-ip", "", "analyst")
    with pytest.raises(ValueError):
        add_ioc(db, "wat", "x", "", "analyst")
    add_ioc(db, "sha256", BAD_HASH.upper(), "stored lowercased", "analyst")
    assert list_iocs(db)[0]["value"] == BAD_HASH


def test_match_iocs_recursive_payload(db):
    add_ioc(db, "filename", "evil.exe", "", "analyst")
    add_ioc(db, "ip", "185.203.116.42", "", "analyst")
    assert len(match_iocs(db, {"name": "EVIL.EXE", "size": 5})) == 1
    assert len(match_iocs(db, {"conn": {"destination": "185.203.116.42:443"}})) == 1
    assert match_iocs(db, {"name": "innocent.txt"}) == []


def test_ingest_escalates_ioc_match_and_opens_incident(db):
    add_ioc(db, "filename", "evil.exe", "known dropper", "analyst")
    correlator = Correlator(db, window_seconds=600)

    # file_metadata is normally severity 0 â€” an IOC hit must force an incident.
    result = process_raw_event(
        db, correlator,
        {"device": "Scout01", "event_type": "file_metadata",
         "occurred_at": "2026-07-18T10:00:00Z", "payload": {"name": "evil.exe"}},
        source="test",
    )
    assert result["incident_id"] is not None
    event = db.query_one("SELECT severity FROM events WHERE id = ?", (result["event_id"],))
    assert event["severity"] == 3
    assert event_tags(db, result["event_id"]) == ["ioc"]
    hits = list_hits(db)
    assert len(hits) == 1 and hits[0]["event_id"] == result["event_id"]


def test_clean_event_not_escalated(db):
    add_ioc(db, "filename", "evil.exe", "", "analyst")
    correlator = Correlator(db, window_seconds=600)
    result = process_raw_event(
        db, correlator,
        {"device": "Scout01", "event_type": "file_metadata",
         "occurred_at": "2026-07-18T10:00:00Z", "payload": {"name": "clean.txt"}},
        source="test",
    )
    assert result["incident_id"] is None
    assert list_hits(db) == []


def test_remove_ioc_clears_hits(db):
    ioc_id = add_ioc(db, "filename", "evil.exe", "", "analyst")
    correlator = Correlator(db, window_seconds=600)
    process_raw_event(
        db, correlator,
        {"device": "S1", "event_type": "file_metadata", "payload": {"name": "evil.exe"}},
        source="test",
    )
    assert remove_ioc(db, ioc_id, "analyst")
    assert list_iocs(db) == [] and list_hits(db) == []
    assert not remove_ioc(db, ioc_id, "analyst")


def test_ioc_api(db, tmp_path):
    from hexbee_hive.api import create_app
    from hexbee_hive.auth import create_user
    from hexbee_hive.config import HiveConfig

    create_user(db, "invest", "invest-strong-pass1", "investigator")
    create_user(db, "watcher", "watcher-strong-pass1", "viewer")
    app = create_app(HiveConfig(data_dir=tmp_path, ingest_key="testkey"), db)
    app.testing = True
    client = app.test_client()

    def login(u, p):
        token = client.post("/api/v1/login", json={"username": u, "password": p}
                            ).get_json()["token"]
        return {"Authorization": f"Bearer {token}"}

    invest = login("invest", "invest-strong-pass1")
    viewer = login("watcher", "watcher-strong-pass1")

    # RBAC: viewer reads, cannot write.
    assert client.post("/api/v1/iocs", json={"kind": "filename", "value": "evil.exe"},
                       headers=viewer).status_code == 403
    resp = client.post("/api/v1/iocs", json={"kind": "filename", "value": "evil.exe"},
                       headers=invest)
    assert resp.status_code == 201
    ioc_id = resp.get_json()["ioc_id"]

    # Duplicate -> 409, bad kind -> 400.
    assert client.post("/api/v1/iocs", json={"kind": "filename", "value": "evil.exe"},
                       headers=invest).status_code == 409
    assert client.post("/api/v1/iocs", json={"kind": "nope", "value": "x"},
                       headers=invest).status_code == 400

    # Ingest a matching event -> hit visible, incident opened.
    client.post("/api/v1/ingest",
                json={"device": "Scout01", "event_type": "file_metadata",
                      "payload": {"name": "docs/evil.exe"}},
                headers={"X-HexBee-Ingest-Key": "testkey"})
    hits = client.get("/api/v1/iocs/hits", headers=viewer).get_json()["hits"]
    assert len(hits) == 1 and hits[0]["incident_id"] is not None

    assert client.delete(f"/api/v1/iocs/{ioc_id}", headers=invest).status_code == 200
    assert client.get("/api/v1/iocs", headers=viewer).get_json()["iocs"] == []
