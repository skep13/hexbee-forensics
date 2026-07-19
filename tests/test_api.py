"""Flask API integration tests: auth, RBAC, ingest, full investigation flow."""

import pytest

from hexbee_hive.api import create_app
from hexbee_hive.auth import create_user
from hexbee_hive.config import HiveConfig


@pytest.fixture
def app(db, tmp_path):
    cfg = HiveConfig(data_dir=tmp_path, ingest_key="testkey")
    create_user(db, "admin", "admin-strong-pass1", "administrator")
    create_user(db, "invest", "invest-strong-pass1", "investigator")
    create_user(db, "watcher", "watcher-strong-pass1", "viewer")
    application = create_app(cfg, db)
    application.testing = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def login(client, username, password):
    resp = client.post("/api/v1/login", json={"username": username, "password": password})
    assert resp.status_code == 200
    return {"Authorization": f"Bearer {resp.get_json()['token']}"}


def ingest(client, event_type, device="Scout01", payload=None, at="2026-07-18T10:00:00Z"):
    return client.post(
        "/api/v1/ingest",
        json={"device": device, "event_type": event_type,
              "occurred_at": at, "payload": payload or {}},
        headers={"X-HexBee-Ingest-Key": "testkey"},
    )


def test_health_is_public(client):
    assert client.get("/api/v1/health").status_code == 200


def test_auth_required_and_bad_login(client):
    assert client.get("/api/v1/stats").status_code == 401
    resp = client.post("/api/v1/login", json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_ingest_requires_key(client):
    resp = client.post("/api/v1/ingest", json={"device": "S1", "event_type": "heartbeat"})
    assert resp.status_code == 401
    assert ingest(client, "heartbeat").status_code == 200


def test_ingest_rejects_bad_events(client):
    resp = client.post("/api/v1/ingest", json={"nonsense": True},
                       headers={"X-HexBee-Ingest-Key": "testkey"})
    assert resp.status_code == 400
    assert resp.get_json()["errors"]


def test_rbac_viewer_cannot_write(client):
    viewer = login(client, "watcher", "watcher-strong-pass1")
    resp = client.post("/api/v1/cases", json={"title": "nope"}, headers=viewer)
    assert resp.status_code == 403
    # but can read
    assert client.get("/api/v1/stats", headers=viewer).status_code == 200


def test_audit_admin_only(client):
    invest = login(client, "invest", "invest-strong-pass1")
    admin = login(client, "admin", "admin-strong-pass1")
    assert client.get("/api/v1/audit", headers=invest).status_code == 403
    assert client.get("/api/v1/audit", headers=admin).status_code == 200


def test_full_investigation_flow(client):
    # Scout reports an incident-worthy sequence.
    for i, event_type in enumerate(
        ["scout_online", "usb_inserted", "executable_found", "network_beacon"]
    ):
        resp = ingest(client, event_type, at=f"2026-07-18T10:0{i}:00Z",
                      payload={"name": "evil.exe"} if event_type == "executable_found" else {})
        assert resp.status_code == 200

    invest = login(client, "invest", "invest-strong-pass1")

    # One incident was opened and contains all four events.
    incidents = client.get("/api/v1/incidents", headers=invest).get_json()["incidents"]
    assert len(incidents) == 1
    incident = client.get(f"/api/v1/incidents/{incidents[0]['id']}",
                          headers=invest).get_json()
    assert len(incident["timeline"]) == 4
    assert incident["severity"] == 3

    # Open a case, assign, note, tag, close out.
    case = client.post("/api/v1/cases",
                       json={"title": "USB malware", "description": "front desk"},
                       headers=invest).get_json()
    assert client.post(f"/api/v1/incidents/{incident['id']}/assign",
                       json={"case_id": case["id"]}, headers=invest).status_code == 200
    assert client.post(f"/api/v1/cases/{case['id']}/notes",
                       json={"body": "Contained."}, headers=invest).status_code == 201

    exe = client.get("/api/v1/events", headers=invest,
                     query_string={"text": "evil.exe"}).get_json()["events"]
    assert len(exe) == 1
    assert client.post(f"/api/v1/events/{exe[0]['id']}/tags",
                       json={"tag": "malware"}, headers=invest).status_code == 200

    # Reports in all three formats.
    for fmt, marker in (("json", '"case_number"'), ("html", "evil.exe"), ("csv", "evil.exe")):
        resp = client.get(f"/api/v1/cases/{case['id']}/report",
                          query_string={"format": fmt}, headers=invest)
        assert resp.status_code == 200
        assert marker in resp.get_data(as_text=True)

    # Chain still verifies end-to-end.
    verify = client.get("/api/v1/verify", headers=invest).get_json()
    assert verify["ok"] and verify["checked"] == 4


def test_dashboard_pages_render(client):
    ingest(client, "executable_found")
    resp = client.post("/login", data={"username": "watcher", "password": "watcher-strong-pass1"})
    assert resp.status_code == 302
    cookie_headers = {}
    for page in ("/", "/incidents", "/cases", "/search", "/incidents/1"):
        page_resp = client.get(page, headers=cookie_headers)
        assert page_resp.status_code == 200, page
    # Unauthenticated dashboard hit redirects to login.
    client.get("/logout")
    assert client.get("/").status_code == 302
