"""API surface added by the recommendations build: scope, ATT&CK, case mode,
engagement data, log forwarding, live stream, map clustering, triage."""

import re

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


@pytest.fixture
def admin(client):
    return login(client, "admin", "admin-strong-pass1")


@pytest.fixture
def investigator(client):
    return login(client, "invest", "invest-strong-pass1")


@pytest.fixture
def viewer(client):
    return login(client, "watcher", "watcher-strong-pass1")


def ingest(client, event_type, payload=None, device="Scout01"):
    return client.post("/api/v1/ingest",
                       json={"device": device, "event_type": event_type,
                             "occurred_at": "2026-07-25T10:00:00Z",
                             "payload": payload or {}},
                       headers={"X-HexBee-Ingest-Key": "testkey"})


# -- scope -----------------------------------------------------------------

def test_scope_crud_and_check(client, investigator):
    resp = client.post("/api/v1/scope",
                       json={"kind": "cidr", "value": "10.10.0.0/24",
                             "auth_ref": "SOW-1"}, headers=investigator)
    assert resp.status_code == 201
    rule_id = resp.get_json()["rule_id"]

    listing = client.get("/api/v1/scope", headers=investigator).get_json()
    assert listing["summary"]["active"] == 1
    assert listing["mode"] == "enforce"

    inside = client.get("/api/v1/scope/check?target=10.10.0.9",
                        headers=investigator).get_json()
    assert inside["allowed"] and inside["auth_ref"] == "SOW-1"
    outside = client.get("/api/v1/scope/check?target=8.8.8.8",
                         headers=investigator).get_json()
    assert not outside["allowed"]

    assert client.delete(f"/api/v1/scope/{rule_id}",
                         headers=investigator).status_code == 200


def test_scope_rejects_bad_input_and_duplicates(client, investigator):
    bad = client.post("/api/v1/scope", json={"kind": "cidr", "value": "nope"},
                      headers=investigator)
    assert bad.status_code == 400
    client.post("/api/v1/scope", json={"kind": "cidr", "value": "10.0.0.0/8"},
                headers=investigator)
    dup = client.post("/api/v1/scope", json={"kind": "cidr", "value": "10.0.0.0/8"},
                      headers=investigator)
    assert dup.status_code == 409


def test_scope_check_requires_a_target(client, viewer):
    assert client.get("/api/v1/scope/check", headers=viewer).status_code == 400


def test_viewer_cannot_add_scope(client, viewer):
    resp = client.post("/api/v1/scope", json={"kind": "cidr", "value": "10.0.0.0/8"},
                       headers=viewer)
    assert resp.status_code == 403


def test_scope_violation_lands_in_the_chain(client, investigator):
    resp = client.post("/api/v1/scope/violation",
                       json={"target": "8.8.8.8", "tool": "hexbee-recon",
                             "reason": "out of scope"}, headers=investigator)
    assert resp.status_code == 201
    event_id = resp.get_json()["event_id"]
    event = client.get(f"/api/v1/events/{event_id}", headers=investigator).get_json()
    assert event["event_type"] == "scope_violation"
    assert event["payload"]["blocked"] is True


# -- ATT&CK ----------------------------------------------------------------

def test_attack_coverage_endpoints(client, viewer):
    ingest(client, "autorun_found", {"name": "evil.lnk"})
    coverage = client.get("/api/v1/attack/coverage", headers=viewer).get_json()
    assert coverage["distinct_techniques"] >= 1
    assert len(coverage["tactics"]) == 14


def test_event_techniques_endpoint(client, viewer):
    event_id = ingest(client, "powershell_launched").get_json()["results"][0]["event_id"]
    techniques = client.get(f"/api/v1/events/{event_id}/techniques",
                            headers=viewer).get_json()["techniques"]
    assert techniques[0]["id"] == "T1059.001"
    assert techniques[0]["tactic"] == "execution"


def test_case_coverage_404s_for_missing_case(client, viewer):
    assert client.get("/api/v1/attack/coverage/999", headers=viewer).status_code == 404


# -- case mode -------------------------------------------------------------

def test_case_mode_round_trip(client, investigator):
    case = client.post("/api/v1/cases", json={"title": "Engagement"},
                       headers=investigator).get_json()
    assert case["mode"] == "ir"
    assert client.post(f"/api/v1/cases/{case['id']}/mode",
                       json={"mode": "pentest"},
                       headers=investigator).status_code == 200
    refreshed = client.get(f"/api/v1/cases/{case['id']}", headers=investigator).get_json()
    assert refreshed["mode"] == "pentest"


def test_invalid_mode_rejected(client, investigator):
    case = client.post("/api/v1/cases", json={"title": "X"},
                       headers=investigator).get_json()
    resp = client.post(f"/api/v1/cases/{case['id']}/mode", json={"mode": "nope"},
                       headers=investigator)
    assert resp.status_code == 400


# -- engagement data -------------------------------------------------------

def test_engagement_data_groups_findings(client, investigator):
    case = client.post("/api/v1/cases", json={"title": "Engagement"},
                       headers=investigator).get_json()
    result = ingest(client, "autorun_found", {"name": "a.lnk"}).get_json()["results"][0]
    client.post(f"/api/v1/incidents/{result['incident_id']}/assign",
                json={"case_id": case["id"]}, headers=investigator)
    ingest(client, "yara_match", {"rule": "Trojan", "name": "b.exe"})

    data = client.get(f"/api/v1/cases/{case['id']}/engagement",
                      headers=investigator).get_json()
    assert data["case"]["id"] == case["id"]
    assert data["stats"]["events"] >= 1
    assert data["groups"]
    assert data["groups"][0]["severity_label"] in ("High", "Medium", "Low",
                                                   "Informational")
    assert "summary" in data and data["case"]["case_number"] in data["summary"]
    assert data["verify"]["ok"] is True


def test_engagement_404(client, viewer):
    assert client.get("/api/v1/cases/999/engagement", headers=viewer).status_code == 404


# -- log forwarding --------------------------------------------------------

def test_log_endpoint_stores_only_findings(client, viewer):
    noise = [{"Hostname": "DC01", "Channel": "System", "EventID": 1,
              "Message": "nothing"} for _ in range(5)]
    finding = {"Hostname": "DC01", "Channel": "Security", "EventID": 4720,
               "Message": "A user account was created"}
    resp = client.post("/api/v1/logs", json=noise + [finding],
                       headers={"X-HexBee-Ingest-Key": "testkey"})
    body = resp.get_json()
    assert body["received"] == 6 and body["anomalies"] == 1
    assert body["findings"][0]["rule"] == "account_created"


def test_log_endpoint_rejects_bad_key(client):
    resp = client.post("/api/v1/logs", json=[{"Message": "x"}],
                       headers={"X-HexBee-Ingest-Key": "wrong"})
    assert resp.status_code == 401


def test_log_endpoint_caps_batch_size(client):
    huge = [{"Message": "x"}] * 2001
    resp = client.post("/api/v1/logs", json=huge,
                       headers={"X-HexBee-Ingest-Key": "testkey"})
    assert resp.status_code == 413


# -- live stream -----------------------------------------------------------

def test_stream_requires_auth(client):
    assert client.get("/api/v1/stream").status_code == 401


def test_stream_emits_sse_headers_and_a_hello(client, viewer):
    resp = client.get("/api/v1/stream?since=0", headers=viewer)
    assert resp.headers["Content-Type"].startswith("text/event-stream")
    assert resp.headers["Cache-Control"] == "no-cache"
    first = next(resp.response)
    assert b"event: hello" in first
    resp.close()


# -- map clustering --------------------------------------------------------

def test_map_points_cluster_on_request(client, investigator):
    for i in range(6):
        ingest(client, "wireless_sighting",
               {"lat": 51.5 + i * 0.00001, "lon": -0.12, "name": f"dev{i}"})
    plain = client.get("/api/v1/map/points", headers=investigator).get_json()
    assert plain["clustered"] is False and plain["total"] == 6

    clustered = client.get("/api/v1/map/points?zoom=3",
                           headers=investigator).get_json()
    assert clustered["clustered"] is True
    assert len(clustered["points"]) < 6
    grouped = next(p for p in clustered["points"] if p["cluster"])
    assert grouped["count"] > 1 and grouped["sample"]

    # Zoomed right in, the same points separate again.
    split = client.get("/api/v1/map/points?zoom=19",
                       headers=investigator).get_json()
    assert len(split["points"]) >= len(clustered["points"])


# -- triage ----------------------------------------------------------------

def test_triage_returns_an_assessment(client, investigator):
    result = ingest(client, "autorun_found", {"name": "evil.lnk"}).get_json()["results"][0]
    resp = client.post(f"/api/v1/incidents/{result['incident_id']}/triage",
                       headers=investigator)
    body = resp.get_json()
    assert resp.status_code == 200
    # No Ollama in CI: the rule-based fallback must still answer.
    assert body["assessment"]
    assert body["incident_id"] == result["incident_id"]


def test_triage_404(client, investigator):
    assert client.post("/api/v1/incidents/999/triage",
                       headers=investigator).status_code == 404


# -- intel -----------------------------------------------------------------

def test_intel_status_reports_absence_cleanly(client, viewer):
    body = client.get("/api/v1/intel/status", headers=viewer).get_json()
    assert body["available"] is False and body["indicators"] == 0


# -- dashboard pages render -------------------------------------------------

@pytest.mark.parametrize("path", ["/", "/attack", "/admin", "/map", "/cases"])
def test_pages_render_for_admin(client, path):
    client.post("/login", data={"username": "admin",
                                "password": "admin-strong-pass1"})
    resp = client.get(path)
    assert resp.status_code == 200, path
    assert b"HEX" in resp.data


def csrf(client, path):
    html = client.get(path).get_data(as_text=True)
    match = re.search(r'name="_csrf" value="([^"]+)"', html)
    return match.group(1) if match else ""


def test_case_preview_page_renders(client):
    client.post("/login", data={"username": "invest",
                                "password": "invest-strong-pass1"})
    resp = client.post("/cases/new",
                       data={"title": "Engagement", "_csrf": csrf(client, "/cases")},
                       follow_redirects=True)
    assert resp.status_code == 200
    preview = client.get("/cases/1/preview")
    assert preview.status_code == 200
    assert b"Report preview" in preview.data
    assert b"Executive summary" in preview.data


def test_preview_404_for_missing_case(client):
    client.post("/login", data={"username": "invest",
                                "password": "invest-strong-pass1"})
    assert client.get("/cases/999/preview").status_code == 404
