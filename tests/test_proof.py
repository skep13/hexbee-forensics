"""The integrity-proof page: it must demonstrate tampering without enabling it.

The security property under test is that nothing here writes. A forensics
product that ships an evidence editor — even a well-intentioned one — is worse
than one that ships no demonstration at all.
"""

import pytest

from hexbee_hive.api import create_app
from hexbee_hive.auth import create_user
from hexbee_hive.config import HiveConfig
from hexbee_hive.integrity import verify_chain
from hexbee_hive.proof import chain_status, explain, tamper_preview


@pytest.fixture
def app(db, tmp_path):
    cfg = HiveConfig(data_dir=tmp_path, ingest_key="testkey")
    create_user(db, "watcher", "watcher-strong-pass1", "viewer")
    application = create_app(cfg, db)
    application.testing = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def ingest(client, event_type="usb_inserted", payload=None):
    resp = client.post("/api/v1/ingest",
                       json={"device": "Scout01", "event_type": event_type,
                             "occurred_at": "2026-07-18T10:00:00Z",
                             "payload": payload or {"a": 1}},
                       headers={"X-HexBee-Ingest-Key": "testkey"})
    assert resp.status_code == 200
    return resp.get_json()["results"][0]["event_id"]


def login(client):
    resp = client.post("/api/v1/login", json={"username": "watcher",
                                              "password": "watcher-strong-pass1"})
    return {"Authorization": f"Bearer {resp.get_json()['token']}"}


def test_status_reports_a_verified_chain(client, db):
    for _ in range(3):
        ingest(client)
    status = chain_status(db)
    assert status["ok"] is True
    assert status["checked"] == 3
    assert status["total_events"] == 3


def test_explain_recomputes_the_stored_hash(client, db):
    event_id = ingest(client)
    detail = explain(db, event_id)
    assert detail["matches"] is True
    assert detail["recomputed_hash"] == detail["stored_hash"]
    assert detail["inputs"]["device"] == "Scout01"


def test_tampering_changes_the_hash_and_names_the_damage(client, db):
    first = ingest(client)
    for _ in range(4):
        ingest(client)

    preview = tamper_preview(db, first, "event_type", "something_else")
    assert preview["changed"] is True
    assert preview["hash_before"] != preview["hash_after"]
    # The four later records all chain through the altered one.
    assert preview["downstream_broken"] == 4
    assert preview["total_invalidated"] == 5


def test_an_unchanged_value_is_reported_as_no_change(client, db):
    event_id = ingest(client, event_type="usb_inserted")
    preview = tamper_preview(db, event_id, "event_type", "usb_inserted")
    assert preview["changed"] is False


def test_the_preview_never_writes_anything(client, db):
    event_id = ingest(client)
    ingest(client)
    before = verify_chain(db)

    for field, value in (("event_type", "x"), ("device", "Evil01"),
                         ("occurred_at", "1999-01-01T00:00:00Z"),
                         ("payload", '{"a": 999}')):
        tamper_preview(db, event_id, field, value)

    after = verify_chain(db)
    assert after["ok"] is True, "the preview must not have altered the chain"
    assert after["checked"] == before["checked"]
    assert explain(db, event_id)["matches"] is True


def test_unknown_event_or_field_is_rejected(client, db):
    event_id = ingest(client)
    assert tamper_preview(db, 9999, "event_type", "x") is None
    assert tamper_preview(db, event_id, "event_hash", "x") is None, \
        "only the hashed input fields may be previewed"


def test_endpoints_require_auth_and_the_page_renders(client):
    ingest(client)
    for path in ("/api/v1/proof/status", "/api/v1/proof/explain/1"):
        assert client.get(path).status_code == 401, path
    assert client.post("/api/v1/proof/tamper-preview", json={}).status_code == 401

    headers = login(client)
    assert client.get("/api/v1/proof/status", headers=headers).status_code == 200
    assert client.get("/api/v1/proof/explain/1", headers=headers).status_code == 200
    bad = client.post("/api/v1/proof/tamper-preview",
                      json={"event_id": 9999, "field": "device", "value": "x"},
                      headers=headers)
    assert bad.status_code == 400

    client.post("/login", data={"username": "watcher",
                                "password": "watcher-strong-pass1"})
    page = client.get("/proof")
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    assert 'id="pf-result"' in body and "/api/v1/proof/status" in body
