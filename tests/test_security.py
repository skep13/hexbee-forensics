"""Security hardening + forensic evidence integrity."""

import pytest

from hexbee_hive.api import create_app
from hexbee_hive.auth import create_user
from hexbee_hive.config import HiveConfig
from hexbee_hive.evidence_export import (
    chain_anchor,
    export_case,
    verify_anchor,
    verify_bundle,
)
from hexbee_hive.security import (
    LoginRateLimiter,
    content_security_policy,
    csrf_token,
    csrf_valid,
)
from hexbee_hive.store import store_event
from hexbee_hive.cases import assign_incident, create_case


@pytest.fixture
def app(db, tmp_path):
    cfg = HiveConfig(data_dir=tmp_path, ingest_key="s3cret-ingest-key-1234",
                     login_max_attempts=3, login_lockout_seconds=300)
    cfg.ensure_dirs()
    create_user(db, "admin", "admin-strong-pass1", "administrator")
    create_user(db, "invest", "invest-strong-pass1", "investigator")
    application = create_app(cfg, db)
    application.testing = True
    application.config["cfg"] = cfg
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def make_event(device="Scout01", event_type="heartbeat", at="2026-07-18T10:00:00Z", payload=None):
    from hexbee_hive.normalize import normalize
    return normalize({"device": device, "event_type": event_type,
                      "occurred_at": at, "payload": payload or {}})


# -- OWASP: security headers + CSP (A05, A03) -----------------------------

def test_security_headers_present(client):
    resp = client.get("/login")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
    assert "object-src 'none'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["Referrer-Policy"] == "no-referrer"


def test_csp_nonce_is_per_response(client):
    a = client.get("/login").headers["Content-Security-Policy"]
    b = client.get("/login").headers["Content-Security-Policy"]
    assert "nonce-" in a and a != b  # fresh nonce each response


def test_hsts_only_with_secure_cookies(db, tmp_path):
    create_user(db, "admin", "admin-strong-pass1", "administrator")
    secure = create_app(HiveConfig(data_dir=tmp_path, secure_cookies=True), db)
    secure.testing = True
    assert "Strict-Transport-Security" in secure.test_client().get("/login").headers


# -- OWASP: CSRF (A01) ----------------------------------------------------

def test_csrf_token_bound_to_session(app):
    key = app.config["cfg"].signing_key
    t1 = csrf_token("session-A", key)
    assert csrf_valid("session-A", t1, key)
    assert not csrf_valid("session-B", t1, key)     # different session
    assert not csrf_valid("session-A", "wrong", key)
    assert not csrf_valid("", t1, key)


def test_form_post_without_csrf_rejected(client):
    client.post("/login", data={"username": "invest", "password": "invest-strong-pass1"})
    # No _csrf field -> blocked.
    resp = client.post("/cases/new", data={"title": "sneaky"})
    assert resp.status_code == 403
    assert b"CSRF" in resp.data


def test_api_is_csrf_exempt(client):
    # Bearer-token API isn't cookie-driven, so no CSRF needed.
    login = client.post("/api/v1/login",
                        json={"username": "invest", "password": "invest-strong-pass1"})
    headers = {"Authorization": f"Bearer {login.get_json()['token']}"}
    assert client.post("/api/v1/cases", json={"title": "ok"}, headers=headers).status_code == 201


# -- OWASP: brute-force lockout (A04/A07) ---------------------------------

def test_login_lockout(client):
    for _ in range(3):
        r = client.post("/api/v1/login",
                        json={"username": "admin", "password": "wrong"})
        assert r.status_code == 401
    # 4th attempt is locked out even though we now supply the RIGHT password.
    locked = client.post("/api/v1/login",
                         json={"username": "admin", "password": "admin-strong-pass1"})
    assert locked.status_code == 429


def test_rate_limiter_unit():
    rl = LoginRateLimiter(max_attempts=2, window_seconds=300)
    assert not rl.locked("u", "ip")
    rl.record_failure("u", "ip")
    rl.record_failure("u", "ip")
    assert rl.locked("u", "ip")
    assert rl.retry_after("u", "ip") > 0
    rl.reset("u", "ip")
    assert not rl.locked("u", "ip")


# -- OWASP: timing-safe ingest key (A02) ----------------------------------

def test_ingest_key_constant_time_compare(client):
    bad = client.post("/api/v1/ingest",
                      json={"device": "S1", "event_type": "heartbeat"},
                      headers={"X-HexBee-Ingest-Key": "wrong"})
    assert bad.status_code == 401
    good = client.post("/api/v1/ingest",
                       json={"device": "S1", "event_type": "heartbeat"},
                       headers={"X-HexBee-Ingest-Key": "s3cret-ingest-key-1234"})
    assert good.status_code == 200


# -- Forensics: chain anchor (A08) ----------------------------------------

def test_chain_anchor_detects_rewind(db, app):
    key = app.config["cfg"].signing_key
    for i in range(5):
        store_event(db, make_event(at=f"2026-07-18T10:00:0{i}Z", payload={"i": i}))
    anchor = chain_anchor(db, key)
    assert verify_anchor(db, anchor, key)["ok"]

    # Rewriting history invalidates the anchored prefix.
    import json
    db.execute("UPDATE events SET payload = ? WHERE id = 3", (json.dumps({"i": 999}),))
    result = verify_anchor(db, anchor, key)
    assert not result["ok"] and "rewritten" in result["reason"]


def test_anchor_signature_tamper(db, app):
    key = app.config["cfg"].signing_key
    store_event(db, make_event())
    anchor = chain_anchor(db, key)
    anchor["event_count"] = 999  # forge a higher count
    assert not verify_anchor(db, anchor, key)["ok"]


# -- Forensics: signed evidence bundle (A08) ------------------------------

def test_signed_bundle_export_and_verify(db, app, tmp_path):
    cfg = app.config["cfg"]
    key = cfg.signing_key

    # A field photo written to the evidence store + a matching chained event.
    import hashlib
    photo = b"\xff\xd8\xff" + b"crime-scene-bytes"
    digest = hashlib.sha256(photo).hexdigest()
    (cfg.evidence_dir / "IMG_9.jpg").write_bytes(photo)
    eid = store_event(db, make_event(
        event_type="field_photo",
        payload={"name": "IMG_9.jpg", "sha256": digest, "size": len(photo)}))
    case = create_case(db, "Bundle case", "", "tester")
    # attach via an incident
    from hexbee_hive.correlate import Correlator
    inc = store_event(db, make_event(event_type="executable_found",
                                     payload={"name": "IMG_9.jpg", "sha256": digest}))
    incident_id = Correlator(db, 600).process_event(inc)
    assign_incident(db, incident_id, case["id"], "tester")

    summary = export_case(db, cfg, case["id"], key, actor="tester")
    assert summary is not None and summary["chain_ok"]

    # A fresh, untampered bundle verifies.
    good = verify_bundle(summary["bundle_dir"], key)
    assert good["ok"], good

    # Tampering with an evidence file is detected.
    from pathlib import Path
    files = list((Path(summary["bundle_dir"]) / "files").iterdir())
    assert files
    files[0].write_bytes(b"swapped")
    assert not verify_bundle(summary["bundle_dir"], key)["ok"]


def test_bundle_wrong_key_fails(db, app):
    cfg = app.config["cfg"]
    case = create_case(db, "Keyless", "", "t")
    summary = export_case(db, cfg, case["id"], cfg.signing_key, "t")
    assert verify_bundle(summary["bundle_dir"], b"the-wrong-key")["ok"] is False


def test_export_missing_case(db, app):
    cfg = app.config["cfg"]
    assert export_case(db, cfg, 9999, cfg.signing_key, "t") is None


# -- CSP string sanity ----------------------------------------------------

def test_csp_requires_nonce_for_scripts():
    csp = content_security_policy("abc123")
    assert "script-src 'self' 'nonce-abc123'" in csp
    assert "'unsafe-inline'" not in csp.split("style-src")[0]  # not on script-src
