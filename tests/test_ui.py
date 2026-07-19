"""Point-and-click UI: Hive Admin page + Comb web UI."""

import re
import sys
from pathlib import Path

import pytest

from hexbee_hive.api import create_app
from hexbee_hive.auth import create_user
from hexbee_hive.config import HiveConfig

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "comb"))


@pytest.fixture
def app(db, tmp_path):
    cfg = HiveConfig(data_dir=tmp_path, ingest_key="testkey")
    cfg.ensure_dirs()
    create_user(db, "admin", "admin-strong-pass1", "administrator")
    create_user(db, "watcher", "watcher-strong-pass1", "viewer")
    application = create_app(cfg, db)
    application.testing = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def cookie_login(client, user="admin", pw="admin-strong-pass1"):
    client.post("/login", data={"username": user, "password": pw})


def csrf(client, path):
    html = client.get(path).get_data(as_text=True)
    m = re.search(r'name="_csrf" value="([^"]+)"', html)
    return m.group(1) if m else ""


# -- Hive Admin page ------------------------------------------------------

def test_admin_page_admin_only(client):
    cookie_login(client, "watcher", "watcher-strong-pass1")
    assert client.get("/admin").status_code == 403      # viewer blocked
    client.get("/logout")
    cookie_login(client)
    page = client.get("/admin")
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    assert "Security posture" in body and "Add a user" in body


def test_admin_create_and_disable_user(client, db):
    cookie_login(client)
    token = csrf(client, "/admin")
    # create via the UI form
    client.post("/admin/users/new", data={
        "_csrf": token, "username": "newanalyst",
        "password": "a-strong-passphrase", "role": "investigator"})
    row = db.query_one("SELECT role, disabled FROM users WHERE username='newanalyst'")
    assert row is not None and row["role"] == "investigator" and row["disabled"] == 0

    # disable via the UI form
    client.post("/admin/users/toggle", data={
        "_csrf": token, "username": "newanalyst", "action": "disable"})
    assert db.query_one("SELECT disabled FROM users WHERE username='newanalyst'")["disabled"] == 1


def test_admin_cannot_disable_self(client, db):
    cookie_login(client)
    token = csrf(client, "/admin")
    client.post("/admin/users/toggle", data={
        "_csrf": token, "username": "admin", "action": "disable"})
    assert db.query_one("SELECT disabled FROM users WHERE username='admin'")["disabled"] == 0


def test_admin_anchor_download(client):
    cookie_login(client)
    resp = client.get("/admin/anchor")
    assert resp.status_code == 200
    assert "attachment" in resp.headers.get("Content-Disposition", "")
    import json
    assert "signature" in json.loads(resp.get_data(as_text=True))


def test_admin_form_needs_csrf(client):
    cookie_login(client)
    # no _csrf -> blocked
    resp = client.post("/admin/users/new", data={
        "username": "x", "password": "a-strong-passphrase", "role": "viewer"})
    assert resp.status_code == 403


# -- Comb web UI ----------------------------------------------------------

def test_comb_webui_scan(tmp_path):
    from hexbee_comb.webui import _Handler  # noqa: F401  (import sanity)
    from hexbee_comb.analysis import render_report, scan

    # build a tiny target dir with a masquerading exe
    target = tmp_path / "evi"
    target.mkdir()
    (target / "note.txt").write_bytes(b"hello")
    (target / "photo.jpg").write_bytes(b"MZ" + b"\x00" * 64)  # exe posing as jpg

    result = scan(target)
    report = render_report(result)
    assert len(result.files) == 2
    assert len(result.mismatches) == 1
    assert "HexBee Comb" in report and "photo.jpg" in report
