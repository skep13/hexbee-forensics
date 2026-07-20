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


def test_comb_webui_all_operations(tmp_path):
    """The Comb UI exposes scan / partitions / carve / files as buttons."""
    import struct
    import threading
    import time
    import urllib.parse
    import urllib.request
    from http.server import ThreadingHTTPServer

    from hexbee_comb.webui import _NAV, _Handler

    assert [t for _, t in _NAV] == ["Scan", "Partitions", "Carve", "Files"]

    # a raw image: MBR (one FAT32 partition) + an embedded JPEG to carve
    s0 = bytearray(512)
    e = bytearray(16); e[0] = 0x80; e[4] = 0x0B
    e[8:12] = struct.pack("<I", 2048); e[12:16] = struct.pack("<I", 100000)
    s0[446:462] = e; s0[510:512] = b"\x55\xaa"
    jpeg = b"\xff\xd8\xff\xe0" + b"\x00" * 48 + b"\xff\xd9"
    img = tmp_path / "disk.dd"
    img.write_bytes(bytes(s0) + b"\x00" * 400 + jpeg + b"\x00" * 100)
    out = tmp_path / "carved"

    srv = ThreadingHTTPServer(("127.0.0.1", 8094), _Handler)
    srv.defaults = {}; srv.last_report = None; srv.last_summary = ""
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    base = "http://127.0.0.1:8094"

    def post(path, data):
        try:
            return urllib.request.build_opener().open(urllib.request.Request(
                base + path, data=urllib.parse.urlencode(data).encode())).read().decode()
        except urllib.error.HTTPError as exc:      # 400 pages carry a body
            return exc.read().decode()
    try:
        # forms render
        for p, marker in [("/", "Scan a directory"), ("/partitions", "Partition table"),
                          ("/carve", "Carve files"), ("/files", "Filesystem listing")]:
            assert marker in urllib.request.urlopen(base + p).read().decode()
        # partitions parses the MBR
        assert "FAT32" in post("/partitions", {"image": str(img)})
        # carve recovers the JPEG
        carved = post("/carve", {"image": str(img), "out_dir": str(out)})
        assert "jpeg" in carved
        assert list(out.iterdir())  # a file was written
        # bad path is handled, not a crash
        assert "Error" in post("/partitions", {"image": str(tmp_path / "nope.dd")})
    finally:
        srv.shutdown()
