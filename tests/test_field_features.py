"""Offline maps, reference library, Hive Mind AI, field upload, QR labels."""

import io
import sqlite3

import pytest

from hexbee_hive.ai import LocalAI, rule_based_case_summary, summarize_case
from hexbee_hive.api import create_app
from hexbee_hive.auth import create_user
from hexbee_hive.cases import assign_incident, create_case
from hexbee_hive.config import HiveConfig
from hexbee_hive.correlate import Correlator
from hexbee_hive.ingest import process_raw_event
from hexbee_hive.maps import PLACEHOLDER_TILE, TileStore, evidence_points
from hexbee_hive.reference import ReferenceLibrary, render_markdown_basic


@pytest.fixture
def app(db, tmp_path):
    cfg = HiveConfig(data_dir=tmp_path, ingest_key="testkey",
                     ai_url="http://127.0.0.1:1")  # unreachable on purpose
    cfg.ensure_dirs()
    create_user(db, "invest", "invest-strong-pass1", "investigator")
    application = create_app(cfg, db)
    application.testing = True
    application.config["cfg"] = cfg
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def login(client):
    resp = client.post("/api/v1/login",
                       json={"username": "invest", "password": "invest-strong-pass1"})
    return {"Authorization": f"Bearer {resp.get_json()['token']}"}


def cookie_login(client):
    client.post("/login", data={"username": "invest", "password": "invest-strong-pass1"})


def csrf_from(client, path):
    """Extract the CSRF token rendered into a form on `path`."""
    import re
    html = client.get(path).get_data(as_text=True)
    m = re.search(r'name="_csrf" value="([^"]+)"', html)
    return m.group(1) if m else ""


def ingest(client, event_type, payload=None):
    return client.post("/api/v1/ingest",
                       json={"device": "Scout01", "event_type": event_type,
                             "payload": payload or {}},
                       headers={"X-HexBee-Ingest-Key": "testkey"})


# -- maps -----------------------------------------------------------------

def test_placeholder_tile_is_valid_png():
    assert PLACEHOLDER_TILE.startswith(b"\x89PNG\r\n\x1a\n")
    assert b"IEND" in PLACEHOLDER_TILE


def _make_mbtiles(path, z, x, y, blob=b"real-tile-bytes"):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE metadata (name TEXT, value TEXT)")
    conn.execute("INSERT INTO metadata VALUES ('format', 'png')")
    conn.execute("""CREATE TABLE tiles (zoom_level INTEGER, tile_column INTEGER,
                    tile_row INTEGER, tile_data BLOB)""")
    tms_y = (2 ** z) - 1 - y
    conn.execute("INSERT INTO tiles VALUES (?, ?, ?, ?)", (z, x, tms_y, blob))
    conn.commit()
    conn.close()


def test_tilestore_serves_mbtiles_with_y_flip(tmp_path):
    maps_dir = tmp_path / "maps"
    maps_dir.mkdir()
    _make_mbtiles(maps_dir / "field.mbtiles", z=3, x=2, y=1)
    store = TileStore(maps_dir)
    assert store.tile(3, 2, 1) == b"real-tile-bytes"
    assert store.tile(3, 0, 0) is None
    assert store.source_name == "field.mbtiles"


def test_map_points_from_gps_events(db, client):
    ingest(client, "artifact_image_gps",
           {"name": "scene.jpg", "lat": 51.5, "lon": -0.1275})
    ingest(client, "heartbeat")  # no coords â€” excluded
    ingest(client, "artifact_image_gps", {"name": "bad.jpg", "lat": 999, "lon": 0})
    points = evidence_points(db)
    assert len(points) == 1
    assert points[0]["lat"] == 51.5 and "scene.jpg" in points[0]["label"]

    headers = login(client)
    resp = client.get("/api/v1/map/points", headers=headers)
    assert resp.status_code == 200
    assert len(resp.get_json()["points"]) == 1

    tile = client.get("/tiles/2/1/1", headers=headers)
    assert tile.status_code == 200
    assert tile.data.startswith(b"\x89PNG")  # placeholder fallback


# -- reference ------------------------------------------------------------

def test_reference_catalog_and_docs(tmp_path):
    lib = ReferenceLibrary(tmp_path / "reference")
    (tmp_path / "reference" / "sop.md").write_text("# Seizure SOP\n- bag it\n- tag it")
    (tmp_path / "reference" / "notes.html").write_text("<p>hi</p>")
    (tmp_path / "reference" / "fake.zim").write_bytes(b"not really a zim")

    catalog = lib.catalog()
    assert catalog["documents"] == ["notes.html", "sop.md"]
    assert catalog["zims"] == ["fake.zim"]

    content, mime = lib.document("sop.md")
    assert b"Seizure" in content and mime.startswith("text/plain")
    assert lib.document("../secret") is None
    assert lib.document("absent.md") is None


def test_markdown_renderer_escapes():
    html = render_markdown_basic("# Title\n<script>alert(1)</script>\n- item")
    assert "<h1>Title</h1>" in html
    assert "<script>" not in html
    assert "<li>item</li>" in html


def test_reference_page_and_doc_route(client, app):
    cookie_login(client)
    cfg = app.config["cfg"]
    (cfg.reference_dir / "sop.md").write_text("# Field SOP\ncontent here")
    page = client.get("/reference")
    assert page.status_code == 200 and b"sop.md" in page.data
    doc = client.get("/reference/doc/sop.md")
    assert doc.status_code == 200 and b"Field SOP" in doc.data
    assert client.get("/reference/doc/..%2Fhive.db").status_code == 404


# -- Hive Mind AI ---------------------------------------------------------

def test_ai_unavailable_and_rule_based_summary(db, client):
    engine = LocalAI("http://127.0.0.1:1", "test-model")
    assert engine.available() is False

    ingest(client, "usb_inserted", {"volume_label": "K32"})
    ingest(client, "executable_found", {"name": "evil.exe"})
    case = create_case(db, "Rule-based test", "", "tester")
    incident = db.query_one("SELECT id FROM incidents")["id"]
    assign_incident(db, incident, case["id"], "tester")

    summary = rule_based_case_summary(db, case["id"])
    assert "Rule-based test" in summary and "Scout01" in summary

    result = summarize_case(db, engine, case["id"])
    assert result["engine"] == "rule-based"
    assert "rule-based" in result["summary"]


def test_ai_uses_local_model_when_available(db, monkeypatch):
    engine = LocalAI("http://fake", "test-model")
    monkeypatch.setattr(engine, "available", lambda: True)
    monkeypatch.setattr(engine, "generate", lambda prompt: "Model says: contained.")
    case = create_case(db, "Model test", "", "tester")
    result = summarize_case(db, engine, case["id"])
    assert result == {"summary": "Model says: contained.", "engine": "test-model"}


def test_ai_endpoints(client):
    headers = login(client)
    status = client.get("/api/v1/ai/status", headers=headers).get_json()
    assert status["available"] is False

    resp = client.post("/api/v1/ai/ask", json={"question": "what happened?"},
                       headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["engine"] == "rule-based"
    assert client.post("/api/v1/ai/ask", json={}, headers=headers).status_code == 400
    assert client.post("/api/v1/ai/summarize/999", headers=headers).status_code == 404


# -- field upload + QR ----------------------------------------------------

def test_field_photo_upload_chains_event(db, client, app):
    cookie_login(client)
    token = csrf_from(client, "/field")
    # Without the CSRF token, the upload is rejected.
    blocked = client.post(
        "/field/upload",
        data={"photo": (io.BytesIO(b"\xff\xd8\xffx"), "x.jpeg")},
        content_type="multipart/form-data",
    )
    assert blocked.status_code == 403

    resp = client.post(
        "/field/upload",
        data={"photo": (io.BytesIO(b"\xff\xd8\xffjpegdata"), "IMG_0001.jpeg"),
              "note": "rear door, forced", "_csrf": token},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    assert b"Evidence photo preserved" in resp.data

    row = db.query_one(
        "SELECT e.payload FROM events e JOIN devices d ON d.id = e.device_id "
        "WHERE d.name = 'iPhone-Field'")
    assert row is not None and "rear door" in row["payload"]
    stored = list(app.config["cfg"].evidence_dir.iterdir())
    assert len(stored) == 1 and stored[0].read_bytes().startswith(b"\xff\xd8\xff")

    from hexbee_hive.integrity import verify_chain
    assert verify_chain(db)["ok"]


def test_case_qr_and_label(db, client):
    cookie_login(client)
    case = create_case(db, "QR test", "", "tester")
    qr = client.get(f"/cases/{case['id']}/qr.svg")
    assert qr.status_code == 200
    assert b"<svg" in qr.data
    label = client.get(f"/cases/{case['id']}/label")
    assert label.status_code == 200 and case["case_number"].encode() in label.data
    assert client.get("/cases/999/qr.svg").status_code == 404
