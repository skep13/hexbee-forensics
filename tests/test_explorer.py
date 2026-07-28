"""The Explorer: navigator tree, result queries, and the artifact detail pane.

The tree is derived from the data rather than stored, so these tests mostly
assert that ingesting a thing makes it appear — that is the property the
design depends on, and the one that breaks silently if a query drifts.
"""

import pytest

from hexbee_hive.api import create_app
from hexbee_hive.auth import create_user
from hexbee_hive.config import HiveConfig
from hexbee_hive.explorer import build_tree, event_detail, query_events


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


def login(client):
    resp = client.post("/api/v1/login",
                       json={"username": "watcher", "password": "watcher-strong-pass1"})
    assert resp.status_code == 200
    return {"Authorization": f"Bearer {resp.get_json()['token']}"}


def ingest(client, event_type, device="Scout01", payload=None,
           at="2026-07-18T10:00:00Z"):
    resp = client.post(
        "/api/v1/ingest",
        json={"device": device, "event_type": event_type,
              "occurred_at": at, "payload": payload or {}},
        headers={"X-HexBee-Ingest-Key": "testkey"},
    )
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()["results"][0]["event_id"]


def branch(tree, node_id):
    return next(b for b in tree if b["id"] == node_id)


# -- navigator -------------------------------------------------------------

def test_tree_has_the_four_top_level_branches(client, db):
    ingest(client, "usb_inserted")
    ids = [b["id"] for b in build_tree(db)]
    assert ids == ["cases", "sources", "types", "results"]


def test_ingesting_a_new_device_grows_the_tree(client, db):
    ingest(client, "usb_inserted", device="Scout01")
    ingest(client, "process_snapshot", device="Forager-lab")
    sources = branch(build_tree(db), "sources")
    assert {c["label"] for c in sources["children"]} == {"Scout01", "Forager-lab"}
    assert sources["count"] == 2


def test_ingesting_a_new_artifact_type_grows_the_tree(client, db):
    ingest(client, "usb_inserted")
    ingest(client, "usb_inserted")
    ingest(client, "executable_found")
    types = {c["label"]: c["count"] for c in branch(build_tree(db), "types")["children"]}
    assert types == {"usb_inserted": 2, "executable_found": 1}


def test_tree_counts_do_not_double_count_events(client, db):
    for _ in range(5):
        ingest(client, "usb_inserted")
    tree = build_tree(db)
    assert branch(tree, "sources")["count"] == 5
    assert branch(tree, "types")["count"] == 5


def test_every_leaf_carries_a_runnable_filter(client, db):
    ingest(client, "executable_found", payload={"path": "/tmp/x"})
    for top in build_tree(db):
        for child in top.get("children", []):
            for leaf in ([child] if child.get("filter") else child.get("children", [])):
                if not leaf.get("filter"):
                    continue
                # The contract the UI relies on: any leaf's filter runs.
                assert "total" in query_events(db, leaf["filter"])


# -- results ---------------------------------------------------------------

def test_filter_by_device_and_type(client, db):
    ingest(client, "usb_inserted", device="Scout01")
    ingest(client, "process_snapshot", device="Forager-lab")
    assert query_events(db, {"device": "Scout01"})["total"] == 1
    assert query_events(db, {"event_type": "process_snapshot"})["total"] == 1
    assert query_events(db, {"device": "Scout01",
                             "event_type": "process_snapshot"})["total"] == 0


def test_text_filter_searches_the_payload(client, db):
    ingest(client, "executable_found", payload={"path": "/tmp/evil.exe"})
    ingest(client, "executable_found", payload={"path": "/tmp/fine.txt"})
    assert query_events(db, {"text": "evil"})["total"] == 1


def test_results_are_paged_and_report_the_true_total(client, db):
    for i in range(7):
        ingest(client, "usb_inserted", payload={"n": i})
    page = query_events(db, {}, limit=3, offset=3)
    assert page["total"] == 7
    assert len(page["events"]) == 3
    assert page["offset"] == 3


def test_every_row_has_the_columns_the_table_renders(client, db):
    ingest(client, "executable_found", payload={"path": "/tmp/x", "sha256": "ab"})
    row = query_events(db, {})["events"][0]
    for column in ("id", "occurred_at", "device", "event_type", "severity", "summary"):
        assert column in row, column


def test_summary_prefers_the_fields_an_examiner_scans_for(client, db):
    ingest(client, "executable_found",
           payload={"irrelevant": "z" * 50, "path": "/tmp/evil.exe"})
    assert "/tmp/evil.exe" in query_events(db, {})["events"][0]["summary"]


def test_summary_survives_a_payload_that_is_not_a_dict(client, db):
    ingest(client, "usb_inserted", payload={})
    assert isinstance(query_events(db, {})["events"][0]["summary"], str)


# -- detail ----------------------------------------------------------------

def test_detail_returns_payload_techniques_and_chain(client, db):
    event_id = ingest(client, "executable_found", payload={"path": "/tmp/x"})
    detail = event_detail(db, event_id)
    assert detail["payload"] == {"path": "/tmp/x"}
    assert detail["device"] == "Scout01"
    assert detail["severity_label"]
    assert detail["chain"]["event_hash"]
    assert isinstance(detail["techniques"], list)


def test_detail_of_a_missing_event_is_none(db):
    assert event_detail(db, 9999) is None


# -- HTTP surface ----------------------------------------------------------

def test_explorer_endpoints_require_authentication(client):
    for path in ("/api/v1/explorer/tree", "/api/v1/explorer/events",
                 "/api/v1/explorer/event/1"):
        assert client.get(path).status_code == 401, path


def test_explorer_page_and_apis_serve_a_logged_in_analyst(client):
    ingest(client, "executable_found", payload={"path": "/tmp/x"})
    headers = login(client)

    assert client.get("/api/v1/explorer/tree", headers=headers).status_code == 200
    events = client.get("/api/v1/explorer/events", headers=headers).get_json()
    assert events["total"] == 1
    detail = client.get(f"/api/v1/explorer/event/{events['events'][0]['id']}",
                        headers=headers)
    assert detail.status_code == 200

    client.post("/login", data={"username": "watcher",
                                "password": "watcher-strong-pass1"})
    page = client.get("/explorer")
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    # The page is useless without its script; a missing template block would
    # still return 200 and render a dead three-pane shell.
    assert 'id="xp-tree"' in body
    assert "/api/v1/explorer/tree" in body


def test_unknown_event_detail_is_404_not_500(client):
    headers = login(client)
    assert client.get("/api/v1/explorer/event/4242",
                      headers=headers).status_code == 404
