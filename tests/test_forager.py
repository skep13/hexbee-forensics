"""Forager autonomous collector: collection, framing, offline spool, deltas,
config discovery, and end-to-end ingest into the Hive."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "forager"))

from hexbee_forager import collectors
from hexbee_forager.agent import Forager, discover_config


# -- collectors run on the local host (read-only) -------------------------

def test_host_info_collector():
    events = collectors.collect_host_info()
    assert len(events) == 1
    p = events[0]["payload"]
    assert p["hostname"] and p["os"] and "current_user" in p
    assert events[0]["event_type"] == "host_info"


def test_processes_collector_finds_self():
    events = collectors.collect_processes()
    assert len(events) >= 1
    assert all(e["event_type"] == "process_snapshot" for e in events)
    # our own python process should be present by name somewhere
    names = " ".join((e["payload"].get("name") or "").lower() for e in events)
    assert "python" in names


def test_recent_files_metadata_only(tmp_path):
    # collector reads real user dirs; just assert shape + no crash
    events = collectors.collect_recent_files(days=3650, cap=5)
    for e in events:
        assert e["event_type"] == "recent_file"
        assert "path" in e["payload"] and "size" in e["payload"]


def test_all_collectors_smoke():
    for name, fn, _volatile in collectors.ALL_COLLECTORS:
        result = fn()
        assert isinstance(result, list)


# -- agent framing + resilience -------------------------------------------

def test_collect_frames_run(tmp_path):
    agent = Forager(hive_url=None, ingest_key=None, spool_dir=tmp_path / "spool",
                    device="Forager-TEST")
    events = agent.collect(volatile_only=False)
    assert events[0]["event_type"] == "collection_started"
    assert events[-1]["event_type"] == "collection_completed"
    assert all(e["device"] == "Forager-TEST" for e in events)
    completed = events[-1]["payload"]
    assert completed["events"] == len(events)
    assert len(completed["manifest_sha256"]) == 64


def test_failing_collector_does_not_abort(tmp_path, monkeypatch):
    def boom():
        raise RuntimeError("collector exploded")
    monkeypatch.setattr(collectors, "ALL_COLLECTORS",
                        [("host_info", collectors.collect_host_info, False),
                         ("boom", boom, True)])
    # agent imports ALL_COLLECTORS by reference at call time
    import hexbee_forager.agent as agent_mod
    monkeypatch.setattr(agent_mod, "ALL_COLLECTORS", collectors.ALL_COLLECTORS)
    agent = Forager(None, None, spool_dir=tmp_path / "s", device="d")
    events = agent.collect()
    assert events[0]["event_type"] == "collection_started"  # survived the boom


def test_offline_spool_and_status(tmp_path):
    agent = Forager(hive_url=None, ingest_key=None, spool_dir=tmp_path / "spool")
    result = agent.ship([{"device": "d", "event_type": "host_info",
                          "occurred_at": "2026-07-19T00:00:00Z", "payload": {}}])
    assert result["shipped"] == 0 and result["spooled"] == 1
    assert list((tmp_path / "spool").glob("*.jsonl"))


def test_watch_delta_detection(tmp_path):
    agent = Forager(None, None, spool_dir=tmp_path / "s", device="d")
    baseline = {"proc:1:init"}
    sample = [
        {"event_type": "process_snapshot", "device": "d",
         "occurred_at": "t", "payload": {"pid": 1, "name": "init"}},      # known
        {"event_type": "process_snapshot", "device": "d",
         "occurred_at": "t", "payload": {"pid": 42, "name": "nc"}},       # NEW
    ]
    new = agent._diff_new(baseline, sample)
    assert len(new) == 1
    assert new[0]["event_type"] == "process_new"
    assert new[0]["payload"]["pid"] == 42


# -- config discovery -----------------------------------------------------

def test_submit_saved_collection(db, tmp_path):
    """Offline USB workflow: a saved collection JSON is uploaded via submit."""
    from hexbee_hive.api import create_app
    from hexbee_hive.config import HiveConfig
    from hexbee_forager.cli import cmd_submit
    import types

    app = create_app(HiveConfig(data_dir=tmp_path, ingest_key="fk"), db)
    app.testing = True

    # Save a collection to a file (as `collect --output` would).
    agent = Forager(None, None, spool_dir=tmp_path / "s", device="Forager-USB")
    events = agent.collect(volatile_only=True)
    saved = tmp_path / "cap.json"
    saved.write_text(json.dumps(events))

    # submit ships them; point the Forager at the test app via monkeypatched post
    forager = Forager("http://x", "fk", spool_dir=tmp_path / "s2")
    posted = {"n": 0}

    def fake_post(chunk):
        r = app.test_client().post("/api/v1/ingest", json=chunk,
                                   headers={"X-HexBee-Ingest-Key": "fk"})
        posted["n"] += len(chunk)
        return r.status_code == 200
    forager._post = fake_post

    res = forager.ship(json.loads(saved.read_text()))
    assert res["shipped"] == len(events) and posted["n"] == len(events)
    assert "Forager-USB" in [r["name"] for r in db.query("SELECT name FROM devices")]


def test_frozen_spool_beside_executable(monkeypatch, tmp_path):
    import sys
    from hexbee_forager.cli import _default_spool
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "forager.exe"))
    monkeypatch.delenv("HEXBEE_SPOOL_DIR", raising=False)
    spool = _default_spool()
    assert spool == tmp_path / "collections" / "spool"


def test_config_discovery_precedence(tmp_path, monkeypatch):
    # explicit args win
    cfg = discover_config("http://explicit:8080", "explicit-key")
    assert cfg["hive_url"] == "http://explicit:8080"

    # env next
    monkeypatch.setenv("HEXBEE_HIVE_URL", "http://env:8080")
    monkeypatch.setenv("HEXBEE_INGEST_KEY", "env-key")
    cfg = discover_config()
    assert cfg["hive_url"] == "http://env:8080" and cfg["ingest_key"] == "env-key"


# -- end-to-end: collect -> ship -> Hive evidence chain -------------------

def test_forager_ships_into_hive(db, tmp_path):
    from hexbee_hive.api import create_app
    from hexbee_hive.config import HiveConfig

    app = create_app(HiveConfig(data_dir=tmp_path, ingest_key="fk"), db)
    app.testing = True
    client = app.test_client()

    agent = Forager("http://testserver", "fk", spool_dir=tmp_path / "spool",
                    device="Forager-CI")
    events = agent.collect(volatile_only=False)

    # Ship through the Flask test client (stand in for the network POST).
    resp = client.post("/api/v1/ingest", json=events,
                       headers={"X-HexBee-Ingest-Key": "fk"})
    assert resp.status_code == 200
    assert resp.get_json()["stored"] == len(events)

    # The device is now inventoried and events are hash-chained.
    from hexbee_hive.integrity import verify_chain
    assert verify_chain(db)["ok"]
    devices = [r["name"] for r in db.query("SELECT name FROM devices")]
    assert "Forager-CI" in devices
    started = db.query_one(
        "SELECT COUNT(*) AS n FROM events WHERE event_type='collection_started'")
    assert started["n"] == 1
