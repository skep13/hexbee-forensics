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


# -- the device name has to satisfy the Hive that receives it --------------
# macOS reports `Jacobs-MacBook-Air.local` and many Linux hosts report an FQDN.
# The Hive's normalizer rejects dots, so the unsanitised default made it refuse
# every event: 819 artifacts collected, 819 spooled, nothing stored.

def test_default_device_name_is_accepted_by_the_hive_normalizer():
    from hexbee_forager.agent import device_name
    from hexbee_hive.normalize import _NAME_RE

    assert _NAME_RE.match(device_name("Forager")), \
        "the Forager's own default device name must pass the Hive's validation"


@pytest.mark.parametrize("hostname", [
    "Jacobs-MacBook-Air.local",     # macOS mDNS suffix
    "pi.lan",                       # short domain
    "host.corp.example.com",        # full FQDN
    "weiße-kiste",             # non-ASCII
    "...",                          # degenerate
])
def test_device_name_sanitises_every_hostname_shape(hostname, monkeypatch):
    import socket
    from hexbee_forager.agent import device_name
    from hexbee_hive.normalize import _NAME_RE

    monkeypatch.setattr(socket, "gethostname", lambda: hostname)
    assert _NAME_RE.match(device_name("Forager"))


def test_explicit_device_name_is_also_sanitised():
    from hexbee_forager.agent import device_name
    from hexbee_hive.normalize import _NAME_RE

    assert _NAME_RE.match(device_name("Forager", "my host.local"))


# -- a spooled collection must be replayable ------------------------------
# The spool is JSONL because it is appended to as sends fail. `submit` used to
# parse the whole file as one JSON document, so the retry path for every
# offline collection failed on line 2.

def test_submit_reads_the_jsonl_spool(tmp_path):
    from hexbee_forager.cli import _load_events

    spool = tmp_path / "spool.jsonl"
    spool.write_text("".join(
        json.dumps({"event_type": "process_snapshot", "device": "F-1",
                    "payload": {"n": i}}) + "\n" for i in range(3)),
        encoding="utf-8")

    assert len(_load_events(spool)) == 3


def test_submit_still_reads_a_single_json_document(tmp_path):
    from hexbee_forager.cli import _load_events

    doc = tmp_path / "collection.json"
    doc.write_text(json.dumps([{"event_type": "process_snapshot"}] * 2),
                   encoding="utf-8")
    assert len(_load_events(doc)) == 2

    wrapped = tmp_path / "wrapped.json"
    wrapped.write_text(json.dumps({"events": [{"event_type": "x"}]}),
                       encoding="utf-8")
    assert len(_load_events(wrapped)) == 1


def test_submit_survives_a_truncated_spool_line(tmp_path):
    """A spool killed mid-write must not cost the events already in it."""
    from hexbee_forager.cli import _load_events

    spool = tmp_path / "partial.jsonl"
    spool.write_text(json.dumps({"event_type": "a", "device": "F-1"}) + "\n"
                     + '{"event_type": "b", "devi',
                     encoding="utf-8")
    assert len(_load_events(spool)) == 1
