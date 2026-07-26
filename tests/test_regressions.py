"""Regressions for bugs found by auditing the built code.

Each of these shipped before it was caught. The tests exist so they cannot
ship again.
"""

import pytest

from hexbee_hive import ingest as ingest_mod
from hexbee_hive import intel as intel_mod
from hexbee_hive import knowledge
from hexbee_hive.ai import LocalAI, ask, looks_evidential, looks_operational
from hexbee_hive.correlate import Correlator
from hexbee_hive.ioc import INTEL_ACTOR, add_ioc, count_iocs, list_iocs, match_iocs


class OfflineAI(LocalAI):
    def __init__(self):
        super().__init__("http://127.0.0.1:1", "none")

    def available(self) -> bool:
        return False


# =====================================================================
# Feed-derived indicators must not enter the per-event substring scan.
#
# `match_iocs` scans every watchlist row against every string in every
# ingested event. Promoting threat-feed hits into that table meant a synced
# feed slowly poisoned the ingest hot path — precisely what the separate
# indexed intel database exists to prevent.
# =====================================================================

def test_intel_derived_iocs_are_excluded_from_the_scan(db):
    add_ioc(db, "substring", "analyst-added", "mine", actor="analyst")
    add_ioc(db, "substring", "feed-added", "from a feed", actor=INTEL_ACTOR)

    matched = match_iocs(db, {"note": "contains analyst-added and feed-added"})
    values = {m["value"] for m in matched}
    assert "analyst-added" in values
    assert "feed-added" not in values, (
        "feed indicators are matched by indexed lookup; rescanning them here "
        "is what made ingest degrade over time")


def test_scan_cost_does_not_grow_with_feed_size(db):
    """The load-bearing property: a big feed must not slow down ingest."""
    add_ioc(db, "substring", "analyst-only", "mine", actor="analyst")
    for i in range(300):
        add_ioc(db, "sha256", f"{i:064x}", "feed", actor=INTEL_ACTOR)

    scanned = db.query("SELECT COUNT(*) AS n FROM iocs WHERE added_by != ?",
                       (INTEL_ACTOR,))[0]["n"]
    assert scanned == 1, f"{scanned} rows would be scanned per event"
    assert count_iocs(db) == {"analyst": 1, "intel": 300, "total": 301}


def test_feed_hits_are_still_recorded_and_visible(db, tmp_path):
    """Excluding them from the scan must not lose them."""
    store = intel_mod.IntelStore(tmp_path / "intel.db")
    store.upsert([("sha256", "e" * 64, "urlhaus", "malware", "")])
    ingest_mod.set_intel_store(store)
    try:
        result = ingest_mod.process_raw_event(
            db, Correlator(db, 600),
            {"device": "Comb01", "event_type": "executable_found",
             "payload": {"name": "bad.exe", "sha256": "e" * 64}},
            source="test")
    finally:
        ingest_mod.set_intel_store(None)
        store.close()

    severity = db.query_one("SELECT severity FROM events WHERE id = ?",
                            (result["event_id"],))["severity"]
    assert severity == 3, "a feed hit must still escalate the event"
    assert db.query_one("SELECT COUNT(*) AS n FROM ioc_hits")["n"] == 1
    from_feed = list_iocs(db, "intel")
    assert len(from_feed) == 1 and "urlhaus" in from_feed[0]["note"]
    assert list_iocs(db, "analyst") == [], "feed rows must not clutter the "\
                                          "analyst watchlist"


def test_ioc_listing_defaults_to_the_analyst_watchlist(db):
    add_ioc(db, "substring", "mine", "", actor="analyst")
    add_ioc(db, "substring", "theirs", "", actor=INTEL_ACTOR)
    assert [i["value"] for i in list_iocs(db)] == ["mine"]
    assert len(list_iocs(db, "all")) == 2


# =====================================================================
# "What is a SHA256 hash" is a glossary question, not an evidence question.
#
# The device-name pattern that catches Scout01 also caught SHA256 and
# Windows10, so beginner definition questions were answered with hive
# statistics.
# =====================================================================

@pytest.mark.parametrize("question", [
    "what is a SHA256 hash",
    "can I use HexBee on Windows10",
    "how do I check the MD5 of a file",
    "does this support IPv6",
    "what is WPA2",
])
def test_technical_terms_are_not_mistaken_for_device_names(question):
    assert not looks_evidential(question), (
        f"{question!r} was treated as a question about specific evidence")


@pytest.mark.parametrize("question", [
    "what happened on Scout01 today",
    "was evil.exe seen anywhere",
    "did anything talk to 203.0.113.9",
])
def test_real_artifact_references_are_still_detected(question):
    assert looks_evidential(question), question


def test_definition_questions_reach_the_glossary(db):
    knowledge.reset()
    for question in ("what is a SHA256 hash", "what is a case",
                     "what does chain of custody mean"):
        result = ask(db, OfflineAI(), question)
        assert result["engine"] == "knowledge-base", (
            f"{question!r} was routed to the evidence path")


def test_evidence_questions_still_reach_the_evidence(db):
    knowledge.reset()
    result = ask(db, OfflineAI(), "was evil.exe seen anywhere")
    assert result["engine"] == "rule-based"


def test_hash_question_gets_the_hash_definition():
    knowledge.reset()
    doc = knowledge.get().best("what is a SHA256 hash")
    assert doc is not None and doc.id == "glossary-hash"


# =====================================================================
# Concurrent live streams are capped so browser tabs cannot starve ingest.
# =====================================================================

def test_stream_slots_are_bounded():
    from hexbee_hive import api

    assert api.MAX_LIVE_STREAMS >= 1
    acquired = []
    try:
        while api._stream_slots.acquire(blocking=False):
            acquired.append(True)
            assert len(acquired) <= api.MAX_LIVE_STREAMS + 1
        assert len(acquired) == api.MAX_LIVE_STREAMS
    finally:
        for _ in acquired:
            api._stream_slots.release()


def test_stream_slot_is_released_when_the_client_disconnects(db, tmp_path):
    """A leaked slot would eventually refuse every stream."""
    from hexbee_hive import api
    from hexbee_hive.api import create_app
    from hexbee_hive.auth import create_user
    from hexbee_hive.config import HiveConfig

    cfg = HiveConfig(data_dir=tmp_path, ingest_key="k" * 20)
    create_user(db, "watcher", "watcher-strong-pass1", "viewer")
    app = create_app(cfg, db)
    app.testing = True
    client = app.test_client()
    token = client.post("/api/v1/login",
                        json={"username": "watcher",
                              "password": "watcher-strong-pass1"}).get_json()

    for _ in range(api.MAX_LIVE_STREAMS + 2):
        resp = client.get("/api/v1/stream?since=0",
                          headers={"Authorization": f"Bearer {token['token']}"})
        assert resp.status_code == 200
        next(resp.response)          # consume the hello frame
        resp.close()                 # closing must return the slot


# =====================================================================
# A passive sweep must not emit one enormous batch.
# =====================================================================

def test_recon_sweep_caps_the_number_of_host_events():
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "netmon"))
    from hexbee_netmon.agent import NetMon
    from hexbee_netmon.decode import Packet

    mon = NetMon(None, None, mode="recon", spool_dir=Path("."))
    for i in range(mon.MAX_RECON_HOSTS + 250):
        mon.engine.feed(Packet(
            proto="tcp", src_ip=f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}",
            dst_ip="10.0.0.1", dst_port=80, flags=0x02, length=60))

    events = mon._recon_events()
    hosts = [e for e in events if e["payload"]["finding"] == "host_observed"]
    summary = next(e for e in events
                   if e["payload"]["finding"] == "sweep_summary")
    assert len(hosts) <= mon.MAX_RECON_HOSTS
    assert summary["payload"]["truncated"] is True
    assert summary["payload"]["hosts_omitted"] > 0, (
        "omitted hosts must be reported, not silently dropped")
