"""Syslog anomaly rules and the offline threat-intel store."""

import time

from hexbee_hive import intel
from hexbee_hive.config import HiveConfig
from hexbee_hive.correlate import Correlator
from hexbee_hive.syslog import (
    LogRecord,
    RuleEngine,
    ingest_records,
    parse_syslog,
    record_from_json,
)


# -- parsing --------------------------------------------------------------

def test_parse_rfc3164():
    rec = parse_syslog("<34>Oct 11 22:14:15 web01 sshd[1234]: Failed password "
                       "for root from 10.0.0.9", "10.0.0.9")
    assert rec.host == "web01"
    assert rec.tag == "sshd"
    assert "Failed password" in rec.message
    assert rec.severity == "crit"


def test_parse_rfc5424():
    rec = parse_syslog("<165>1 2026-07-25T22:14:15Z host01 app 42 ID47 - "
                       "an event happened")
    assert rec.host == "host01"
    assert rec.tag == "app"
    assert rec.message == "an event happened"


def test_unparseable_line_still_yields_a_record():
    rec = parse_syslog("total gibberish with no structure", "192.0.2.5")
    assert rec.message == "total gibberish with no structure"
    assert rec.source_ip == "192.0.2.5"


def test_windows_forwarder_record():
    rec = record_from_json({"Hostname": "DC01", "Channel": "Security",
                            "EventID": 4625, "Message": "logon failure"},
                           "10.0.0.4")
    assert rec.host == "DC01"
    assert rec.tag == "Security"
    assert "EventID=4625" in rec.message


# -- rules ----------------------------------------------------------------

def test_single_shot_rule_fires_immediately():
    engine = RuleEngine()
    events = engine.evaluate(LogRecord(host="web01", tag="sudo",
                                       message="sudo: jacob : COMMAND=/bin/bash"))
    assert [e["payload"]["rule"] for e in events] == ["privilege_escalation"]
    assert events[0]["event_type"] == "log_anomaly"


def test_bruteforce_needs_the_threshold():
    engine = RuleEngine()
    rec = LogRecord(host="web01", tag="sshd", message="Failed password for root")
    for _ in range(4):
        assert engine.evaluate(rec) == []
    fired = engine.evaluate(rec)
    assert fired and fired[0]["payload"]["rule"] == "auth_bruteforce"
    assert fired[0]["payload"]["occurrences"] == 5


def test_bruteforce_fires_once_per_window():
    engine = RuleEngine()
    rec = LogRecord(host="web01", tag="sshd", message="Failed password for root")
    fired = sum(bool(engine.evaluate(rec)) for _ in range(10))
    assert fired == 2          # at the 5th and the 10th, not 6 times


def test_bruteforce_counts_per_host():
    engine = RuleEngine()
    for _ in range(4):
        engine.evaluate(LogRecord(host="a", message="Failed password"))
    assert engine.evaluate(LogRecord(host="b", message="Failed password")) == []


def test_windows_event_ids_match_rules():
    engine = RuleEngine()
    for event_id, expected in [(4720, "account_created"),
                               (7045, "service_installed"),
                               (1102, "log_cleared")]:
        events = engine.evaluate(
            LogRecord(host="DC01", tag="Security",
                      message=f"EventID={event_id} something happened"))
        assert expected in [e["payload"]["rule"] for e in events]


def test_findings_are_stored_but_raw_logs_are_not(db):
    engine = RuleEngine()
    records = [LogRecord(host="web01", tag="cron", message="nothing special")
               for _ in range(20)]
    records.append(LogRecord(host="web01", tag="useradd",
                             message="useradd[99]: new user: name=backdoor"))
    result = ingest_records(db, Correlator(db, 600), records, engine)
    assert result["received"] == 21
    assert result["anomalies"] == 1
    # 21 lines in, exactly one evidence record out.
    assert db.query_one("SELECT COUNT(*) AS n FROM events")["n"] == 1


def test_message_is_truncated_in_the_event(db):
    engine = RuleEngine()
    rec = LogRecord(host="web01", tag="sudo",
                    message="sudo: x : COMMAND=/bin/sh " + "A" * 2000)
    events = engine.evaluate(rec)
    assert len(events[0]["payload"]["message"]) <= 500


# -- threat intel ---------------------------------------------------------

def test_candidate_extraction_finds_hashes_ips_domains():
    payload = {"name": "evil.exe",
               "sha256": "a" * 64,
               "md5": "b" * 32,
               "url": "http://bad.example.com/payload.bin",
               "remote": "203.0.113.9:443",
               "local": "192.168.1.5:1234"}
    found = set(intel.candidates(payload))
    assert ("sha256", "a" * 64) in found
    assert ("md5", "b" * 32) in found
    assert ("ip", "203.0.113.9") in found
    assert {kind for kind, _ in found} >= {"sha256", "md5", "url", "ip", "domain"}


def test_private_addresses_are_not_looked_up():
    values = [value for kind, value in
              intel.candidates({"local": "192.168.1.5", "loop": "127.0.0.1",
                                "public": "203.0.113.9"})
              if kind == "ip"]
    assert values == ["203.0.113.9"]


def test_candidates_are_capped():
    payload = {"blob": " ".join(f"203.0.{i // 256}.{i % 256}" for i in range(200))}
    assert len(intel.candidates(payload, cap=10)) <= 10


def test_lookup_is_empty_without_a_database(tmp_path):
    store = intel.IntelStore(tmp_path / "missing.db")
    assert store.available() is False
    assert store.lookup([("sha256", "a" * 64)]) == []
    assert store.stats()["available"] is False


def test_upsert_and_lookup(tmp_path):
    store = intel.IntelStore(tmp_path / "intel.db")
    store.upsert([("sha256", "a" * 64, "testfeed", "malware", "2026-01-01")])
    hits = store.lookup([("sha256", "a" * 64), ("sha256", "b" * 64)])
    assert len(hits) == 1
    assert hits[0]["source"] == "testfeed"
    stats = store.stats()
    assert stats["available"] and stats["indicators"] == 1
    store.close()


def test_intel_hit_escalates_and_creates_an_ioc(db, tmp_path, monkeypatch):
    from hexbee_hive import ingest as ingest_mod

    store = intel.IntelStore(tmp_path / "intel.db")
    store.upsert([("sha256", "c" * 64, "urlhaus", "malware-sample", "")])
    ingest_mod.set_intel_store(store)
    try:
        result = ingest_mod.process_raw_event(
            db, Correlator(db, 600),
            {"device": "Comb01", "event_type": "executable_found",
             "payload": {"name": "x.exe", "sha256": "c" * 64}},
            source="test")
    finally:
        ingest_mod.set_intel_store(None)
        store.close()

    row = db.query_one("SELECT severity FROM events WHERE id = ?",
                       (result["event_id"],))
    assert row["severity"] == 3          # intel hits are always critical
    ioc = db.query_one("SELECT note, added_by FROM iocs WHERE value = ?",
                       ("c" * 64,))
    assert ioc is not None and ioc["added_by"] == "intel-sync"
    assert "urlhaus" in ioc["note"]


def test_classify_mixed_feed_values():
    assert intel._classify("a" * 64, "mixed") == ("sha256", "a" * 64)
    assert intel._classify("203.0.113.9:80", "mixed") == ("ip", "203.0.113.9")
    assert intel._classify("bad.example.com", "mixed") == ("domain", "bad.example.com")
    assert intel._classify("http://x.test/a", "mixed")[0] == "url"
    assert intel._classify("", "mixed") is None


def test_intel_db_lives_outside_the_evidence_db(tmp_path):
    cfg = HiveConfig(data_dir=tmp_path)
    path = intel.intel_db_path(cfg)
    assert path.name == "intel.db"
    assert path.parent.name == "intel"
    assert path != cfg.db_path
