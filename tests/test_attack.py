"""Offline MITRE ATT&CK attribution."""

import json

from hexbee_hive import attack
from hexbee_hive.cases import assign_incident, create_case
from hexbee_hive.correlate import Correlator
from hexbee_hive.ingest import process_raw_event


def store(db, event_type, payload=None, device="Scout01"):
    return process_raw_event(
        db, Correlator(db, 600),
        {"device": device, "event_type": event_type, "payload": payload or {},
         "occurred_at": "2026-07-25T10:00:00Z"},
        source="test")


def test_map_event_by_type():
    assert "T1547.001" in attack.map_event("autorun_found")
    assert "T1059.001" in attack.map_event("powershell_launched")
    assert set(attack.map_event("usb_inserted")) == {"T1200", "T1091"}


def test_map_event_by_payload_discriminator():
    assert attack.map_event("persistence_item", {"type": "cron"}) == ["T1053.003"]
    assert attack.map_event("persistence_item", {"type": "systemd_unit"}) == ["T1543.002"]
    assert attack.map_event("network_alert", {"rule": "arp_spoof"}) == ["T1557.002"]
    assert attack.map_event("log_anomaly", {"rule": "auth_bruteforce"}) == ["T1110"]
    assert attack.map_event("ad_recon_finding",
                            {"finding": "kerberoastable"}) == ["T1558.003"]


def test_unknown_types_map_to_nothing():
    assert attack.map_event("heartbeat") == []
    assert attack.map_event("totally_made_up") == []


def test_tool_can_declare_its_own_technique():
    ids = attack.map_event("carved_file", {"attack": "T1027"})
    assert ids == ["T1005", "T1027"]


def test_mapping_is_deduplicated():
    ids = attack.map_event("usb_inserted", {"attack": ["T1200", "T1200"]})
    assert ids.count("T1200") == 1


def test_every_mapped_technique_has_a_valid_tactic():
    """A technique pointing at a tactic the heatmap does not render would
    silently vanish from the report."""
    for tid, (_name, tactic) in attack.TECHNIQUES.items():
        assert tactic in attack.TACTICS, f"{tid} has unknown tactic {tactic}"


def test_all_referenced_techniques_are_defined():
    referenced = set()
    for ids in attack._BY_TYPE.values():
        referenced.update(ids)
    for _key, table in attack._BY_PAYLOAD.values():
        for ids in table.values():
            referenced.update(ids)
    missing = referenced - set(attack.TECHNIQUES)
    assert not missing, f"undefined techniques referenced: {missing}"


def test_tagging_happens_at_ingest(db):
    result = store(db, "autorun_found", {"name": "evil.lnk"})
    assert "T1547.001" in result["techniques"]
    rows = db.query("SELECT technique_id, tactic FROM event_techniques "
                    "WHERE event_id = ?", (result["event_id"],))
    assert [dict(r) for r in rows] == [{"technique_id": "T1547.001",
                                        "tactic": "persistence"}]


def test_backfill_tags_untagged_events(db):
    result = store(db, "powershell_launched", {"cmd": "iex"})
    db.execute("DELETE FROM event_techniques")
    assert attack.backfill(db) == 1
    assert attack.event_techniques(db, result["event_id"])[0]["id"] == "T1059.001"


def test_case_coverage_aggregates_by_tactic(db):
    case = create_case(db, "Engagement", "", "tester")
    result = store(db, "autorun_found", {"name": "evil.lnk"})
    assign_incident(db, result["incident_id"], case["id"], "tester")
    store(db, "credential_capture", {"account": "svc"})

    coverage = attack.case_coverage(db, case["id"])
    persistence = next(t for t in coverage["tactics"] if t["tactic"] == "persistence")
    assert persistence["events"] >= 1
    assert coverage["total_attributions"] >= 1
    assert len(coverage["tactics"]) == len(attack.TACTICS)


def test_global_coverage_shape(db):
    store(db, "yara_match", {"rule": "Win32_Trojan"})
    coverage = attack.global_coverage(db)
    assert coverage["distinct_techniques"] >= 1
    labels = [t["label"] for t in coverage["tactics"]]
    assert "Command And Control" in labels


def test_bundle_load_is_safe_when_absent(tmp_path):
    assert attack.load_bundle(tmp_path / "nope.json") == 0
    assert attack.load_bundle("") == 0


def test_bundle_enriches_technique_names(tmp_path):
    bundle = tmp_path / "attack.json"
    bundle.write_text(json.dumps({"objects": [{
        "type": "attack-pattern",
        "name": "Renamed Technique",
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack",
                               "phase_name": "discovery"}],
        "external_references": [{"source_name": "mitre-attack",
                                 "external_id": "T9999"}],
    }]}), encoding="utf-8")
    assert attack.load_bundle(bundle) == 1
    assert attack.technique("T9999")["name"] == "Renamed Technique"
    assert attack.technique("T9999")["tactic"] == "discovery"


def test_malformed_bundle_does_not_raise(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert attack.load_bundle(bad) == 0


def test_tagging_failure_never_loses_the_event(db, monkeypatch):
    monkeypatch.setattr(attack, "tag_event",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    result = store(db, "usb_inserted", {"name": "stick"})
    assert result["ok"] and result["techniques"] == []
    assert db.query_one("SELECT id FROM events WHERE id = ?",
                        (result["event_id"],)) is not None
