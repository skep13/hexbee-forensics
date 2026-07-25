"""Forager diagnostics mode, memory acquisition prechecks, and Comb YARA."""

from hexbee_forager import diagnostics, memory
from hexbee_forager.agent import MODES, Forager


# -- diagnostics collectors -----------------------------------------------

def test_every_diagnostic_collector_returns_well_formed_events():
    """A collector that returns a malformed event would be rejected at the
    Hive and the failure would only show up in the field."""
    for name, fn, _volatile in diagnostics.DIAGNOSTIC_COLLECTORS:
        events = fn()
        assert isinstance(events, list), name
        for event in events:
            assert event["event_type"] in ("diagnostic_snapshot", "diagnostic_alert"), name
            assert isinstance(event["payload"], dict), name
            assert event["occurred_at"].endswith("Z"), name


def test_resources_reports_memory():
    events = diagnostics.collect_resources()
    snapshot = next(e for e in events if e["event_type"] == "diagnostic_snapshot")
    assert snapshot["payload"]["kind"] == "resources"
    assert snapshot["payload"].get("memory_total", 0) > 0


def test_disks_reports_at_least_one_filesystem():
    events = diagnostics.collect_disks()
    snapshot = events[0]["payload"]
    assert snapshot["kind"] == "disks"
    assert snapshot["filesystems"]
    assert all(0 <= fs["used_percent"] <= 100 for fs in snapshot["filesystems"])


def test_alerts_carry_a_rule_the_attack_tagger_understands():
    from hexbee_hive.attack import map_event

    alert = diagnostics._alert("disk_full", "test", mount="/")
    assert alert["event_type"] == "diagnostic_alert"
    assert alert["payload"]["rule"] == "disk_full"
    # diagnostic_alert is not an adversary technique; it must map to nothing
    # rather than to something misleading.
    assert map_event("diagnostic_alert", alert["payload"]) == []


def test_smart_is_silent_without_smartctl(monkeypatch):
    monkeypatch.setattr(diagnostics.shutil, "which", lambda _: None)
    assert diagnostics.collect_smart() == []


# -- agent mode wiring -----------------------------------------------------

def test_agent_swaps_collector_registry_by_mode(tmp_path):
    forensic = Forager(None, None, spool_dir=tmp_path, mode="forensic")
    diag = Forager(None, None, spool_dir=tmp_path, mode="diagnostics")
    assert [n for n, _, _ in forensic.collectors] != [n for n, _, _ in diag.collectors]
    assert "resources" in [n for n, _, _ in diag.collectors]
    assert "processes" in [n for n, _, _ in forensic.collectors]


def test_unknown_mode_falls_back_to_forensic(tmp_path):
    assert Forager(None, None, spool_dir=tmp_path, mode="nonsense").mode == "forensic"
    assert set(MODES) == {"forensic", "diagnostics"}


def test_diagnostics_collection_is_framed_and_stamped(tmp_path):
    agent = Forager(None, None, spool_dir=tmp_path, mode="diagnostics",
                    device="Forager-Test")
    events = agent.collect(volatile_only=True)
    assert events[0]["event_type"] == "collection_started"
    assert events[0]["payload"]["collection_mode"] == "diagnostics"
    assert events[-1]["event_type"] == "collection_completed"
    assert all(e["device"] == "Forager-Test" for e in events)
    types = {e["event_type"] for e in events}
    assert types <= {"collection_started", "collection_completed",
                     "diagnostic_snapshot", "diagnostic_alert"}


# -- memory acquisition ----------------------------------------------------

def test_status_is_honest_about_readiness():
    info = memory.status()
    assert set(info) >= {"platform", "ram_bytes", "method", "ready", "reason",
                         "elevated"}
    if not info["ready"]:
        assert info["reason"] and info["method"] is None


def test_physical_memory_is_detected():
    assert memory.physical_memory_bytes() > 0


def test_space_precheck_refuses_when_too_small(tmp_path):
    ok, detail = memory.check_space(tmp_path, needed=10 ** 15)
    assert ok is False
    assert detail["required"] > detail["free"]


def test_space_precheck_passes_for_a_tiny_dump(tmp_path):
    ok, _ = memory.check_space(tmp_path, needed=1024)
    assert ok is True


def test_hash_stream_matches_hashlib(tmp_path):
    import hashlib

    blob = b"hexbee" * 5000
    path = tmp_path / "dump.raw"
    path.write_bytes(blob)
    digest, size = memory.hash_stream(path, chunk=64)
    assert digest == hashlib.sha256(blob).hexdigest()
    assert size == len(blob)


def test_hash_stream_peak_memory_is_one_chunk(tmp_path):
    """The whole point of streaming: a dump larger than RAM must still hash."""
    path = tmp_path / "big.raw"
    path.write_bytes(b"\x00" * (1024 * 512))
    seen = []
    _digest, size = memory.hash_stream(path, chunk=4096,
                                       progress=lambda n: seen.append(n))
    assert size == 1024 * 512
    # One progress callback per chunk proves it read incrementally rather than
    # slurping the file — which is what makes a 64 GB dump hashable on 4 GB.
    assert len(seen) == size // 4096


def test_dry_run_reports_without_capturing(tmp_path, monkeypatch):
    monkeypatch.setattr(memory, "find_tool", lambda method="auto": ("lime", "/fake/lime.ko"))
    events = memory.acquire(tmp_path, dry_run=True)
    assert events[0]["event_type"] == "memory_acquisition_started"
    assert events[1]["event_type"] == "memory_acquisition_failed"
    assert "dry run" in events[1]["payload"]["reason"]
    assert not list(tmp_path.glob("*.raw"))


def test_missing_tool_is_explained(tmp_path, monkeypatch):
    monkeypatch.setattr(memory, "find_tool", lambda method="auto": None)
    events = memory.acquire(tmp_path)
    assert events[-1]["event_type"] == "memory_acquisition_failed"
    reason = events[-1]["payload"]["reason"]
    assert "winpmem" in reason or "LiME" in reason


def test_started_event_warns_about_the_driver(tmp_path, monkeypatch):
    monkeypatch.setattr(memory, "find_tool", lambda method="auto": None)
    started = memory.acquire(tmp_path)[0]
    assert "kernel driver" in started["payload"]["warning"]


# -- Comb YARA -------------------------------------------------------------

def test_yara_status_is_honest_when_unavailable(tmp_path):
    from hexbee_comb import yara_scan

    info = yara_scan.status(tmp_path)          # empty dir: no rules
    assert info["available"] is False
    assert info["reason"]


def test_compile_returns_none_without_rules(tmp_path):
    from hexbee_comb import yara_scan

    assert yara_scan.compile_rules(tmp_path) is None


def test_find_rule_dir_prefers_explicit(tmp_path):
    from hexbee_comb import yara_scan

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "test.yar").write_text("rule x { condition: true }", encoding="utf-8")
    assert yara_scan.find_rule_dir(rules) == rules


def test_scan_without_yara_still_completes(tmp_path):
    """YARA is optional: a scan must run, and say why it skipped."""
    from hexbee_comb.analysis import scan, to_hive_events

    (tmp_path / "note.txt").write_text("hello", encoding="utf-8")
    result = scan(tmp_path, use_yara=False)
    assert result.files
    assert result.yara == []
    assert "disabled" in result.yara_status["reason"]
    events = to_hive_events(result, device="Comb01")
    completed = next(e for e in events if e["event_type"] == "analysis_completed")
    assert completed["payload"]["yara_matches"] == 0


def test_yara_matches_become_events():
    from hexbee_comb.analysis import ScanResult, to_hive_events
    from hexbee_comb.yara_scan import Match

    result = ScanResult(target="/t", started_at="2026-07-25T10:00:00Z",
                        finished_at="2026-07-25T10:01:00Z")
    result.yara = [Match(path="bad.exe", rule="Win32_Trojan", namespace="malware",
                         tags=["trojan"], meta={"description": "test rule"},
                         strings=["$a", "$b"], sha256="d" * 64)]
    events = to_hive_events(result, device="Comb01")
    match_event = next(e for e in events if e["event_type"] == "yara_match")
    assert match_event["payload"]["rule"] == "Win32_Trojan"
    assert match_event["payload"]["sha256"] == "d" * 64
    assert match_event["payload"]["matched_strings"] == ["$a", "$b"]


def test_yara_match_maps_to_attack_techniques():
    from hexbee_hive.attack import map_event

    assert set(map_event("yara_match", {"rule": "X"})) == {"T1204.002", "T1027"}


def test_report_includes_the_yara_section(tmp_path):
    from hexbee_comb.analysis import render_report, scan

    (tmp_path / "a.txt").write_text("x", encoding="utf-8")
    html = render_report(scan(tmp_path, use_yara=False))
    assert "YARA matches" in html
