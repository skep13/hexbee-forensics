"""Queen-side engagement tooling: recon, responder, bloodhound, pivot, picos."""

import hashlib
import hmac
import json
import zipfile

import pytest

from hexbee_queen import bloodhound, pico, pivot, recon
from hexbee_queen import scope as queen_scope


# -- recon -----------------------------------------------------------------

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV 10.10.0.5">
  <host>
    <status state="up"/>
    <address addr="10.10.0.5" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Dell Inc."/>
    <hostnames><hostname name="web01.client.test"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Samba" version="4.15"/>
        <script id="smb-vuln-ms17-010" output="VULNERABLE: CVE-2017-0143"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed"/>
        <service name="http-proxy"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.X" accuracy="95"/></os>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.10.0.6" addrtype="ipv4"/>
  </host>
</nmaprun>"""


def test_parse_nmap_xml():
    hosts = recon.parse_xml(NMAP_XML)
    assert len(hosts) == 1                      # the down host is dropped
    host = hosts[0]
    assert host["ip"] == "10.10.0.5"
    assert host["vendor"] == "Dell Inc."
    assert host["os"] == "Linux 5.X" and host["os_accuracy"] == 95
    assert [p["port"] for p in host["ports"]] == [22, 445]   # closed port dropped


def test_recon_events_flag_vulnerabilities():
    hosts = recon.parse_xml(NMAP_XML)
    events = recon.to_events(hosts, "Queen-Recon", "sweep", "nmap -sV", case_id=3)
    findings = [e["payload"]["finding"] for e in events]
    assert findings.count("host_up") == 1
    assert "vulnerability" in findings
    assert findings[-1] == "sweep_summary"
    vuln = next(e for e in events if e["payload"]["finding"] == "vulnerability")
    assert "CVE-2017-0143" in json.dumps(vuln["payload"])
    assert all(e["event_type"] == "recon_finding" for e in events)


def test_bad_xml_raises():
    with pytest.raises(ValueError):
        recon.parse_xml("<not-xml")


def test_expand_targets_per_host():
    """Expansion is what lets a partially-authorised range scan only its
    authorised part instead of being refused wholesale."""
    assert recon.expand_targets("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]
    assert recon.expand_targets("10.0.0.5") == ["10.0.0.5"]
    assert recon.expand_targets("host.example") == ["host.example"]


def test_expand_targets_refuses_huge_ranges():
    with pytest.raises(ValueError):
        recon.expand_targets("10.0.0.0/8")


# -- scope gate ------------------------------------------------------------

class FakeClient:
    def __init__(self, allowed=True, reason="ok", raise_on_check=False):
        self.allowed = allowed
        self.reason = reason
        self.raise_on_check = raise_on_check
        self.violations = []
        self.ingested = []

    def scope_check(self, target, case_id=None):
        if self.raise_on_check:
            raise OSError("hive unreachable")
        return {"allowed": self.allowed, "reason": self.reason,
                "auth_ref": "SOW-1" if self.allowed else ""}

    def scope_violation(self, target, tool, reason, extra):
        self.violations.append((target, tool, reason))
        return {"event_id": 99}

    def ingest(self, events, key):
        self.ingested.extend(events)
        return {"stored": len(events)}

    def anchor(self):
        return {"head_hash": "abc123", "signature": "sig"}


def test_guard_allows_and_reports_authorisation(capsys):
    decision = queen_scope.guard(FakeClient(True), "10.0.0.1", tool="test")
    assert decision and decision.auth_ref == "SOW-1"


def test_guard_records_a_violation_on_refusal():
    client = FakeClient(False, "not in scope")
    decision = queen_scope.guard(client, "8.8.8.8", tool="hexbee-recon")
    assert not decision
    assert client.violations == [("8.8.8.8", "hexbee-recon", "not in scope")]
    assert decision.recorded_event == 99


def test_guard_fails_closed_when_the_hive_is_unreachable():
    """An unreachable authorisation server is not permission."""
    decision = queen_scope.guard(FakeClient(raise_on_check=True), "10.0.0.1",
                                 tool="test")
    assert not decision
    assert "unreachable" in decision.reason or "failed" in decision.reason


def test_override_requires_the_exact_value(monkeypatch):
    client = FakeClient(False, "nope")
    monkeypatch.setenv(queen_scope.OVERRIDE_ENV, "yes")
    assert not queen_scope.guard(client, "10.0.0.1", tool="test")
    monkeypatch.setenv(queen_scope.OVERRIDE_ENV, queen_scope.OVERRIDE_VALUE)
    assert queen_scope.guard(client, "10.0.0.1", tool="test")


def test_recon_refuses_when_everything_is_out_of_scope():
    result = recon.scan(FakeClient(False, "denied"), "10.0.0.5", dry_run=True)
    assert result["ok"] is False and result["refused"] == 1


# -- responder -------------------------------------------------------------

def test_parse_ntlmv2_line():
    from hexbee_queen.responder import parse_line

    line = "jdoe::CLIENT:1122334455667788:" + "a" * 32 + ":" + "b" * 120
    cap = parse_line(line, "SMB", "NTLMv2", "10.0.0.9")
    assert cap["format"] == "NTLMv2-SSP"
    assert cap["user"] == "jdoe" and cap["domain"] == "CLIENT"
    assert cap["crackable"] is True
    assert len(cap["fingerprint"]) == 64


def test_parse_cleartext_only_in_cleartext_files():
    from hexbee_queen.responder import parse_line

    assert parse_line("bob:hunter2", "HTTP", "Clear-Text", "10.0.0.9")["format"] == "cleartext"
    assert parse_line("bob:hunter2", "HTTP", "NTLMv2", "10.0.0.9") is None


def test_responder_events_omit_material_by_default():
    from hexbee_queen.responder import to_events

    caps = [{"format": "NTLMv2-SSP", "user": "jdoe", "domain": "CLIENT",
             "protocol": "SMB", "source_host": "10.0.0.9", "crackable": True,
             "fingerprint": "f" * 64, "material": "SECRET-HASH"}]
    payload = to_events(caps, "Q", None, include_material=False)[0]["payload"]
    assert "material" not in payload
    assert payload["fingerprint"] == "f" * 64
    assert payload["material_included"] is False

    payload = to_events(caps, "Q", None, include_material=True)[0]["payload"]
    assert payload["material"] == "SECRET-HASH"
    assert payload["material_included"] is True


def test_responder_bridge_deduplicates(tmp_path):
    from hexbee_queen.responder import ResponderBridge

    log = tmp_path / "SMB-NTLMv2-10.0.0.9.txt"
    line = "jdoe::CLIENT:1122334455667788:" + "a" * 32 + ":" + "b" * 40
    log.write_text(line + "\n", encoding="utf-8")
    bridge = ResponderBridge(FakeClient(), tmp_path, ingest_key="k")
    assert len(bridge.sweep()) == 1
    assert bridge.sweep() == []                 # same hash, not re-reported
    log.write_text(line + "\n" + line + "\n", encoding="utf-8")
    assert bridge.sweep() == []


# -- bloodhound ------------------------------------------------------------

def bloodhound_bundle(tmp_path):
    users = {"meta": {"type": "users"}, "data": [
        {"Properties": {"name": "SVC_SQL@CLIENT.TEST", "domain": "CLIENT.TEST",
                        "serviceprincipalnames": ["MSSQLSvc/sql01"],
                        "enabled": True, "admincount": True}},
        {"Properties": {"name": "NOPREAUTH@CLIENT.TEST", "domain": "CLIENT.TEST",
                        "dontreqpreauth": True, "enabled": True}},
        {"Properties": {"name": "PLAIN@CLIENT.TEST", "domain": "CLIENT.TEST",
                        "enabled": True}},
    ]}
    computers = {"meta": {"type": "computers"}, "data": [
        {"Properties": {"name": "DC01.CLIENT.TEST", "domain": "CLIENT.TEST",
                        "unconstraineddelegation": True,
                        "operatingsystem": "Windows Server 2022"}},
    ]}
    groups = {"meta": {"type": "groups"}, "data": [
        {"Properties": {"name": "DOMAIN ADMINS@CLIENT.TEST",
                        "domain": "CLIENT.TEST"},
         "Members": [{"ObjectIdentifier": "S-1-5-21-1"}]},
    ]}
    path = tmp_path / "bh.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("users.json", json.dumps(users))
        zf.writestr("computers.json", json.dumps(computers))
        zf.writestr("groups.json", json.dumps(groups))
    return path


def test_bloodhound_parses_a_zip_bundle(tmp_path):
    findings = bloodhound.parse(bloodhound_bundle(tmp_path))
    assert [f["account"] for f in findings["kerberoastable"]] == ["SVC_SQL@CLIENT.TEST"]
    assert [f["account"] for f in findings["asrep_roastable"]] == ["NOPREAUTH@CLIENT.TEST"]
    assert findings["unconstrained_delegation"][0]["host"] == "DC01.CLIENT.TEST"
    assert findings["domain_admins"][0]["member_count"] == 1
    assert findings["domains"] == ["CLIENT.TEST"]


def test_bloodhound_events_carry_the_attack_discriminator(tmp_path):
    from hexbee_hive.attack import map_event

    findings = bloodhound.parse(bloodhound_bundle(tmp_path))
    events = bloodhound.to_events(findings, "Queen-BH", case_id=1)
    kinds = [e["payload"]["finding"] for e in events]
    assert kinds[-1] == "collection_summary"
    # Each finding kind must actually map to a technique in the Hive.
    for kind in ("kerberoastable", "asrep_roastable", "unconstrained_delegation",
                 "domain_admin_path"):
        assert kind in kinds
        assert map_event("ad_recon_finding", {"finding": kind}), kind


def test_bloodhound_ignores_unreadable_files(tmp_path):
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    findings = bloodhound.parse(tmp_path)
    assert findings["kerberoastable"] == []


# -- pivot -----------------------------------------------------------------

def test_pivot_unit_binds_to_localhost_only(tmp_path):
    rendered = pivot.write_unit(tmp_path, queen_host="queen.lan", remote_port=2222)
    unit = (tmp_path / pivot.UNIT_NAME).read_text(encoding="utf-8")
    assert "-R 2222:localhost:22" in unit
    assert "ExitOnForwardFailure yes" in unit
    assert "MemoryMax=64M" in unit               # cannot crowd out the Hive
    assert "autossh" in unit
    assert len(rendered["files"]) == 2


def test_hive_pause_never_stops_ingest():
    commands = " ".join(pivot.hive_pause_commands(True))
    assert "hexbee-web" in commands
    assert "stop hexbee-engine" not in commands


def test_pivot_session_event_shape():
    event = pivot.session_event("Queen-Pivot", "opened", 2222, case_id=4)
    assert event["event_type"] == "pivot_session"
    assert event["payload"]["state"] == "opened"


# -- picos -----------------------------------------------------------------

SEAL_KEY = b"0123456789abcdef" * 4


def make_seal(device="abc123", kind="case_seal", counter=1, nonce="deadbeef",
              head="head1", key=SEAL_KEY):
    material = f"{device}|{kind}|{counter}|{nonce}|{head}"
    sig = hmac.new(key, material.encode(), hashlib.sha256).hexdigest()
    return (f"HEXBEE-SEAL v=1 device={device} kind={kind} counter={counter} "
            f"nonce={nonce} head={head} sig={sig} uptime=12.3")


def test_parse_and_verify_seal():
    seal = pico.parse_seal(make_seal())
    assert seal["device"] == "abc123" and seal["counter"] == 1
    ok, reason = pico.verify_seal(seal, SEAL_KEY)
    assert ok and "verified" in reason


def test_seal_with_wrong_key_fails():
    seal = pico.parse_seal(make_seal())
    ok, reason = pico.verify_seal(seal, b"wrong-key")
    assert not ok and "MISMATCH" in reason


def test_unsigned_seal_is_reported_as_such():
    line = "HEXBEE-SEAL v=1 device=x kind=case_seal counter=1 nonce=n head=- sig=unsigned"
    seal = pico.parse_seal(line)
    assert seal["head"] == ""
    ok, reason = pico.verify_seal(seal, SEAL_KEY)
    assert not ok and "unsigned" in reason


def test_non_seal_lines_are_ignored():
    assert pico.parse_seal("HEXBEE-SENTINEL ready device=x") is None
    assert pico.parse_seal("garbage") is None
    assert pico.parse_seal("HEXBEE-SEAL v=1 device=x") is None      # no counter


def test_counter_guard_rejects_replays(tmp_path):
    guard = pico.CounterGuard(tmp_path / "counters")
    assert guard.check("tok", 1)[0] is True
    assert guard.check("tok", 2)[0] is True
    ok, reason = guard.check("tok", 2)
    assert not ok and "backwards" in reason
    assert guard.check("other-token", 1)[0] is True


def test_counter_guard_persists(tmp_path):
    path = tmp_path / "counters"
    pico.CounterGuard(path).check("tok", 5)
    assert pico.CounterGuard(path).check("tok", 5)[0] is False


def test_seal_event_states_the_timestamp_source():
    seal = pico.parse_seal(make_seal())
    payload = pico.seal_event(seal, True, "ok", "Pico-Sentinel", 1,
                              "jacob", witness="DS Miller")["payload"]
    assert payload["signature_verified"] is True
    assert payload["witness"] == "DS Miller"
    assert "no real-time clock" in payload["timestamp_source"]


def test_hid_log_import_skips_disarmed_runs(tmp_path):
    log = tmp_path / "deploy.log"
    log.write_text(
        "proof-of-execution\tok\tfnv1a:1234\tlines=8\tkeys=120\tuptime=5.0\n"
        "proof-of-execution\tdisarmed\tfnv1a:1234\n"
        "host-enum\terror: boom\tfnv1a:abcd\tlines=2\tkeys=3\tuptime=6.0\n",
        encoding="utf-8")
    client = FakeClient()
    result = pico.import_hid_log(client, log, ingest_key="k", case_id=2,
                                 operator="jacob", target="RECEPTION-PC")
    assert result["entries"] == 2               # the disarmed run is skipped
    assert result["stored"] == 2
    payload = client.ingested[0]["payload"]
    assert client.ingested[0]["event_type"] == "hid_deployment"
    assert payload["payload_name"] == "proof-of-execution"
    assert payload["target_host"] == "RECEPTION-PC"
    assert payload["keystrokes"] == 120


def test_hid_log_missing_file_raises(tmp_path):
    with pytest.raises(RuntimeError):
        pico.parse_hid_log(tmp_path / "nope.log")
