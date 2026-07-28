"""Netmon packet decoding, detection rules, and PCAP output."""

import socket
import struct

from hexbee_netmon import rules
from hexbee_netmon.capture import PcapWriter
from hexbee_netmon.decode import Packet, decode


# -- frame builders (so the decoder is tested against real byte layouts) ----

def eth(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:ff", ethertype=0x0800):
    def mac(value):
        return bytes(int(part, 16) for part in value.split(":"))
    return mac(dst) + mac(src) + struct.pack("!H", ethertype)


def ipv4(src="10.0.0.1", dst="10.0.0.2", proto=6, payload=b""):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0,
                         64, proto, 0, socket.inet_aton(src),
                         socket.inet_aton(dst))
    return header + payload


def tcp(sport=12345, dport=80, flags=0x02):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 8192, 0, 0)


def udp(sport=5353, dport=53, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_query(name="tunnel.example.com"):
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    encoded = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + encoded + struct.pack("!HH", 1, 1)


def arp(op=2, sender_ip="10.0.0.1", sender_mac="aa:bb:cc:dd:ee:ff",
        target_ip="10.0.0.2"):
    def mac(value):
        return bytes(int(part, 16) for part in value.split(":"))
    return (struct.pack("!HHBBH", 1, 0x0800, 6, 4, op)
            + mac(sender_mac) + socket.inet_aton(sender_ip)
            + mac("00:00:00:00:00:00") + socket.inet_aton(target_ip))


# -- decoding --------------------------------------------------------------

def test_decode_tcp_syn():
    pkt = decode(eth() + ipv4(payload=tcp(dport=443)))
    assert pkt.proto == "tcp"
    assert pkt.src_ip == "10.0.0.1" and pkt.dst_ip == "10.0.0.2"
    assert pkt.dst_port == 443
    assert pkt.is_syn


def test_syn_ack_is_not_a_syn():
    pkt = decode(eth() + ipv4(payload=tcp(flags=0x12)))
    assert not pkt.is_syn


def test_decode_arp():
    pkt = decode(eth(ethertype=0x0806) + arp())
    assert pkt.proto == "arp"
    assert pkt.arp_op == 2
    assert pkt.arp_sender_ip == "10.0.0.1"
    assert pkt.arp_sender_mac == "aa:bb:cc:dd:ee:ff"


def test_decode_vlan_tagged_frame():
    frame = (eth(ethertype=0x8100)[:12] + struct.pack("!H", 0x8100)
             + struct.pack("!H", 0x0064) + struct.pack("!H", 0x0800)
             + ipv4(payload=tcp()))
    pkt = decode(frame)
    assert pkt.proto == "tcp" and pkt.dst_port == 80


def test_decode_dns_query_name():
    pkt = decode(eth() + ipv4(proto=17, payload=udp(payload=dns_query())))
    assert pkt.dns_qname == "tunnel.example.com"


def test_decode_rejects_short_and_truncated_frames():
    assert decode(b"\x00" * 4) is None
    assert decode(eth()) is not None            # header only: still a frame
    truncated = decode(eth() + b"\x45\x00")
    assert truncated is not None and truncated.src_ip == ""


def test_dns_parser_refuses_compression_pointers():
    """A pointer could be made to loop; the parser stops instead of chasing."""
    header = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    pkt = decode(eth() + ipv4(proto=17, payload=udp(payload=header + b"\xc0\x0c")))
    assert pkt.dns_qname == ""


# -- rules -----------------------------------------------------------------

def make(**kwargs):
    return Packet(**kwargs)


def test_port_scan_fires_at_the_threshold():
    engine = rules.RuleEngine(scan_ports=5)
    findings = []
    for port in range(1000, 1005):
        findings += engine.feed(make(proto="tcp", src_ip="10.0.0.9",
                                     dst_ip="10.0.0.1", dst_port=port,
                                     flags=0x02))
    assert [f.rule for f in findings] == ["port_scan"]
    assert findings[0].detail["distinct_ports"] == 5


def test_port_scan_ignores_non_syn():
    engine = rules.RuleEngine(scan_ports=3)
    findings = []
    for port in range(2000, 2010):
        findings += engine.feed(make(proto="tcp", src_ip="10.0.0.9",
                                     dst_ip="10.0.0.1", dst_port=port,
                                     flags=0x10))
    assert findings == []


def test_arp_spoof_on_mac_change():
    engine = rules.RuleEngine()
    engine.feed(make(proto="arp", arp_op=2, arp_sender_ip="10.0.0.1",
                     arp_sender_mac="aa:aa:aa:aa:aa:aa"))
    findings = engine.feed(make(proto="arp", arp_op=2, arp_sender_ip="10.0.0.1",
                                arp_sender_mac="bb:bb:bb:bb:bb:bb"))
    assert [f.rule for f in findings] == ["arp_spoof"]
    assert findings[0].detail["previous_mac"] == "aa:aa:aa:aa:aa:aa"


def test_arp_requests_do_not_fire():
    engine = rules.RuleEngine()
    engine.feed(make(proto="arp", arp_op=1, arp_sender_ip="10.0.0.1",
                     arp_sender_mac="aa:aa:aa:aa:aa:aa"))
    assert engine.feed(make(proto="arp", arp_op=1, arp_sender_ip="10.0.0.1",
                            arp_sender_mac="bb:bb:bb:bb:bb:bb")) == []


def test_smb_relay_needs_multiple_sources():
    engine = rules.RuleEngine(relay_sources=3)
    findings = []
    for i in range(3):
        findings += engine.feed(make(proto="tcp", src_ip=f"10.0.0.{i}",
                                     dst_ip="10.0.0.50", dst_port=445,
                                     flags=0x02))
    assert [f.rule for f in findings] == ["smb_relay"]


def test_suspicious_port_rule():
    engine = rules.RuleEngine()
    findings = engine.feed(make(proto="tcp", src_ip="10.0.0.1",
                                dst_ip="10.0.0.2", dst_port=4444, flags=0x02))
    assert [f.rule for f in findings] == ["nonstandard_port"]
    assert "metasploit" in findings[0].detail["note"]


def test_dns_tunnel_needs_long_labels_and_volume():
    engine = rules.RuleEngine(dns_queries=3, dns_min_label=20)
    short = make(proto="udp", src_ip="10.0.0.5", dns_qname="www.example.com")
    for _ in range(10):
        assert engine.feed(short) == []
    long_name = ("x" * 40) + ".tunnel.example.com"
    findings = []
    for _ in range(3):
        findings += engine.feed(make(proto="udp", src_ip="10.0.0.5",
                                     dns_qname=long_name))
    assert [f.rule for f in findings] == ["dns_tunnel"]


def test_deauth_flood():
    engine = rules.RuleEngine(deauth_count=4)
    findings = []
    for _ in range(4):
        findings += engine.feed(make(proto="dot11", src_mac="aa:bb:cc:00:11:22",
                                     flags=0xDE))
    assert [f.rule for f in findings] == ["deauth_flood"]


def test_repeat_findings_are_suppressed():
    """One noisy scanner should produce one evidence record, not thousands."""
    engine = rules.RuleEngine(scan_ports=3)
    fired = 0
    for round_ in range(4):
        for port in range(round_ * 100, round_ * 100 + 3):
            fired += len(engine.feed(make(proto="tcp", src_ip="10.0.0.9",
                                          dst_ip="10.0.0.1", dst_port=port,
                                          flags=0x02)))
    assert fired == 1


def test_inventory_records_hosts_and_listening_ports():
    engine = rules.RuleEngine()
    engine.feed(make(proto="tcp", src_ip="10.0.0.7", src_mac="aa:bb:cc:00:00:01",
                     dst_ip="10.0.0.1", src_port=22, flags=0x12))
    inventory = engine.inventory()
    assert inventory[0]["ip"] == "10.0.0.7"
    assert 22 in inventory[0]["ports"]


def test_randomised_mac_detection():
    # The locally-administered bit is 0x02 of the first octet.
    assert rules._is_random_mac("00:11:22:33:44:55") is False   # universal (OUI)
    assert rules._is_random_mac("02:11:22:33:44:55") is True    # locally administered
    assert rules._is_random_mac("aa:bb:cc:dd:ee:ff") is True    # 0xaa has 0x02 set
    assert rules._is_random_mac("") is False


def test_rule_state_is_bounded():
    engine = rules.RuleEngine()
    for i in range(engine.MAX_TRACKED_HOSTS + 500):
        engine.feed(make(proto="tcp", src_ip=f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}",
                         dst_ip="10.0.0.1", dst_port=80, flags=0x02))
    assert len(engine.hosts) <= engine.MAX_TRACKED_HOSTS


# -- PCAP ------------------------------------------------------------------

def test_pcap_header_and_rotation(tmp_path):
    path = tmp_path / "cap.pcap"
    writer = PcapWriter(path, snaplen=64, max_bytes=200, keep=3)
    for _ in range(20):
        writer.write(b"\x00" * 60)
    writer.close()
    blob = path.read_bytes()
    magic, major, minor = struct.unpack("<IHH", blob[:8])
    assert magic == PcapWriter.MAGIC and (major, minor) == (2, 4)
    # It rotated rather than growing, and reused files rather than growing the
    # file *count* — that is what bounds disk use on the HDD.
    assert writer.total_rotations > 0
    assert len(list(tmp_path.glob("cap.pcap*"))) <= 3


def test_pcap_truncates_to_snaplen(tmp_path):
    path = tmp_path / "snap.pcap"
    writer = PcapWriter(path, snaplen=32, max_bytes=10 ** 6)
    writer.write(b"\xff" * 500)
    writer.close()
    blob = path.read_bytes()
    caplen, original = struct.unpack("<II", blob[24 + 8:24 + 16])
    assert caplen == 32 and original == 500


# -- diagnostics -----------------------------------------------------------

def test_arp_anomaly_detection():
    from hexbee_netmon import diagnostics

    entries = [{"ip": f"10.0.0.{i}", "mac": "aa:bb:cc:dd:ee:ff"} for i in range(4)]
    entries.append({"ip": "10.0.0.99", "mac": "11:22:33:44:55:66"})
    anomalies = diagnostics.arp_anomalies(entries)
    assert len(anomalies) == 1
    assert anomalies[0]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_ping_of_empty_host_is_unreachable():
    from hexbee_netmon import diagnostics

    result = diagnostics.ping("")
    assert result["reachable"] is False and result["loss_pct"] == 100.0


# -- ping parsing ----------------------------------------------------------
# macOS reports a *reachable* host with no per-reply lines when the wait
# deadline is short, which once made `hexbee-netmon check` raise a severity-3
# gateway_unreachable alert against a gateway answering in 4 ms.

MACOS_PING_NO_REPLY_LINES = """\
PING 192.168.1.254 (192.168.1.254): 56 data bytes

--- 192.168.1.254 ping statistics ---
2 packets transmitted, 2 packets received, 0.0% packet loss, 2 packets out of wait time
round-trip min/avg/max/stddev = 3.256/3.325/3.394/0.069 ms
"""

LINUX_PING_NORMAL = """\
PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=1.20 ms
64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=1.40 ms

--- 10.0.0.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 1.200/1.300/1.400/0.100 ms
"""

UNREACHABLE_PING = """\
PING 10.9.9.9 (10.9.9.9): 56 data bytes

--- 10.9.9.9 ping statistics ---
3 packets transmitted, 0 packets received, 100.0% packet loss
"""


def _ping_with_output(monkeypatch, text):
    from hexbee_netmon import diagnostics
    monkeypatch.setattr(diagnostics, "_run", lambda *a, **k: text)
    return diagnostics.ping("host")


def test_ping_trusts_the_summary_when_there_are_no_reply_lines(monkeypatch):
    result = _ping_with_output(monkeypatch, MACOS_PING_NO_REPLY_LINES)
    assert result["reachable"] is True
    assert result["loss_pct"] == 0.0
    assert result["avg_ms"] == 3.325      # recovered from min/avg/max


def test_ping_parses_per_reply_timings_when_present(monkeypatch):
    result = _ping_with_output(monkeypatch, LINUX_PING_NORMAL)
    assert result["reachable"] is True
    assert result["rtts_ms"] == [1.20, 1.40]
    assert result["avg_ms"] == 1.3
    assert result["loss_pct"] == 0.0


def test_ping_still_reports_a_genuinely_dead_host(monkeypatch):
    result = _ping_with_output(monkeypatch, UNREACHABLE_PING)
    assert result["reachable"] is False
    assert result["loss_pct"] == 100.0


def test_ping_wait_flag_unit_matches_the_platform():
    """BSD ping reads -W as milliseconds, GNU/Linux as seconds."""
    from hexbee_netmon import diagnostics
    expected = "1000" if diagnostics.IS_BSD_PING else "1"
    assert diagnostics._PING_WAIT == expected
