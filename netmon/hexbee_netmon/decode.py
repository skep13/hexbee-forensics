"""Header-only packet decoding.

Deliberately stdlib-only and deliberately shallow. The Pi 3B+ has 1 GB of RAM
with the Hive already using a third of it, so Netmon:

  * decodes fixed-offset headers with `struct` instead of importing scapy
    (scapy costs roughly 80 MB resident before a single packet arrives),
  * never retains packet bodies — a decoded packet is a small dataclass of
    scalars, and the original buffer is released immediately,
  * stops at layer 4. No deep packet inspection, no reassembly, no flow
    tracking beyond counters.

scapy is still supported as an optional capture backend (see `capture.py`) for
802.11 monitor-mode work, which raw AF_PACKET cannot give us.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_IPV6 = 0x86DD
ETH_P_VLAN = 0x8100

PROTO_ICMP, PROTO_TCP, PROTO_UDP = 1, 6, 17
PROTO_NAMES = {PROTO_ICMP: "icmp", PROTO_TCP: "tcp", PROTO_UDP: "udp"}

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


@dataclass
class Packet:
    """One decoded frame. Scalars only — no payload is retained."""

    src_mac: str = ""
    dst_mac: str = ""
    ethertype: int = 0
    src_ip: str = ""
    dst_ip: str = ""
    proto: str = ""
    src_port: int = 0
    dst_port: int = 0
    flags: int = 0
    length: int = 0
    # ARP specifics
    arp_op: int = 0
    arp_sender_ip: str = ""
    arp_sender_mac: str = ""
    arp_target_ip: str = ""
    # A DNS query name, when one was cheap to read (used by the tunnel rule).
    dns_qname: str = ""

    @property
    def is_syn(self) -> bool:
        return bool(self.flags & TCP_SYN) and not (self.flags & TCP_ACK)


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _ipv4(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def decode(frame: bytes) -> Packet | None:
    """Decode an Ethernet frame. Returns None for anything unparseable."""
    if len(frame) < 14:
        return None
    pkt = Packet(length=len(frame))
    pkt.dst_mac = _mac(frame[0:6])
    pkt.src_mac = _mac(frame[6:12])
    ethertype = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    if ethertype == ETH_P_VLAN:
        if len(frame) < 18:
            return pkt
        ethertype = struct.unpack("!H", frame[16:18])[0]
        offset = 18
    pkt.ethertype = ethertype

    if ethertype == ETH_P_ARP:
        _decode_arp(frame, offset, pkt)
        return pkt
    if ethertype == ETH_P_IP:
        _decode_ipv4(frame, offset, pkt)
        return pkt
    if ethertype == ETH_P_IPV6:
        # IPv6 is recorded at layer 3 only; the kit's engagements are IPv4.
        pkt.proto = "ipv6"
        return pkt
    return pkt


def _decode_arp(frame: bytes, offset: int, pkt: Packet) -> None:
    if len(frame) < offset + 28:
        return
    body = frame[offset:offset + 28]
    hlen, plen = body[4], body[5]
    if hlen != 6 or plen != 4:
        return
    pkt.proto = "arp"
    pkt.arp_op = struct.unpack("!H", body[6:8])[0]
    pkt.arp_sender_mac = _mac(body[8:14])
    pkt.arp_sender_ip = _ipv4(body[14:18])
    pkt.arp_target_ip = _ipv4(body[24:28])


def _decode_ipv4(frame: bytes, offset: int, pkt: Packet) -> None:
    if len(frame) < offset + 20:
        return
    vihl = frame[offset]
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(frame) < offset + ihl:
        return
    proto_num = frame[offset + 9]
    pkt.src_ip = _ipv4(frame[offset + 12:offset + 16])
    pkt.dst_ip = _ipv4(frame[offset + 16:offset + 20])
    pkt.proto = PROTO_NAMES.get(proto_num, str(proto_num))
    l4 = offset + ihl

    if proto_num == PROTO_TCP and len(frame) >= l4 + 20:
        pkt.src_port, pkt.dst_port = struct.unpack("!HH", frame[l4:l4 + 4])
        pkt.flags = frame[l4 + 13]
    elif proto_num == PROTO_UDP and len(frame) >= l4 + 8:
        pkt.src_port, pkt.dst_port = struct.unpack("!HH", frame[l4:l4 + 4])
        if pkt.dst_port == 53 or pkt.src_port == 53:
            pkt.dns_qname = _dns_qname(frame, l4 + 8)


def _dns_qname(frame: bytes, dns_start: int, max_labels: int = 16) -> str:
    """Read the first question name out of a DNS message.

    Compression pointers are not followed — a query's first QNAME is always
    literal, and refusing to chase pointers means a malformed packet cannot
    make us loop.
    """
    if len(frame) < dns_start + 12:
        return ""
    pos = dns_start + 12
    labels: list[str] = []
    for _ in range(max_labels):
        if pos >= len(frame):
            return ""
        n = frame[pos]
        if n == 0:
            break
        if n & 0xC0:            # compression pointer: stop
            return ""
        pos += 1
        if pos + n > len(frame):
            return ""
        labels.append(frame[pos:pos + n].decode("ascii", errors="replace"))
        pos += n
    return ".".join(labels)[:253]
