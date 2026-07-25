"""Packet sources and streaming PCAP output.

Two backends:

  * `RawSocketCapture` (default) — Linux AF_PACKET, stdlib only, needs
    CAP_NET_RAW. This is what runs on the Pi: no dependencies and a flat
    memory profile.
  * `ScapyCapture` (optional) — only worth its ~80 MB when you need 802.11
    monitor mode, which AF_PACKET cannot provide.

`PcapWriter` streams frames straight to disk with size-based rotation. It is
opt-in (`--pcap`), it should point at the external HDD, and it never holds
more than one frame in memory.
"""

from __future__ import annotations

import logging
import socket
import struct
import time
from pathlib import Path

from .decode import Packet, decode

log = logging.getLogger("hexbee.netmon.capture")

ETH_P_ALL = 0x0003
# Only the headers are needed; a short snaplen keeps copies cheap and makes
# an accidental full-payload capture impossible.
DEFAULT_SNAPLEN = 256


class CaptureError(RuntimeError):
    pass


class RawSocketCapture:
    """Promiscuous AF_PACKET capture. Yields decoded packets, one at a time."""

    def __init__(self, iface: str | None = None, snaplen: int = DEFAULT_SNAPLEN,
                 pcap: "PcapWriter | None" = None):
        self.iface = iface
        self.snaplen = snaplen
        self.pcap = pcap
        self._sock: socket.socket | None = None
        self.dropped = 0
        self.seen = 0

    def open(self) -> None:
        if not hasattr(socket, "AF_PACKET"):
            raise CaptureError(
                "raw capture needs Linux AF_PACKET. On Windows/macOS install "
                "scapy plus a capture driver and pass --backend scapy.")
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(ETH_P_ALL))
        except PermissionError as exc:
            raise CaptureError(
                "permission denied opening a raw socket. Either run as root or "
                "grant the capability once:\n"
                "  sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f "
                "$(which python3))") from exc
        if self.iface:
            try:
                sock.bind((self.iface, 0))
            except OSError as exc:
                sock.close()
                raise CaptureError(f"cannot bind to {self.iface}: {exc}") from exc
        # Small buffer on purpose: under a flood we would rather drop frames
        # than let the kernel queue grow on a 1 GB host.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 512 * 1024)
        sock.settimeout(1.0)
        self._sock = sock

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def packets(self, stop_event=None):
        """Generator of decoded packets. Runs until `stop_event` is set."""
        if self._sock is None:
            self.open()
        while stop_event is None or not stop_event.is_set():
            try:
                frame = self._sock.recv(self.snaplen)
            except socket.timeout:
                continue
            except OSError as exc:
                log.warning("capture read error: %s", exc)
                continue
            self.seen += 1
            if self.pcap is not None:
                self.pcap.write(frame)
            pkt = decode(frame)
            if pkt is None:
                self.dropped += 1
                continue
            yield pkt


class ScapyCapture:
    """Optional scapy backend — used for 802.11 monitor mode."""

    def __init__(self, iface: str | None = None, monitor: bool = False,
                 pcap: "PcapWriter | None" = None):
        self.iface = iface
        self.monitor = monitor
        self.pcap = pcap
        self.seen = 0
        self.dropped = 0
        self._sniffer = None

    def open(self) -> None:
        try:
            import scapy.all  # noqa: F401
        except ImportError as exc:
            raise CaptureError(
                "scapy is not installed. `pip install scapy` (adds ~80 MB "
                "resident — only do this on the Pi if you need monitor mode)."
            ) from exc

    def packets(self, stop_event=None):
        from scapy.all import Dot11, Dot11Deauth, sniff  # type: ignore

        self.open()
        queue: list[Packet] = []

        def handle(frame) -> None:
            self.seen += 1
            if self.pcap is not None:
                try:
                    self.pcap.write(bytes(frame))
                except Exception:
                    pass
            pkt = Packet(length=len(frame))
            if self.monitor and frame.haslayer(Dot11):
                dot11 = frame.getlayer(Dot11)
                pkt.proto = "dot11"
                pkt.src_mac = (dot11.addr2 or "").lower()
                pkt.dst_mac = (dot11.addr1 or "").lower()
                if frame.haslayer(Dot11Deauth):
                    pkt.flags = 0xDE  # marker consumed by the deauth rule
            else:
                decoded = decode(bytes(frame))
                if decoded is None:
                    self.dropped += 1
                    return
                pkt = decoded
            queue.append(pkt)

        while stop_event is None or not stop_event.is_set():
            sniff(iface=self.iface, prn=handle, store=False, timeout=2,
                  monitor=self.monitor or None)
            while queue:
                yield queue.pop(0)

    def close(self) -> None:
        return None


class PcapWriter:
    """Streaming libpcap writer with size-based rotation.

    Point this at the external HDD. Rotation keeps any single file small
    enough to move, and nothing beyond the current frame is ever in memory.
    """

    MAGIC = 0xA1B2C3D4

    def __init__(self, path: str | Path, snaplen: int = DEFAULT_SNAPLEN,
                 max_bytes: int = 64 * 1024 * 1024, keep: int = 8):
        self.base = Path(path)
        self.snaplen = snaplen
        self.max_bytes = max_bytes
        self.keep = keep
        self.written = 0
        self.rotations = 0          # index of the current file; wraps at `keep`
        self.total_rotations = 0    # lifetime count, for status reporting
        self._fh = None
        self._open()

    def _open(self) -> None:
        self.base.parent.mkdir(parents=True, exist_ok=True)
        suffix = f".{self.rotations}" if self.rotations else ""
        self._path = self.base.with_name(self.base.name + suffix)
        self._fh = open(self._path, "wb", buffering=64 * 1024)
        self._fh.write(struct.pack("<IHHiIII", self.MAGIC, 2, 4, 0, 0,
                                   self.snaplen, 1))
        self.written = 24

    def write(self, frame: bytes) -> None:
        if self._fh is None:
            return
        now = time.time()
        caplen = min(len(frame), self.snaplen)
        self._fh.write(struct.pack("<IIII", int(now), int((now % 1) * 1_000_000),
                                   caplen, len(frame)))
        self._fh.write(frame[:caplen])
        self.written += 16 + caplen
        if self.written >= self.max_bytes:
            self.rotate()

    def rotate(self) -> None:
        self.close()
        self.total_rotations += 1
        self.rotations += 1
        if self.keep and self.rotations >= self.keep:
            self.rotations = 0  # wrap: bounded disk use, oldest file reused
        self._open()

    def close(self) -> None:
        if self._fh is not None:
            self._fh.flush()
            self._fh.close()
            self._fh = None


def make_capture(backend: str, iface: str | None, monitor: bool,
                 pcap_path: str | None):
    writer = PcapWriter(pcap_path) if pcap_path else None
    if backend == "scapy" or monitor:
        return ScapyCapture(iface, monitor=monitor, pcap=writer)
    return RawSocketCapture(iface, pcap=writer)
