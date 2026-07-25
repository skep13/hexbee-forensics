# HexBee Netmon

Passive network monitoring for the Hive host. Netmon is the answer to the one
thing the rest of HexBee could not see: the network itself.

```bash
pipx install ./netmon          # or: pip install -e ./netmon
hexbee-netmon config --hive http://127.0.0.1:8080 --key "$HEXBEE_INGEST_KEY"
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(which python3)")"
hexbee-netmon run --mode ids --iface eth0
```

Findings POST to the Hive's `/api/v1/ingest`, so they land in the same
hash-chained evidence log and the same dashboard timeline as forensic
artifacts, and the ATT&CK tagger maps each rule to a technique.

## Modes

| Mode | Transmits? | What it does |
|---|---|---|
| `ids` | no | Passive detection only. Port scans, ARP spoofing, SMB relay/poisoning, DNS tunnelling, suspicious destination ports, 802.11 deauth floods (monitor mode). |
| `recon` | no | Passive inventory: every MAC, IP, and listening service observed, with randomised-MAC flagging. One event per host, not per packet. |
| `diagnostics` | yes | Gateway latency and loss, DNS resolution health, route hop count, ARP table anomalies. Probes the host's own gateway and resolvers. |

## Why it is not built on scapy

The recommendation that produced this module budgeted ~80 MB for scapy on a
1 GB Pi that is already running the Hive. The default backend here is a
stdlib `AF_PACKET` socket with a hand-written header decoder instead:

* no dependency, no import cost — resident set stays in single-digit MB;
* a 256-byte snaplen means payloads are never even copied out of the kernel;
* decoding stops at layer 4 — no reassembly, no flow tracking, no DPI;
* all rule state is explicitly bounded and trimmed every 30 seconds.

scapy is still an optional extra (`pip install 'hexbee-netmon[wireless]'`) and
is required for one thing only: 802.11 monitor mode, which `AF_PACKET` cannot
provide.

## PCAP

`--pcap /mnt/evidence/capture.pcap` streams frames straight to disk with
64 MB rotation and a bounded number of files. Point it at the external HDD.
Nothing beyond the current frame is ever held in memory, and Netmon never
reads a capture file back.

## Detection rules

| Rule | Fires when | ATT&CK |
|---|---|---|
| `port_scan` | one source SYNs 20+ distinct ports in 60 s | T1046 |
| `arp_spoof` | an IP's ARP reply changes MAC | T1557.002 |
| `smb_relay` | 3+ distinct sources open 445/139 to one host in 120 s | T1557.001 |
| `dns_tunnel` | 40+ long-label DNS queries from one source in 60 s | T1071 |
| `nonstandard_port` | SYN to a known backdoor/remote-access port | T1571 |
| `deauth_flood` | 20+ 802.11 deauth frames in 30 s (monitor mode) | T1498 |
| `gateway_unreachable` / `gateway_latency` / `dns_failure` / `dns_slow` / `arp_anomaly` | diagnostics mode | — |

Repeat findings are suppressed for 120 s per (rule, source, target), so a
noisy scanner produces one evidence record rather than thousands.

## Running as a service

`hexbee-netmon.service` runs it under systemd with `CAP_NET_RAW` only,
`ProtectSystem=strict`, and `MemoryMax=192M` so it can never crowd out the
Hive on the Pi.

## Limitations

* Raw capture is Linux-only (`AF_PACKET`). On Windows/macOS use
  `--backend scapy` with a capture driver installed.
* Capture sees only what reaches the interface. On a switched network without
  a SPAN/mirror port or an inline tap, that is broadcast, multicast, and the
  Pi's own traffic — enough for ARP spoofing, DHCP, mDNS, and broadcast-based
  discovery, but not another host's unicast sessions.
* 802.11 rules need an adapter already placed in monitor mode. The Pi 3B+'s
  onboard `brcmfmac` radio cannot do monitor mode reliably; use a supported
  USB adapter.
* Detection is header-only by design. Anything requiring payload inspection
  (TLS fingerprinting, protocol decoding, file extraction) is out of scope for
  this hardware.
