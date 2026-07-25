"""hexbee-netmon — passive network monitoring for the Hive host.

    hexbee-netmon run --mode ids           passive detection, alerts only
    hexbee-netmon run --mode recon         inventory MACs / IPs / services
    hexbee-netmon run --mode diagnostics   latency, DNS, routes, ARP table
    hexbee-netmon check                    one-shot diagnostics to stdout
    hexbee-netmon status                   config, capability, spool backlog

Hive location comes from --hive/--key, then HEXBEE_HIVE_URL /
HEXBEE_INGEST_KEY, then ~/.hexbee-netmon.json. With no Hive reachable,
findings spool locally and flush on the next run.

ids and recon are passive: they receive, they never transmit. diagnostics
does transmit (ping / DNS / traceroute) and is aimed at the host's own
gateway and resolvers.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .agent import MODES, NetMon
from .capture import CaptureError

CONFIG_PATHS = [Path.home() / ".hexbee-netmon.json", Path("/etc/hexbee/netmon.json")]


def discover_config(hive: str | None, key: str | None) -> dict:
    cfg = {"hive_url": hive or os.environ.get("HEXBEE_HIVE_URL"),
           "ingest_key": key or os.environ.get("HEXBEE_INGEST_KEY")}
    if not (cfg["hive_url"] and cfg["ingest_key"]):
        for path in CONFIG_PATHS:
            if path.is_file():
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                cfg["hive_url"] = cfg["hive_url"] or data.get("hive_url")
                cfg["ingest_key"] = cfg["ingest_key"] or data.get("ingest_key")
    return cfg


def _make(args) -> NetMon:
    cfg = discover_config(getattr(args, "hive", None), getattr(args, "key", None))
    return NetMon(cfg["hive_url"], cfg["ingest_key"],
                  mode=getattr(args, "mode", "ids"),
                  iface=getattr(args, "iface", None),
                  device=getattr(args, "device", None),
                  backend=getattr(args, "backend", "raw"),
                  monitor=getattr(args, "monitor", False),
                  pcap=getattr(args, "pcap", None))


def cmd_run(args) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    mon = _make(args)
    print(f"HexBee Netmon {__version__} — mode={mon.mode} "
          f"iface={mon.iface or 'any'} device={mon.device}", file=sys.stderr)
    if mon.mode != "diagnostics":
        print("Passive capture: receiving only, nothing is transmitted.",
              file=sys.stderr)
    if not (mon.hive_url and mon.ingest_key):
        print("No Hive configured — findings will spool to "
              f"{mon.spool_dir}", file=sys.stderr)
    try:
        if mon.mode == "diagnostics":
            result = mon.run_diagnostics(args.duration, interval=args.interval,
                                         targets=tuple(args.target or ()))
        else:
            result = mon.run_capture(args.duration)
    except CaptureError as exc:
        print(f"Capture unavailable: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0
    print(json.dumps(result, indent=2))
    return 0


def cmd_check(args) -> int:
    """One-shot diagnostics printed locally — no Hive needed."""
    from .diagnostics import snapshot

    payload, alerts = snapshot(tuple(args.target or ()))
    gw = payload["gateway_ping"]
    print(f"Gateway:   {payload['gateway'] or '(none found)'}  "
          f"{'reachable' if gw['reachable'] else 'UNREACHABLE'}"
          + (f"  avg {gw['avg_ms']} ms  loss {gw['loss_pct']}%" if gw['reachable'] else ""))
    print(f"Resolvers: {', '.join(payload['resolvers']) or '(none)'}")
    for check in payload["dns_health"]:
        state = "ok" if check["ok"] else "FAILED"
        print(f"  DNS {check['name']:<28} {state:<7} {check['ms']} ms")
    print(f"ARP table: {payload['arp_entries']} entries   "
          f"route hops to gateway: {payload['route_hops']}")
    if alerts:
        print("\nAlerts:")
        for a in alerts:
            print(f"  [{a['severity']}] {a['rule']}: {a['summary']}")
    else:
        print("\nNo alerts.")
    return 0


def cmd_status(args) -> int:
    mon = _make(args)
    spooled = list(mon.spool_dir.glob("*.jsonl"))
    backlog = sum(sum(1 for _ in open(p, encoding="utf-8")) for p in spooled)
    print(f"netmon:     {__version__}")
    print(f"device:     {mon.device}")
    print(f"hive:       {mon.hive_url or '(none configured)'}")
    print(f"ingest key: {'set' if mon.ingest_key else '(none)'}")
    print(f"spool:      {mon.spool_dir}  ({len(spooled)} file(s), ~{backlog} event(s))")

    import socket as _socket
    if hasattr(_socket, "AF_PACKET"):
        try:
            s = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW,
                               _socket.htons(3))
            s.close()
            print("raw capture: available")
        except PermissionError:
            print("raw capture: needs privileges — sudo setcap "
                  "cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))")
        except OSError as exc:
            print(f"raw capture: unavailable ({exc})")
    else:
        print("raw capture: unavailable (AF_PACKET is Linux-only) — "
              "use --backend scapy on other platforms")
    try:
        import scapy  # noqa: F401
        print("scapy:      installed (802.11 monitor mode available)")
    except ImportError:
        print("scapy:      not installed (not required for ids/recon/diagnostics)")
    return 0


def cmd_config(args) -> int:
    path = Path(args.path) if args.path else CONFIG_PATHS[0]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"hive_url": args.hive, "ingest_key": args.key},
                               indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    print(f"Wrote config to {path}.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="hexbee-netmon",
                                description="HexBee passive network monitor")
    p.add_argument("--hive", help="Hive base URL (else env/config)")
    p.add_argument("--key", help="Hive ingest key (else env/config)")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run a monitoring mode")
    r.add_argument("--mode", choices=MODES, default="ids")
    r.add_argument("--iface", help="interface to capture on (default: all)")
    r.add_argument("--device", help="device name for Hive events")
    r.add_argument("--backend", choices=("raw", "scapy"), default="raw",
                   help="raw = stdlib AF_PACKET (default, low memory); "
                        "scapy = needed only for 802.11 monitor mode")
    r.add_argument("--monitor", action="store_true",
                   help="802.11 monitor mode (implies --backend scapy and a "
                        "capable adapter already in monitor mode)")
    r.add_argument("--pcap", help="stream raw frames to this file (put it on "
                                  "the external HDD; rotates at 64 MB)")
    r.add_argument("--duration", type=int, help="stop after N seconds")
    r.add_argument("--interval", type=int, default=300,
                   help="diagnostics mode: seconds between snapshots")
    r.add_argument("--target", action="append",
                   help="diagnostics mode: extra name to resolve/probe")
    r.set_defaults(fn=cmd_run)

    c = sub.add_parser("check", help="one-shot diagnostics, printed locally")
    c.add_argument("--target", action="append")
    c.set_defaults(fn=cmd_check)

    s = sub.add_parser("status", help="config and capture capability")
    s.set_defaults(fn=cmd_status)

    cf = sub.add_parser("config", help="write a config file for unattended runs")
    cf.add_argument("--hive", required=True)
    cf.add_argument("--key", required=True)
    cf.add_argument("--path")
    cf.set_defaults(fn=cmd_config)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
