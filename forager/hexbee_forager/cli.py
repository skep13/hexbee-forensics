"""hexbee-forager — autonomous live-response forensic collector.

    hexbee-forager collect                     one-shot triage, ship to Hive
    hexbee-forager collect --output run.json   save locally instead of shipping
    hexbee-forager watch --interval 60         continuous monitoring
    hexbee-forager status                      show config + spool backlog
    hexbee-forager config --hive URL --key K   write a config file for unattended runs

Hive location auto-discovered from --hive/--key, then HEXBEE_HIVE_URL /
HEXBEE_INGEST_KEY, then ~/.hexbee-forager.json or /etc/hexbee/forager.json.
With no Hive reachable, events spool locally and flush on the next run.

Authorized forensic collection only. This agent is read-only: it inspects the
host, it never modifies it.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import __version__
from .agent import CONFIG_PATHS, Forager, discover_config


def _banner() -> None:
    print(f"HexBee Forager {__version__} — authorized forensic collection (read-only)",
          file=sys.stderr)


def _default_spool() -> Path:
    """Where to buffer events when the Hive is unreachable.

    When frozen into an executable (e.g. run from a USB stick), keep the spool
    *beside the executable* — i.e. on the USB — so no evidence is left on the
    target's own disk.
    """
    import os
    import sys

    env = os.environ.get("HEXBEE_SPOOL_DIR")
    if env:
        return Path(env)
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "collections" / "spool"
    return Path.home() / ".hexbee-forager" / "spool"


def _make(args) -> Forager:
    cfg = discover_config(getattr(args, "hive", None), getattr(args, "key", None))
    spool = Path(args.spool) if getattr(args, "spool", None) else _default_spool()
    return Forager(cfg["hive_url"], cfg["ingest_key"], spool_dir=spool)


def cmd_collect(args) -> int:
    _banner()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    forager = _make(args)
    if args.output:
        events = forager.collect(volatile_only=False)
        Path(args.output).write_text(json.dumps(events, indent=2), encoding="utf-8")
        print(f"{len(events)} events written to {args.output}")
        return 0
    result = forager.run_once()
    print(f"Collected {result['collected']} events -> "
          f"shipped {result.get('shipped', 0)}, "
          f"spooled {result.get('spooled', 0)}"
          + (f", flushed {result['flushed_from_spool']} from spool"
             if result.get("flushed_from_spool") else ""))
    if result.get("reason"):
        print(f"  note: {result['reason']} — events spooled at {result.get('spool_file')}")
    return 0


def cmd_watch(args) -> int:
    _banner()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    forager = _make(args)
    if not (forager.hive_url and forager.ingest_key):
        print("watch mode needs a Hive; events will spool locally until one is "
              "configured. Configure with `hexbee-forager config`.", file=sys.stderr)
    forager.watch(interval=args.interval, full_every=args.full_every)
    return 0


def cmd_status(args) -> int:
    forager = _make(args)
    spooled = list(forager.spool_dir.glob("*.jsonl"))
    backlog = sum(sum(1 for _ in open(p, encoding="utf-8")) for p in spooled)
    print(f"device:     {forager.device}")
    print(f"hive:       {forager.hive_url or '(none configured)'}")
    print(f"ingest key: {'set' if forager.ingest_key else '(none)'}")
    print(f"spool dir:  {forager.spool_dir}")
    print(f"spool backlog: {len(spooled)} file(s), ~{backlog} event(s)")
    from .collectors import HAVE_PSUTIL
    print(f"psutil:     {'available (rich process/network data)' if HAVE_PSUTIL else 'not installed (native fallback)'}")
    return 0


def cmd_submit(args) -> int:
    """Upload one or more previously-saved collections (from `collect
    --output`) into the Hive. This is the offline USB workflow: capture on the
    target to the stick, then submit later from a networked machine."""
    _banner()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    forager = _make(args)
    if not (forager.hive_url and forager.ingest_key):
        print("submit needs a Hive: pass --hive/--key or set HEXBEE_HIVE_URL / "
              "HEXBEE_INGEST_KEY.", file=sys.stderr)
        return 1
    total = 0
    for f in args.files:
        try:
            data = json.loads(Path(f).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"{f}: skipped ({exc})", file=sys.stderr)
            continue
        events = data if isinstance(data, list) else data.get("events", [])
        res = forager.ship(events)
        total += res.get("shipped", 0)
        print(f"{f}: shipped {res.get('shipped', 0)}, spooled {res.get('spooled', 0)}")
    print(f"total shipped: {total}")
    return 0


def cmd_config(args) -> int:
    path = Path(args.path) if args.path else CONFIG_PATHS[0]
    data = {"hive_url": args.hive, "ingest_key": args.key}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    print(f"Wrote config to {path}. The agent can now run unattended.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="hexbee-forager",
                                description="HexBee autonomous forensic collector")
    p.add_argument("--hive", help="Hive base URL (else env/config)")
    p.add_argument("--key", help="Hive ingest key (else env/config)")
    p.add_argument("--spool", help="offline spool directory (default: beside the "
                   "executable when run from USB, else the user home)")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect", help="one-shot triage collection")
    c.add_argument("-o", "--output", help="write events to a JSON file instead of shipping")
    c.set_defaults(fn=cmd_collect)

    w = sub.add_parser("watch", help="continuous monitoring")
    w.add_argument("--interval", type=int, default=60, help="seconds between samples")
    w.add_argument("--full-every", type=int, default=30, help="full sweep every N cycles")
    w.set_defaults(fn=cmd_watch)

    s = sub.add_parser("status", help="show config and spool backlog")
    s.set_defaults(fn=cmd_status)

    sm = sub.add_parser("submit", help="upload saved collection JSON files to the Hive")
    sm.add_argument("files", nargs="+", help="JSON files from `collect --output`")
    sm.set_defaults(fn=cmd_submit)

    cf = sub.add_parser("config", help="write a config file for unattended runs")
    cf.add_argument("--hive", required=True)
    cf.add_argument("--key", required=True)
    cf.add_argument("--path", help="config file path (default ~/.hexbee-forager.json)")
    cf.set_defaults(fn=cmd_config)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
