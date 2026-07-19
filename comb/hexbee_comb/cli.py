"""hexbee-comb — forensic triage from the Queen.

    hexbee-comb scan TARGET [-o report.html] [--json out.json] [--max-files N]
                     [--hive URL --key INGEST_KEY --device Comb01]
    hexbee-comb carve IMAGE OUT_DIR
    hexbee-comb partitions IMAGE
    hexbee-comb tsk-ls IMAGE [--offset SECTORS]

`scan` walks a mounted image / extraction directory; with --hive the
findings are pushed into the Hive's hash-chained evidence log and show up
correlated on the dashboard (GPS images land on the offline map).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def cmd_scan(args) -> int:
    from .analysis import render_report, result_to_json, scan, to_hive_events, upload

    target = Path(args.target)
    if not target.exists():
        print(f"No such target: {target}", file=sys.stderr)
        return 1
    if target.is_file():
        print("Target is a file — for raw images use `partitions`/`carve`/`tsk-ls`, "
              "or mount it and scan the mount point.", file=sys.stderr)
        return 1

    print(f"Scanning {target} …")
    result = scan(target, max_files=args.max_files)
    print(f"  {len(result.files)} files, {len(result.executables)} executables, "
          f"{len(result.mismatches)} mismatches, {len(result.gps_points)} GPS images, "
          f"{len(result.visits)} browser visits")

    if args.output:
        Path(args.output).write_text(render_report(result), encoding="utf-8")
        print(f"Report: {args.output}")
    if args.json:
        Path(args.json).write_text(result_to_json(result), encoding="utf-8")
        print(f"JSON: {args.json}")

    if args.hive:
        if not args.key:
            print("--hive requires --key (the Hive's ingest key)", file=sys.stderr)
            return 1
        events = to_hive_events(result, device=args.device)
        summary = upload(events, args.hive, args.key)
        print(f"Uploaded {summary.get('stored', 0)} events to {args.hive}")
        if summary.get("errors"):
            print(f"  rejected: {summary['errors']}", file=sys.stderr)
    return 0


def cmd_carve(args) -> int:
    from .carver import carve

    results = carve(args.image, args.out_dir)
    for r in results:
        print(f"{r.kind:<7} offset={r.offset:<12} size={r.size:<10} {r.path}")
    print(f"{len(results)} file(s) carved into {args.out_dir}")
    return 0


def cmd_partitions(args) -> int:
    from .diskimage import parse_partitions

    parts = parse_partitions(args.image)
    if not parts:
        print("No partition table found (superfloppy or unknown format).")
        return 0
    print(f"{'#':<3} {'scheme':<6} {'start LBA':<12} {'sectors':<12} type")
    for p in parts:
        boot = " *" if p.bootable else ""
        print(f"{p.index:<3} {p.scheme:<6} {p.start_lba:<12} {p.sectors:<12} "
              f"{p.type_name}{boot}")
    return 0


def cmd_tsk_ls(args) -> int:
    from . import tsk

    if not tsk.available():
        print("Sleuth Kit (mmls/fls) not found on PATH. On Kali: "
              "sudo apt install sleuthkit", file=sys.stderr)
        return 1
    entries = tsk.list_files(args.image, args.offset)
    for e in entries:
        flag = " (deleted)" if e.deleted else ""
        print(f"{e.size:<12} {e.path}{flag}")
    print(f"{len(entries)} entries")
    return 0


def cmd_serve(args) -> int:
    import os

    from .webui import serve

    serve(args.host, args.port, defaults={
        "hive": args.hive or os.environ.get("HEXBEE_HIVE_URL", ""),
        "key": args.key or os.environ.get("HEXBEE_INGEST_KEY", ""),
        "device": "Comb01"})
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="hexbee-comb",
                                description="HexBee forensic triage toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="inventory + artifacts from a directory/mount")
    s.add_argument("target")
    s.add_argument("-o", "--output", help="write HTML report here")
    s.add_argument("--json", help="write full JSON results here")
    s.add_argument("--max-files", type=int)
    s.add_argument("--hive", help="Hive base URL to upload findings to")
    s.add_argument("--key", help="Hive ingest key")
    s.add_argument("--device", default="Comb01", help="device name for uploaded events")
    s.set_defaults(fn=cmd_scan)

    c = sub.add_parser("carve", help="carve files out of a raw image")
    c.add_argument("image")
    c.add_argument("out_dir")
    c.set_defaults(fn=cmd_carve)

    pt = sub.add_parser("partitions", help="show MBR/GPT partition table")
    pt.add_argument("image")
    pt.set_defaults(fn=cmd_partitions)

    t = sub.add_parser("tsk-ls", help="list files in an image via Sleuth Kit")
    t.add_argument("image")
    t.add_argument("--offset", type=int, default=0, help="partition start in sectors")
    t.set_defaults(fn=cmd_tsk_ls)

    sv = sub.add_parser("serve", help="point-and-click web UI (no commands)")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8091)
    sv.add_argument("--hive", help="prefill Hive URL in the UI")
    sv.add_argument("--key", help="prefill Hive ingest key in the UI")
    sv.set_defaults(fn=cmd_serve)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
