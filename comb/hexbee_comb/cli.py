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

from .pkghint import install_hint


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
    result = scan(target, max_files=args.max_files,
                  yara_rules=args.yara_rules, use_yara=not args.no_yara)
    print(f"  {len(result.files)} files, {len(result.executables)} executables, "
          f"{len(result.mismatches)} mismatches, {len(result.gps_points)} GPS images, "
          f"{len(result.visits)} browser visits")
    if result.yara_status.get("available"):
        print(f"  YARA: {len(result.yara)} match(es) from "
              f"{result.yara_status['rule_files']} rule file(s)")
        for m in result.yara[:20]:
            print(f"    [{m.rule}] {m.path}")
        if len(result.yara) > 20:
            print(f"    … and {len(result.yara) - 20} more")
    else:
        print(f"  YARA: skipped — {result.yara_status.get('reason', 'unavailable')}")

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


def cmd_yara(args) -> int:
    from .yara_scan import DEFAULT_RULE_PATHS, status

    info = status(args.yara_rules)
    print(f"YARA: {'available' if info['available'] else 'unavailable'} — {info['reason']}")
    if info["rules_dir"]:
        print(f"Rules: {info['rule_files']} file(s) in {info['rules_dir']}")
    else:
        print("Searched: " + ", ".join(str(p) for p in DEFAULT_RULE_PATHS))
        print("\nTo add a ruleset offline, copy a bundle onto the external HDD:")
        print("  mkdir -p /mnt/evidence/yara && cp -r <bundle>/*.yar /mnt/evidence/yara/")
        print("  export HEXBEE_YARA_RULES=/mnt/evidence/yara")
    return 0 if info["available"] else 1


def cmd_extract(args) -> int:
    """Pull files out of a disk image without mounting it.

    Mounting an image needs a loop device, which only Linux has. This route
    works everywhere — and it never lets the host operating system touch the
    evidence, which is the safer choice even on Linux.
    """
    from . import tsk
    from .diskimage import parse_partitions

    image = Path(args.image)
    if not image.is_file():
        print(f"No such image: {image}", file=sys.stderr)
        return 1
    if not tsk.recover_available():
        print("Sleuth Kit's tsk_recover is not installed.\n"
              f"  {install_hint('sleuthkit')}", file=sys.stderr)
        return 1

    offset = args.offset
    if offset is None:
        parts = parse_partitions(str(image))
        if not parts:
            offset = 0
            print("No partition table found — treating the image as a single "
                  "filesystem.")
        else:
            print(f"{'#':<3} {'scheme':<6} {'start LBA':<12} {'sectors':<12} type")
            for p in parts:
                print(f"{p.index:<3} {p.scheme:<6} {p.start_lba:<12} "
                      f"{p.sectors:<12} {p.type_name}")
            biggest = max(parts, key=lambda p: p.sectors)
            offset = biggest.start_lba
            print(f"\nUsing partition {biggest.index} (the largest) at sector "
                  f"{offset}. Pass --offset to choose a different one.")

    print(f"\nExtracting from {image} …")
    try:
        result = tsk.recover(str(image), args.out_dir, sector_offset=offset,
                             allocated_only=args.allocated_only)
    except RuntimeError as exc:
        print(f"{exc}", file=sys.stderr)
        return 1

    print(f"Recovered {result['files']} file(s) into {result['output_dir']}"
          + (" (deleted files included)" if result["deleted_included"] else ""))
    print(f"\nNow scan the extraction:\n  hexbee-comb scan {result['output_dir']}")
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
        print("Sleuth Kit (mmls/fls) not found on PATH. Install it with: "
              f"{install_hint('sleuthkit')}", file=sys.stderr)
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
    s.add_argument("--yara-rules", help="YARA rules file or directory "
                                        "(else HEXBEE_YARA_RULES, else the "
                                        "standard kit locations)")
    s.add_argument("--no-yara", action="store_true", help="skip YARA matching")
    s.set_defaults(fn=cmd_scan)

    y = sub.add_parser("yara", help="show YARA capability and ruleset location")
    y.add_argument("--yara-rules")
    y.set_defaults(fn=cmd_yara)

    ex = sub.add_parser("extract", help="pull files out of a disk image "
                                        "without mounting it (works on macOS "
                                        "and Windows too)")
    ex.add_argument("image")
    ex.add_argument("out_dir", help="where to write the recovered files")
    ex.add_argument("--offset", type=int,
                    help="partition start in sectors (default: the largest "
                         "partition found)")
    ex.add_argument("--allocated-only", action="store_true",
                    help="skip deleted files (they are recovered by default)")
    ex.set_defaults(fn=cmd_extract)

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
