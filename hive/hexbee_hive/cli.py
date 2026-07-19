"""hexbee-hive command line.

    hexbee-hive init                          create the database
    hexbee-hive engine                        run the MQTT ingest engine
    hexbee-hive web                           run the dashboard/API server
    hexbee-hive user add <name> <role>        create a user (prompts for password)
    hexbee-hive user disable <name>
    hexbee-hive verify                        verify the evidence hash chain
    hexbee-hive correlate                     backfill correlation over old events
    hexbee-hive report <case_id> [--format html|json|csv] [-o FILE]
"""

from __future__ import annotations

import argparse
import getpass
import logging
import sys

from .config import load_config
from .db import Database


def _open_db():
    cfg = load_config()
    return cfg, Database(cfg.db_path)


def cmd_init(_args) -> int:
    cfg, db = _open_db()
    db.close()
    print(f"Database initialized at {cfg.db_path}")
    return 0


def cmd_engine(_args) -> int:
    from .correlate import Correlator
    from .ingest import MqttIngest

    cfg, db = _open_db()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    ingest = MqttIngest(cfg, db, Correlator(db, cfg.correlation_window_seconds))
    try:
        ingest.run_forever()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_web(_args) -> int:
    from .api import create_app

    cfg, db = _open_db()
    logging.basicConfig(level=logging.INFO)
    app = create_app(cfg, db)
    # Werkzeug's threaded server is adequate for a small analyst team on a
    # Pi 3B+; swap in waitress/gunicorn behind a reverse proxy if needed.
    app.run(host=cfg.web_host, port=cfg.web_port, threaded=True)
    return 0


def cmd_user_add(args) -> int:
    from .auth import create_user

    cfg, db = _open_db()
    password = getpass.getpass(f"Password for {args.username}: ")
    confirm = getpass.getpass("Confirm: ")
    if password != confirm:
        print("Passwords do not match.", file=sys.stderr)
        return 1
    try:
        create_user(db, args.username, password, args.role, actor="cli",
                    min_length=cfg.min_password_length)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"User {args.username} ({args.role}) created.")
    return 0


def cmd_user_disable(args) -> int:
    from .auth import set_user_disabled

    _, db = _open_db()
    if set_user_disabled(db, args.username, True, actor="cli"):
        print(f"User {args.username} disabled and tokens revoked.")
        return 0
    print("No such user.", file=sys.stderr)
    return 1


def cmd_verify(_args) -> int:
    from .integrity import verify_chain

    _, db = _open_db()
    result = verify_chain(db)
    if result["ok"]:
        print(f"OK — hash chain verified over {result['checked']} events.")
        return 0
    print(f"FAILED — chain breaks at event id {result['first_bad_id']} "
          f"(checked {result['checked']}).", file=sys.stderr)
    return 2


def cmd_correlate(_args) -> int:
    from .correlate import backfill

    cfg, db = _open_db()
    total = backfill(db, cfg.correlation_window_seconds)
    print(f"Correlation backfill complete; {total} incident(s) exist.")
    return 0


def cmd_report(args) -> int:
    from .reports import case_report_data, render_csv, render_html, render_json

    _, db = _open_db()
    data = case_report_data(db, args.case_id)
    if data is None:
        print(f"No case with id {args.case_id}.", file=sys.stderr)
        return 1
    rendered = {"html": render_html, "json": render_json, "csv": render_csv}[args.format](data)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        print(f"Report written to {args.output}")
    else:
        print(rendered)
    return 0


def cmd_anchor(_args) -> int:
    from .evidence_export import chain_anchor
    import json

    cfg, db = _open_db()
    print(json.dumps(chain_anchor(db, cfg.signing_key), indent=2))
    return 0


def cmd_export(args) -> int:
    from .evidence_export import export_case

    cfg, db = _open_db()
    summary = export_case(db, cfg, args.case_id, cfg.signing_key, actor="cli")
    if summary is None:
        print(f"No case with id {args.case_id}.", file=sys.stderr)
        return 1
    print(f"Signed evidence bundle written to:\n  {summary['bundle_dir']}")
    print(f"  case: {summary['case_number']}  evidence files: {summary['evidence_files']}"
          f"  chain: {'OK' if summary['chain_ok'] else 'BROKEN'}")
    print(f"  signature: {summary['signature']}")
    return 0


def cmd_verify_bundle(args) -> int:
    from .evidence_export import verify_bundle

    cfg, _ = _open_db()
    result = verify_bundle(args.bundle_dir, cfg.signing_key)
    if result["ok"]:
        print(f"OK — {result['reason']}"
              + (f" ({result.get('evidence_files', 0)} evidence files)"))
        return 0
    print(f"FAILED — {result['reason']}", file=sys.stderr)
    for issue in result.get("files", []):
        print(f"  - {issue}", file=sys.stderr)
    return 2


def cmd_security_check(_args) -> int:
    """Print a security posture report; non-zero exit on critical findings."""
    from .ops import security_report

    cfg, db = _open_db()
    report = security_report(cfg, db)
    print("HexBee Hive — security posture\n" + "=" * 32)
    for item in report["ok"]:
        print(f"  [ ok ] {item}")
    for item in report["warn"]:
        print(f"  [warn] {item}")
    for item in report["critical"]:
        print(f"  [CRIT] {item}")
    print(f"\n{len(report['ok'])} ok, {len(report['warn'])} warnings, "
          f"{len(report['critical'])} critical.")
    return 1 if report["critical"] else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hexbee-hive", description="HexBee Hive server")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create/upgrade the database").set_defaults(fn=cmd_init)
    sub.add_parser("engine", help="run the MQTT ingest engine").set_defaults(fn=cmd_engine)
    sub.add_parser("web", help="run the dashboard/API server").set_defaults(fn=cmd_web)
    sub.add_parser("verify", help="verify the evidence hash chain").set_defaults(fn=cmd_verify)
    sub.add_parser("correlate", help="backfill incident correlation").set_defaults(fn=cmd_correlate)

    user = sub.add_parser("user", help="user management").add_subparsers(
        dest="user_cmd", required=True
    )
    add = user.add_parser("add")
    add.add_argument("username")
    add.add_argument("role", choices=("administrator", "investigator", "viewer"))
    add.set_defaults(fn=cmd_user_add)
    dis = user.add_parser("disable")
    dis.add_argument("username")
    dis.set_defaults(fn=cmd_user_disable)

    rep = sub.add_parser("report", help="generate a case report")
    rep.add_argument("case_id", type=int)
    rep.add_argument("--format", choices=("html", "json", "csv"), default="html")
    rep.add_argument("-o", "--output")
    rep.set_defaults(fn=cmd_report)

    sub.add_parser("anchor", help="print a signed chain-anchor receipt").set_defaults(fn=cmd_anchor)
    exp = sub.add_parser("export", help="write a signed evidence bundle for a case")
    exp.add_argument("case_id", type=int)
    exp.set_defaults(fn=cmd_export)
    vb = sub.add_parser("verify-bundle", help="verify a signed evidence bundle offline")
    vb.add_argument("bundle_dir")
    vb.set_defaults(fn=cmd_verify_bundle)
    sub.add_parser("security-check", help="report security posture").set_defaults(fn=cmd_security_check)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
