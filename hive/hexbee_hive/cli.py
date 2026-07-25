"""hexbee-hive command line.

New here? Two commands cover it:

    hexbee-hive setup                         guided first-time setup
    hexbee-hive doctor                        what works, and how to fix what doesn't

Everything else:

    hexbee-hive init                          create the database
    hexbee-hive engine                        run the MQTT ingest engine
    hexbee-hive web                           run the dashboard/API server
    hexbee-hive user add <name> <role>        create a user (prompts for password)
    hexbee-hive user disable <name>
    hexbee-hive verify                        verify the evidence hash chain
    hexbee-hive correlate                     backfill correlation over old events
    hexbee-hive report <case_id> [--format html|json|csv] [-o FILE]
    hexbee-hive syslog [--port 5514]          syslog receiver + anomaly engine
    hexbee-hive sync-intel                    pre-deployment threat intel pull
    hexbee-hive scope add cidr 10.0.0.0/24    authorise an engagement range
    hexbee-hive attack coverage [--case N]    ATT&CK tactic breakdown
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


def cmd_syslog(args) -> int:
    """Run the syslog receiver + log anomaly engine."""
    from .correlate import Correlator
    from .syslog import SyslogListener

    cfg, db = _open_db()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    listener = SyslogListener(cfg, db, Correlator(db, cfg.correlation_window_seconds),
                              host=args.host, port=args.port)
    if args.port < 1024:
        print(f"Binding udp/{args.port} needs privileges. Either run with "
              f"sudo, grant the capability once "
              f"(setcap cap_net_bind_service=+ep), or use --port 5514 and "
              f"redirect with iptables.", file=sys.stderr)
    try:
        listener.run_forever()
    except PermissionError:
        print(f"Permission denied binding udp/{args.port}.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Cannot bind udp/{args.port}: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_sync_intel(args) -> int:
    """Pre-deployment: pull threat intel feeds while online."""
    from .intel import FEEDS, sync

    cfg, _ = _open_db()
    if args.list:
        print("Available feeds:")
        for name, feed in FEEDS.items():
            print(f"  {name:<22} {feed.kind:<8} {feed.url}")
        return 0
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    print("Syncing threat intel. This is the only Hive command that uses the "
          "internet — run it before deployment, not in the field.\n")
    summary = sync(cfg, args.feeds or None, max_rows=args.max_rows)
    for result in summary["results"]:
        state = "ok" if result["ok"] else f"FAILED — {result.get('error', '')}"
        print(f"  {result['feed']:<22} {result['rows']:>8} rows   {state}")
    stats = summary["stats"]
    print(f"\n{stats['indicators']} indicator(s) total in {stats['path']} "
          f"({stats.get('size_bytes', 0) // 1024} KB)")
    if summary["failed"]:
        print(f"\nFailed feeds: {', '.join(summary['failed'])}", file=sys.stderr)
        print("abuse.ch requires a free account for most downloads. Create one "
              "and set HEXBEE_ABUSE_CH_KEY to your Auth-Key.", file=sys.stderr)
        return 1
    return 0


def cmd_intel_status(_args) -> int:
    from .intel import IntelStore, intel_db_path

    cfg, _ = _open_db()
    info = IntelStore(intel_db_path(cfg)).stats()
    if not info["available"]:
        print(f"No intel database at {info['path']}. Run: hexbee-hive sync-intel")
        return 1
    print(f"Indicators: {info['indicators']}  "
          f"({info.get('size_bytes', 0) // 1024} KB at {info['path']})")
    for kind, count in sorted(info.get("by_kind", {}).items()):
        print(f"  {kind:<10} {count}")
    print("\nFeeds:")
    for feed in info["feeds"]:
        print(f"  {feed['name']:<22} {feed['rows']:>8} rows  "
              f"{feed['last_sync']}  {feed['status']}")
    return 0


def cmd_scope(args) -> int:
    from . import scope as scope_mod

    _, db = _open_db()
    if args.scope_cmd == "list":
        rules = scope_mod.list_rules(db)
        if not rules:
            print("No scope rules. Active Queen tooling is blocked until one exists.")
            return 0
        for r in rules:
            window = f"{r['starts_at'] or '-'} .. {r['ends_at'] or '-'}"
            print(f"  #{r['id']:<4} {r['kind']:<7} {r['value']:<24} "
                  f"auth={r['auth_ref'] or '-':<18} {window}  "
                  f"{'active' if r['active'] else 'inactive'}")
        return 0
    if args.scope_cmd == "add":
        try:
            rule_id = scope_mod.add_rule(db, args.kind, args.value, actor="cli",
                                         auth_ref=args.auth_ref,
                                         starts_at=args.starts, ends_at=args.ends,
                                         note=args.note or "")
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        print(f"Scope rule {rule_id} added.")
        return 0
    if args.scope_cmd == "del":
        ok = scope_mod.remove_rule(db, args.id, actor="cli")
        print("Removed." if ok else "No such rule.")
        return 0 if ok else 1
    decision = scope_mod.check(db, args.target)
    print(("IN SCOPE — " if decision else "OUT OF SCOPE — ") + decision.reason)
    return 0 if decision else 2


def cmd_attack(args) -> int:
    from . import attack

    _, db = _open_db()
    if args.attack_cmd == "backfill":
        learned = attack.load_bundle(args.bundle)
        if learned:
            print(f"Loaded {learned} technique definitions from the ATT&CK bundle.")
        tagged = attack.backfill(db)
        print(f"Attributed techniques to {tagged} previously untagged event(s).")
        return 0
    coverage = (attack.case_coverage(db, args.case) if args.case
                else attack.global_coverage(db))
    print(f"{coverage['distinct_techniques']} technique(s) across "
          f"{coverage['total_attributions']} attribution(s)\n")
    for tactic in coverage["tactics"]:
        if not tactic["events"]:
            continue
        print(f"{tactic['label']} ({tactic['events']})")
        for tech in tactic["techniques"]:
            print(f"    {tech['id']:<12} {tech['name'][:56]:<56} x{tech['count']}")
    return 0


def cmd_setup(_args) -> int:
    """Guided first run."""
    from .setup_wizard import run

    try:
        return run()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled. Nothing was left half-finished — run "
              "`hexbee-hive setup` again whenever you're ready.")
        return 1


def cmd_doctor(args) -> int:
    """What works on this machine, and how to fix what doesn't."""
    from . import doctor

    cfg, db = _open_db()
    report = doctor.run(cfg, db)
    print(doctor.render(report, verbose=args.verbose))
    db.close()
    return 0 if report.ready else 1


def cmd_howto(args) -> int:
    """Answer a 'how do I use HexBee' question, with or without a model."""
    from .ai import LocalAI, how_to
    from . import knowledge

    cfg, _ = _open_db()
    if args.list:
        kb = knowledge.get()
        for doc in kb.docs:
            if doc.kind in ("recipe", "concept"):
                print(f"  {doc.title}")
        print(f"\n{len(kb.docs)} document(s) in the knowledge base.")
        return 0
    if not args.question:
        print("Ask a question, or use --list to see what is covered.",
              file=sys.stderr)
        return 1

    result = how_to(LocalAI(cfg.ai_url, cfg.ai_model), " ".join(args.question))
    print(result["answer"])
    print(f"\n[engine: {result['engine']}"
          + (f" · sources: {', '.join(result['sources'])}"
             if result.get("sources") else "") + "]")
    return 0 if result.get("grounded") else 2


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

    sl = sub.add_parser("syslog", help="run the syslog receiver + anomaly engine")
    sl.add_argument("--host", default="0.0.0.0")
    sl.add_argument("--port", type=int, default=514,
                    help="514 needs privileges; 5514 does not")
    sl.set_defaults(fn=cmd_syslog)

    si = sub.add_parser("sync-intel",
                        help="pre-deployment: download threat intel feeds")
    si.add_argument("feeds", nargs="*",
                    help="feed names (default: the small 'recent' set)")
    si.add_argument("--max-rows", type=int, default=250_000,
                    help="per-feed row cap (protects the SD card and lookup time)")
    si.add_argument("--list", action="store_true", help="list known feeds and exit")
    si.set_defaults(fn=cmd_sync_intel)
    sub.add_parser("intel-status",
                   help="local threat intel database status").set_defaults(
        fn=cmd_intel_status)

    scp = sub.add_parser("scope", help="authorised engagement scope").add_subparsers(
        dest="scope_cmd", required=True)
    scp.add_parser("list").set_defaults(fn=cmd_scope)
    sadd = scp.add_parser("add")
    sadd.add_argument("kind", choices=("cidr", "host", "domain"))
    sadd.add_argument("value")
    sadd.add_argument("--auth-ref", default="")
    sadd.add_argument("--starts")
    sadd.add_argument("--ends")
    sadd.add_argument("--note")
    sadd.set_defaults(fn=cmd_scope)
    sdel = scp.add_parser("del")
    sdel.add_argument("id", type=int)
    sdel.set_defaults(fn=cmd_scope)
    schk = scp.add_parser("check")
    schk.add_argument("target")
    schk.set_defaults(fn=cmd_scope)

    sub.add_parser("setup", help="guided first-time setup (start here)"
                   ).set_defaults(fn=cmd_setup)

    doc = sub.add_parser("doctor", help="check what works on this machine and "
                                        "how to fix what doesn't")
    doc.add_argument("-v", "--verbose", action="store_true",
                     help="also list everything that is already working")
    doc.set_defaults(fn=cmd_doctor)

    ht = sub.add_parser("howto", help="ask how to use HexBee (grounded, "
                                      "works with or without a local model)")
    ht.add_argument("question", nargs="*")
    ht.add_argument("--list", action="store_true",
                    help="list what the knowledge base covers")
    ht.set_defaults(fn=cmd_howto)

    atk = sub.add_parser("attack", help="MITRE ATT&CK attribution").add_subparsers(
        dest="attack_cmd", required=True)
    abf = atk.add_parser("backfill", help="tag events that have no techniques yet")
    abf.add_argument("--bundle", help="path to an offline ATT&CK STIX bundle")
    abf.set_defaults(fn=cmd_attack)
    acv = atk.add_parser("coverage", help="tactic/technique breakdown")
    acv.add_argument("--case", type=int)
    acv.set_defaults(fn=cmd_attack)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
