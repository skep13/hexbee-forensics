"""hexbee-queen — analyst command line for investigating from the Queen.

Session state (Hive URL + token) is stored in ~/.hexbee-queen.json so you
log in once:

    hexbee-queen connect http://hive.local:8080 -u analyst
    hexbee-queen status
    hexbee-queen incidents
    hexbee-queen incident 3
    hexbee-queen cases
    hexbee-queen case 1
    hexbee-queen case new "USB malware on front-desk PC" -d "Walk-in report"
    hexbee-queen case note 1 "Imaged the drive, hash matches"
    hexbee-queen assign 3 1              # incident 3 -> case 1
    hexbee-queen search --text evil.exe
    hexbee-queen tag 42 malware
    hexbee-queen report 1 -f html -o case1.html
    hexbee-queen verify

Engagement tooling (all scope-gated — nothing fires at a target that is not
inside an authorised, in-window scope rule):

    hexbee-queen scope add cidr 10.10.0.0/24 --auth-ref SOW-2026-14
    hexbee-queen scope check 10.10.0.5
    hexbee-queen recon quick 10.10.0.0/24 --case 1
    hexbee-queen responder --watch --case 1
    hexbee-queen bloodhound ./20260725_bloodhound.zip --case 1
    hexbee-queen pivot generate queen.lan -o ./pivot
    hexbee-queen engagement report 1 -o HB-2026-0001.html --pdf
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from .client import HiveClient, HiveError
from .pkghint import install_hint

SESSION_FILE = Path.home() / ".hexbee-queen.json"

SEV = {0: "info", 1: "notice", 2: "WARNING", 3: "CRITICAL"}


def _session() -> dict:
    if not SESSION_FILE.exists():
        print("Not connected. Run: hexbee-queen connect <hive-url> -u <user>", file=sys.stderr)
        raise SystemExit(1)
    return json.loads(SESSION_FILE.read_text())


def _load_client() -> HiveClient:
    state = _session()
    return HiveClient(state["url"], state["token"])


def _ingest_key(args) -> str | None:
    """Shared ingest key for tools that write findings back into the chain:
    --key, then HEXBEE_INGEST_KEY, then whatever `connect --ingest-key` saved."""
    import os

    key = getattr(args, "key", None) or os.environ.get("HEXBEE_INGEST_KEY")
    if key:
        return key
    try:
        return _session().get("ingest_key") or None
    except SystemExit:
        return None


def _table(rows: list[dict], columns: list[tuple[str, str]]) -> None:
    if not rows:
        print("(none)")
        return
    widths = {
        key: max(len(header), *(len(str(r.get(key, ""))) for r in rows))
        for key, header in columns
    }
    line = "  ".join(header.ljust(widths[key]) for key, header in columns)
    print(line)
    print("-" * len(line))
    for r in rows:
        print("  ".join(str(r.get(key, "")).ljust(widths[key]) for key, _ in columns))


def cmd_connect(args) -> int:
    client = HiveClient(args.url)
    password = getpass.getpass(f"Password for {args.username}: ")
    try:
        session = client.login(args.username, password)
    except HiveError as exc:
        print(f"Login failed: {exc}", file=sys.stderr)
        return 1
    state = {"url": args.url, "token": session["token"]}
    if args.ingest_key:
        # Stored 0600 so recon/responder/bloodhound can write findings back
        # into the chain without re-typing the shared key each time.
        state["ingest_key"] = args.ingest_key
    SESSION_FILE.write_text(json.dumps(state))
    try:
        SESSION_FILE.chmod(0o600)
    except OSError:
        pass  # Windows
    print(f"Connected to {args.url} as {session['username']} ({session['role']}).")
    if args.ingest_key:
        print("Ingest key saved — active tools can now write findings.")
    return 0


def cmd_status(_args) -> int:
    client = _load_client()
    s = client.stats()
    v = client.verify()
    print(f"Events: {s['events']}   Devices: {s['devices']}")
    print(f"Incidents: {s['incidents_open']} open / {s['incidents_total']} total")
    print(f"Cases: {s['cases_open']} open / {s['cases_total']} total")
    chain = f"verified over {v['checked']} events" if v["ok"] else \
        f"BROKEN at event {v['first_bad_id']}"
    print(f"Evidence chain: {chain}")
    return 0


def cmd_incidents(args) -> int:
    client = _load_client()
    _table(client.incidents(args.status),
           [("id", "#"), ("opened_at", "Opened"), ("severity", "Sev"),
            ("status", "Status"), ("case_id", "Case"), ("title", "Title")])
    return 0


def cmd_incident(args) -> int:
    client = _load_client()
    inc = client.incident(args.id)
    print(f"Incident #{inc['id']} — {inc['title']}")
    print(f"  status={inc['status']} severity={SEV.get(inc['severity'], inc['severity'])} "
          f"opened={inc['opened_at']} case={inc['case_id'] or '-'}")
    print("\nTimeline:")
    for t in inc["timeline"]:
        print(f"  {t['at']}  [{t['device']}]  {t['narrative']}")
    return 0


def cmd_cases(_args) -> int:
    client = _load_client()
    _table(client.cases(),
           [("id", "id"), ("case_number", "Case #"), ("status", "Status"),
            ("created_at", "Opened"), ("created_by", "By"), ("title", "Title")])
    return 0


def cmd_case_show(args) -> int:
    client = _load_client()
    case = client.case(args.id)
    print(f"{case['case_number']} — {case['title']}  [{case['status']}]")
    if case["description"]:
        print(case["description"])
    print(f"Opened {case['created_at']} by {case['created_by']}")
    print("\nIncidents:")
    for i in case["incidents"]:
        print(f"  #{i['id']} [{i['status']}] {i['title']}")
    if not case["incidents"]:
        print("  (none)")
    print("\nTimeline:")
    for t in case.get("timeline", []):
        print(f"  {t['at']}  [{t['device']}]  {t['narrative']}")
    print("\nNotes:")
    for n in case["notes"]:
        print(f"  {n['created_at']} {n['author']}: {n['body']}")
    if not case["notes"]:
        print("  (none)")
    return 0


def cmd_case_new(args) -> int:
    client = _load_client()
    case = client.create_case(args.title, args.description or "")
    print(f"Created {case['case_number']} (id {case['id']}).")
    return 0


def cmd_case_note(args) -> int:
    client = _load_client()
    client.add_note(args.id, args.body)
    print("Note added.")
    return 0


def cmd_case_status(args) -> int:
    client = _load_client()
    client.set_case_status(args.id, args.status)
    print(f"Case {args.id} -> {args.status}.")
    return 0


def cmd_assign(args) -> int:
    client = _load_client()
    client.assign_incident(args.incident_id, args.case_id)
    print(f"Incident {args.incident_id} assigned to case {args.case_id}.")
    return 0


def cmd_search(args) -> int:
    client = _load_client()
    events = client.events(
        text=args.text, device=args.device, event_type=args.event_type,
        tag=args.tag, since=args.since, until=args.until, limit=args.limit,
    )
    for e in events:
        print(f"{e['occurred_at']}  #{e['id']:<5} [{e['device']}] "
              f"{e['event_type']:<20} {json.dumps(e['payload'], ensure_ascii=False)}")
    print(f"({len(events)} result(s))")
    return 0


def cmd_tag(args) -> int:
    client = _load_client()
    client.tag_event(args.event_id, args.tag)
    print(f"Event {args.event_id} tagged '{args.tag}'.")
    return 0


def cmd_report(args) -> int:
    client = _load_client()
    result = client.report(args.case_id, args.format)
    rendered = result if isinstance(result, str) else json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(rendered)
    return 0


def cmd_ioc_list(_args) -> int:
    client = _load_client()
    _table(client.iocs(),
           [("id", "id"), ("kind", "Kind"), ("value", "Value"), ("hits", "Hits"),
            ("added_by", "By"), ("note", "Note")])
    return 0


def cmd_ioc_add(args) -> int:
    client = _load_client()
    ioc_id = client.add_ioc(args.kind, args.value, args.note or "")
    print(f"IOC {ioc_id} added ({args.kind}: {args.value}).")
    return 0


def cmd_ioc_del(args) -> int:
    client = _load_client()
    client.delete_ioc(args.id)
    print(f"IOC {args.id} removed.")
    return 0


def cmd_ioc_hits(args) -> int:
    client = _load_client()
    for h in client.ioc_hits(args.limit):
        incident = f" incident #{h['incident_id']}" if h["incident_id"] else ""
        print(f"{h['matched_at']}  {h['kind']}:{h['value']}  ->  event #{h['event_id']} "
              f"({h['event_type']}, {h['device']}){incident}")
    return 0


def cmd_ai_ask(args) -> int:
    client = _load_client()
    result = client.ai_ask(args.question, args.case)
    print(result["answer"])
    print(f"\n[engine: {result['engine']}]")
    return 0


def cmd_ai_how(args) -> int:
    """Ask how to use HexBee. Answered from the Hive's grounded manual, so it
    cannot invent a command that does not exist."""
    client = _load_client()
    result = client.ai_howto(" ".join(args.question))
    print(result["answer"])
    footer = f"[engine: {result['engine']}"
    if result.get("sources"):
        footer += f" · sources: {', '.join(result['sources'])}"
    print(f"\n{footer}]")
    return 0 if result.get("grounded") else 2


def cmd_ai_summarize(args) -> int:
    client = _load_client()
    result = client.ai_summarize(args.case_id)
    print(result["summary"])
    print(f"\n[engine: {result['engine']}]")
    return 0


def cmd_verify(_args) -> int:
    client = _load_client()
    v = client.verify()
    if v["ok"]:
        print(f"OK — chain verified over {v['checked']} events.")
        return 0
    print(f"FAILED — chain breaks at event {v['first_bad_id']}.", file=sys.stderr)
    return 2


def cmd_anchor(args) -> int:
    client = _load_client()
    anchor = client.anchor()
    print(json.dumps(anchor, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(anchor, indent=2), encoding="utf-8")
        print(f"\nAnchor receipt saved to {args.output}")
    return 0


def cmd_anchor_verify(args) -> int:
    client = _load_client()
    anchor = json.loads(Path(args.file).read_text(encoding="utf-8"))
    result = client.verify_anchor(anchor)
    print(("OK — " if result["ok"] else "FAILED — ") + result["reason"])
    return 0 if result["ok"] else 2


def cmd_export(args) -> int:
    client = _load_client()
    summary = client.export_case(args.case_id)
    print(f"Signed evidence bundle created on the Hive:\n  {summary['bundle_dir']}")
    print(f"  case {summary['case_number']} · {summary['evidence_files']} evidence file(s) · "
          f"chain {'OK' if summary['chain_ok'] else 'BROKEN'}")
    print(f"  signature: {summary['signature']}")
    return 0


# -- engagement scope -----------------------------------------------------

def cmd_scope_list(args) -> int:
    client = _load_client()
    rules = client.scope_list(args.case)
    if not rules:
        print("No scope rules defined. Active tooling is blocked until at "
              "least one authorised range exists:\n"
              "  hexbee-queen scope add cidr 10.10.0.0/24 --auth-ref SOW-2026-14")
        return 0
    _table(rules, [("id", "id"), ("kind", "Kind"), ("value", "Value"),
                   ("auth_ref", "Authorisation"), ("starts_at", "From"),
                   ("ends_at", "Until"), ("active", "Active"),
                   ("added_by", "By")])
    return 0


def cmd_scope_add(args) -> int:
    client = _load_client()
    result = client.scope_add(args.kind, args.value, auth_ref=args.auth_ref,
                              starts_at=args.starts, ends_at=args.ends,
                              case_id=args.case, note=args.note)
    print(f"Scope rule {result['rule_id']} added ({args.kind}: {args.value}).")
    return 0


def cmd_scope_del(args) -> int:
    client = _load_client()
    client.scope_delete(args.id)
    print(f"Scope rule {args.id} removed.")
    return 0


def cmd_scope_check(args) -> int:
    client = _load_client()
    result = client.scope_check(args.target, args.case)
    if result["allowed"]:
        ref = f" [auth: {result['auth_ref']}]" if result.get("auth_ref") else ""
        print(f"IN SCOPE — {result['reason']}{ref}")
        return 0
    print(f"OUT OF SCOPE — {result['reason']}", file=sys.stderr)
    return 2


# -- recon ----------------------------------------------------------------

def cmd_recon(args) -> int:
    from . import recon

    client = _load_client()
    if recon.available() is None:
        print(f"nmap is not installed — {install_hint('nmap')}", file=sys.stderr)
        return 1
    try:
        result = recon.scan(client, args.target, profile=args.profile,
                            case_id=args.case, ingest_key=_ingest_key(args),
                            dry_run=args.dry_run)
    except (ValueError, RuntimeError) as exc:
        print(f"Recon failed: {exc}", file=sys.stderr)
        return 1
    if not result["ok"]:
        print(f"Nothing scanned — {result['reason']}", file=sys.stderr)
        return 2
    if result.get("dry_run"):
        print(f"Would scan {len(result['would_scan'])} target(s); "
              f"{result['refused']} refused by scope.")
        return 0
    print(f"Scanned {result['scanned']} target(s) "
          f"({result['refused']} refused by scope)")
    print(f"  {result['hosts_up']} host(s) up, {result['services']} open service(s)")
    for host in result["hosts"]:
        ports = ", ".join(f"{p['port']}/{p['protocol']} {p['service']}"
                          for p in host["ports"][:12])
        print(f"  {host['ip']:<16} {host['os'][:28]:<28} {ports}")
    print(f"  {result['stored']} finding(s) written to the evidence chain"
          if result["stored"] else
          "  (no ingest key — findings were not written; pass --key)")
    return 0


# -- responder bridge -----------------------------------------------------

def cmd_responder(args) -> int:
    import logging

    from .responder import ResponderBridge, find_log_dir

    client = _load_client()
    log_dir = find_log_dir(args.log_dir)
    if log_dir is None:
        print("Responder log directory not found. Pass --log-dir "
              "(usually /usr/share/responder/logs).", file=sys.stderr)
        return 1
    key = _ingest_key(args)
    if not key:
        print("An ingest key is required to write captures into the chain "
              "(--key or HEXBEE_INGEST_KEY).", file=sys.stderr)
        return 1

    bridge = ResponderBridge(client, log_dir, case_id=args.case,
                             ingest_key=key,
                             include_material=args.include_material)
    if args.include_material:
        print("WARNING: full credential material will be written into the "
              "evidence log. Make sure your rules of engagement allow this.",
              file=sys.stderr)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    if args.watch:
        skipped = 0 if args.import_existing else bridge.prime()
        print(f"Watching {log_dir} ({skipped} pre-existing capture(s) skipped). "
              f"Ctrl-C to stop.", file=sys.stderr)
        bridge.watch(interval=args.interval)
        return 0
    fresh = bridge.sweep()
    stored = bridge.ship(fresh)
    print(f"Imported {len(fresh)} capture(s) from {log_dir}; "
          f"{stored} written to the chain.")
    for cap in fresh[:20]:
        print(f"  {cap['format']:<12} {cap['domain'] or '.'}\\{cap['user']} "
              f"from {cap['source_host']}")
    return 0


# -- BloodHound -----------------------------------------------------------

def cmd_bloodhound(args) -> int:
    from . import bloodhound

    client = _load_client()
    path = Path(args.path)
    if not path.exists():
        print(f"No such path: {path}", file=sys.stderr)
        return 1
    result = bloodhound.ingest(client, path, case_id=args.case,
                               ingest_key=_ingest_key(args))
    print(f"Domains: {', '.join(result['domains']) or '(none identified)'}")
    print(f"  kerberoastable accounts:        {result['kerberoastable']}")
    print(f"  AS-REP roastable accounts:      {result['asrep_roastable']}")
    print(f"  unconstrained delegation hosts: {result['unconstrained_delegation']}")
    print(f"  privileged groups:              {result['privileged_groups']}")
    print(f"{result['stored']} finding(s) written to the evidence chain"
          if result["stored"] else
          "(no ingest key — findings were not written; pass --key)")
    return 0


# -- pivot ----------------------------------------------------------------

def cmd_pivot_generate(args) -> int:
    from . import pivot

    result = pivot.write_unit(args.out, queen_host=args.queen_host,
                              queen_user=args.queen_user,
                              queen_ssh_port=args.queen_ssh_port,
                              remote_port=args.port, pi_user=args.pi_user)
    print(f"Wrote:\n  " + "\n  ".join(result["files"]))
    print(f"\nCopy setup-pivot.sh to the Pi and run it there, then:\n"
          f"  hexbee-queen pivot connect --port {args.port}")
    return 0


def cmd_pivot_status(args) -> int:
    from . import pivot

    up = pivot.tunnel_up(args.port)
    print(f"Reverse tunnel on 127.0.0.1:{args.port}: "
          f"{'UP — drop box has dialled in' if up else 'down'}")
    return 0 if up else 1


def cmd_pivot_connect(args) -> int:
    from . import pivot

    client = _load_client()
    key = _ingest_key(args)
    if key:
        try:
            client.ingest([pivot.session_event("Queen-Pivot", "opened",
                                               args.port, args.case,
                                               note=args.note or "")], key)
        except HiveError:
            pass
    try:
        code = pivot.connect(args.port, args.user, hive_pause=args.hive_pause)
    except RuntimeError as exc:
        print(f"{exc}", file=sys.stderr)
        return 1
    finally:
        if key:
            try:
                client.ingest([pivot.session_event("Queen-Pivot", "closed",
                                                   args.port, args.case)], key)
            except HiveError:
                pass
    return code


# -- sealing --------------------------------------------------------------

def cmd_seal(args) -> int:
    """Declare a case sealed and anchor the evidence log at that moment."""
    from .seal import seal_case

    client = _load_client()
    key = _ingest_key(args)
    if not key:
        print("An ingest key is required (--key or HEXBEE_INGEST_KEY).",
              file=sys.stderr)
        return 1
    operator = args.operator or getpass.getuser()

    result = seal_case(client, args.case_id, operator=operator, ingest_key=key,
                       witness=args.witness or "", note=args.note or "")
    if not result["chain_ok"]:
        print("REFUSING TO SEAL: the evidence chain does not verify. "
              "Investigate before declaring this case complete.",
              file=sys.stderr)
        return 2

    print(f"Case {args.case_id} sealed by {result['operator']}"
          + (f" before {result['witness']}" if result["witness"] else ""))
    print(f"  evidence chain: verified over {result['records']} record(s)")
    print(f"  head hash:      {result['head_hash']}")
    print(f"  signature:      {result['signature']}")
    if args.output:
        Path(args.output).write_text(json.dumps(result["anchor"], indent=2),
                                     encoding="utf-8")
        print(f"\nAnchor receipt written to {args.output}")
        print("Keep it somewhere separate from the Hive. It is how you show "
              "later that the log has not been rewritten since.")
    else:
        print("\nSave the anchor somewhere separate with -o <file>; it is how "
              "you prove later that the log has not been rewritten.")
    return 0


# -- engagement report ----------------------------------------------------

def cmd_engagement_report(args) -> int:
    from . import engagement

    client = _load_client()

    def progress(index, total, event_type, kind):
        print(f"  [{index}/{total}] narrating {event_type} {kind}".rstrip(),
              file=sys.stderr)

    print(f"Building engagement report for case {args.case_id} …", file=sys.stderr)
    result = engagement.build(client, args.case_id, args.output,
                              use_ai=not args.no_ai, pdf=args.pdf,
                              progress=progress if not args.no_ai else None)
    print(f"Report: {result['html']}")
    print(f"  {result['events']} evidence record(s) in {result['groups']} "
          f"finding group(s)")
    print(f"  narration: {'Hive Mind' if result['ai_used'] else 'template (no local model)'}")
    print(f"  evidence chain: {'verified' if result['chain_ok'] else 'VERIFICATION FAILED'}")
    if args.pdf:
        pdf = result.get("pdf", {})
        print(f"  PDF: {pdf.get('path') if pdf.get('ok') else 'not produced — ' + pdf.get('reason', '')}")
    return 0


# -- case mode / intel ----------------------------------------------------

def cmd_mode(args) -> int:
    client = _load_client()
    client.set_case_mode(args.case_id, args.mode)
    print(f"Case {args.case_id} is now in {args.mode} mode.")
    return 0


def cmd_intel(_args) -> int:
    client = _load_client()
    info = client.intel_status()
    if not info.get("available"):
        print("No local threat intel database. Sync one before deployment:\n"
              "  hexbee-hive sync-intel")
        return 1
    print(f"Indicators: {info['indicators']}  ({info.get('size_bytes', 0) // 1024} KB)")
    for kind, count in sorted((info.get("by_kind") or {}).items()):
        print(f"  {kind:<10} {count}")
    print("\nFeeds:")
    for feed in info.get("feeds", []):
        print(f"  {feed['name']:<20} {feed['rows']:>8} rows  "
              f"{feed['last_sync']}  {feed['status']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="hexbee-queen", description="HexBee analyst CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("connect", help="log in to a Hive")
    c.add_argument("url")
    c.add_argument("-u", "--username", required=True)
    c.add_argument("--ingest-key", help="save the shared ingest key so active "
                                        "tools can write findings back")
    c.set_defaults(fn=cmd_connect)

    sub.add_parser("status", help="Hive overview").set_defaults(fn=cmd_status)

    i = sub.add_parser("incidents", help="list incidents")
    i.add_argument("--status", choices=("open", "triaged", "closed"))
    i.set_defaults(fn=cmd_incidents)

    ii = sub.add_parser("incident", help="show one incident with timeline")
    ii.add_argument("id", type=int)
    ii.set_defaults(fn=cmd_incident)

    case = sub.add_parser("case", help="case operations").add_subparsers(
        dest="case_cmd", required=True)
    cs = case.add_parser("show"); cs.add_argument("id", type=int); cs.set_defaults(fn=cmd_case_show)
    cn = case.add_parser("new")
    cn.add_argument("title"); cn.add_argument("-d", "--description")
    cn.set_defaults(fn=cmd_case_new)
    cno = case.add_parser("note")
    cno.add_argument("id", type=int); cno.add_argument("body")
    cno.set_defaults(fn=cmd_case_note)
    cst = case.add_parser("status")
    cst.add_argument("id", type=int)
    cst.add_argument("status", choices=("open", "active", "closed"))
    cst.set_defaults(fn=cmd_case_status)

    sub.add_parser("cases", help="list cases").set_defaults(fn=cmd_cases)

    a = sub.add_parser("assign", help="assign incident to case")
    a.add_argument("incident_id", type=int)
    a.add_argument("case_id", type=int)
    a.set_defaults(fn=cmd_assign)

    s = sub.add_parser("search", help="search evidence")
    s.add_argument("--text"); s.add_argument("--device"); s.add_argument("--event-type")
    s.add_argument("--tag"); s.add_argument("--since"); s.add_argument("--until")
    s.add_argument("--limit", type=int, default=100)
    s.set_defaults(fn=cmd_search)

    t = sub.add_parser("tag", help="tag an event")
    t.add_argument("event_id", type=int)
    t.add_argument("tag")
    t.set_defaults(fn=cmd_tag)

    r = sub.add_parser("report", help="pull a case report")
    r.add_argument("case_id", type=int)
    r.add_argument("-f", "--format", choices=("html", "json", "csv"), default="html")
    r.add_argument("-o", "--output")
    r.set_defaults(fn=cmd_report)

    ioc = sub.add_parser("ioc", help="IOC watchlist").add_subparsers(
        dest="ioc_cmd", required=True)
    ioc.add_parser("list").set_defaults(fn=cmd_ioc_list)
    ia = ioc.add_parser("add")
    ia.add_argument("kind", choices=("sha256", "filename", "ip", "domain", "substring"))
    ia.add_argument("value")
    ia.add_argument("-n", "--note")
    ia.set_defaults(fn=cmd_ioc_add)
    idl = ioc.add_parser("del")
    idl.add_argument("id", type=int)
    idl.set_defaults(fn=cmd_ioc_del)
    ih = ioc.add_parser("hits")
    ih.add_argument("--limit", type=int, default=50)
    ih.set_defaults(fn=cmd_ioc_hits)

    ai = sub.add_parser("ai", help="Hive Mind local AI").add_subparsers(
        dest="ai_cmd", required=True)
    aa = ai.add_parser("ask")
    aa.add_argument("question")
    aa.add_argument("--case", type=int, help="scope to one case")
    aa.set_defaults(fn=cmd_ai_ask)
    ahow = ai.add_parser("how", help="how do I use HexBee? (grounded answer)")
    ahow.add_argument("question", nargs="+")
    ahow.set_defaults(fn=cmd_ai_how)
    asum = ai.add_parser("summarize")
    asum.add_argument("case_id", type=int)
    asum.set_defaults(fn=cmd_ai_summarize)

    sub.add_parser("verify", help="verify evidence hash chain").set_defaults(fn=cmd_verify)

    an = sub.add_parser("anchor", help="get a signed chain-anchor receipt")
    an.add_argument("-o", "--output", help="save the anchor JSON to a file")
    an.set_defaults(fn=cmd_anchor)
    anv = sub.add_parser("anchor-verify", help="verify a saved anchor against the Hive")
    anv.add_argument("file")
    anv.set_defaults(fn=cmd_anchor_verify)
    ex = sub.add_parser("export", help="create a signed evidence bundle for a case")
    ex.add_argument("case_id", type=int)
    ex.set_defaults(fn=cmd_export)

    # -- engagement scope (gates every active tool below) ------------------
    sc = sub.add_parser("scope", help="authorised engagement scope").add_subparsers(
        dest="scope_cmd", required=True)
    sl = sc.add_parser("list")
    sl.add_argument("--case", type=int)
    sl.set_defaults(fn=cmd_scope_list)
    sa = sc.add_parser("add")
    sa.add_argument("kind", choices=("cidr", "host", "domain"))
    sa.add_argument("value")
    sa.add_argument("--auth-ref", default="", help="client authorisation reference")
    sa.add_argument("--starts", help="UTC ISO-8601, e.g. 2026-08-01T09:00:00Z")
    sa.add_argument("--ends")
    sa.add_argument("--case", type=int)
    sa.add_argument("--note", default="")
    sa.set_defaults(fn=cmd_scope_add)
    sd = sc.add_parser("del")
    sd.add_argument("id", type=int)
    sd.set_defaults(fn=cmd_scope_del)
    sck = sc.add_parser("check")
    sck.add_argument("target")
    sck.add_argument("--case", type=int)
    sck.set_defaults(fn=cmd_scope_check)

    # -- active tooling ----------------------------------------------------
    rc = sub.add_parser("recon", help="scope-gated nmap sweep into the case")
    rc.add_argument("profile", choices=("quick", "sweep", "vuln", "discover"))
    rc.add_argument("target", help="host, hostname, or CIDR range")
    rc.add_argument("--case", type=int)
    rc.add_argument("--key", help="Hive ingest key (else env/session)")
    rc.add_argument("--dry-run", action="store_true",
                    help="resolve scope only; do not run nmap")
    rc.set_defaults(fn=cmd_recon)

    rp = sub.add_parser("responder", help="import Responder captures into the chain")
    rp.add_argument("--log-dir", help="Responder Logs/ directory")
    rp.add_argument("--watch", action="store_true", help="follow continuously")
    rp.add_argument("--interval", type=int, default=5)
    rp.add_argument("--import-existing", action="store_true",
                    help="with --watch, also import captures already on disk")
    rp.add_argument("--include-material", action="store_true",
                    help="store the full hash/password, not just a fingerprint")
    rp.add_argument("--case", type=int)
    rp.add_argument("--key")
    rp.set_defaults(fn=cmd_responder)

    bh = sub.add_parser("bloodhound", help="import BloodHound collector output")
    bh.add_argument("path", help="collector .json, .zip, or directory")
    bh.add_argument("--case", type=int)
    bh.add_argument("--key")
    bh.set_defaults(fn=cmd_bloodhound)

    pv = sub.add_parser("pivot", help="drop-box reverse SSH tunnel").add_subparsers(
        dest="pivot_cmd", required=True)
    pg = pv.add_parser("generate", help="render the Pi's autossh unit + setup script")
    pg.add_argument("queen_host", help="address the Pi should dial back to")
    pg.add_argument("-o", "--out", default="./pivot", help="output directory")
    pg.add_argument("--queen-user", default="hexbee")
    pg.add_argument("--queen-ssh-port", type=int, default=22)
    pg.add_argument("--pi-user", default="hexbee")
    pg.add_argument("--port", type=int, default=2222, help="reverse-forward port")
    pg.set_defaults(fn=cmd_pivot_generate)
    ps = pv.add_parser("status")
    ps.add_argument("--port", type=int, default=2222)
    ps.set_defaults(fn=cmd_pivot_status)
    pc = pv.add_parser("connect")
    pc.add_argument("--port", type=int, default=2222)
    pc.add_argument("--user", default="hexbee")
    pc.add_argument("--case", type=int)
    pc.add_argument("--note")
    pc.add_argument("--key")
    pc.add_argument("--hive-pause", action="store_true",
                    help="stop the Hive dashboard during the session to free "
                         "~150 MB on the Pi (ingest keeps running)")
    pc.set_defaults(fn=cmd_pivot_connect)

    sl = sub.add_parser("seal", help="declare a case sealed and anchor the "
                                     "evidence log at that moment")
    sl.add_argument("case_id", type=int)
    sl.add_argument("--operator", help="who is sealing it (default: you)")
    sl.add_argument("--witness", help="name of the witness present")
    sl.add_argument("--note")
    sl.add_argument("-o", "--output", help="save the anchor receipt here")
    sl.add_argument("--key", help="Hive ingest key")
    sl.set_defaults(fn=cmd_seal)

    # -- deliverables ------------------------------------------------------
    en = sub.add_parser("engagement", help="engagement deliverables").add_subparsers(
        dest="engagement_cmd", required=True)
    er = en.add_parser("report", help="ATT&CK-mapped pentest report (HTML/PDF)")
    er.add_argument("case_id", type=int)
    er.add_argument("-o", "--output", default="engagement-report.html")
    er.add_argument("--pdf", action="store_true", help="also render a PDF")
    er.add_argument("--no-ai", action="store_true",
                    help="skip Hive Mind narration (faster, no model needed)")
    er.set_defaults(fn=cmd_engagement_report)

    md = sub.add_parser("mode", help="set a case's operating mode")
    md.add_argument("case_id", type=int)
    md.add_argument("mode", choices=("ir", "pentest", "diagnostics"))
    md.set_defaults(fn=cmd_mode)

    sub.add_parser("intel", help="local threat intel status").set_defaults(fn=cmd_intel)

    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except HiveError as exc:
        print(f"Hive error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
