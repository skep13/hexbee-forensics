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
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from .client import HiveClient, HiveError

SESSION_FILE = Path.home() / ".hexbee-queen.json"

SEV = {0: "info", 1: "notice", 2: "WARNING", 3: "CRITICAL"}


def _load_client() -> HiveClient:
    if not SESSION_FILE.exists():
        print("Not connected. Run: hexbee-queen connect <hive-url> -u <user>", file=sys.stderr)
        raise SystemExit(1)
    state = json.loads(SESSION_FILE.read_text())
    return HiveClient(state["url"], state["token"])


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
    SESSION_FILE.write_text(json.dumps({"url": args.url, "token": session["token"]}))
    try:
        SESSION_FILE.chmod(0o600)
    except OSError:
        pass  # Windows
    print(f"Connected to {args.url} as {session['username']} ({session['role']}).")
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


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="hexbee-queen", description="HexBee analyst CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("connect", help="log in to a Hive")
    c.add_argument("url")
    c.add_argument("-u", "--username", required=True)
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

    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except HiveError as exc:
        print(f"Hive error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
