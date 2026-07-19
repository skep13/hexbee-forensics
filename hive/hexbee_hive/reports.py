"""Report generation: case reports as self-contained HTML, JSON, and CSV.

HTML is rendered with html.escape + string templates rather than a template
engine so reports are dependency-free and safe to archive alongside evidence.
PDF is intentionally left to the Queen (print-to-PDF or wkhtmltopdf there);
rendering PDFs on a 1 GB Pi is not worth the memory.
"""

from __future__ import annotations

import base64
import csv
import io
import json
from datetime import datetime, timezone
from functools import lru_cache
from html import escape
from pathlib import Path

from . import __version__
from .db import Database
from .cases import get_case
from .integrity import verify_chain
from .timeline import case_timeline

_SEV_NAMES = {0: "info", 1: "notice", 2: "warning", 3: "critical"}

_HTML_STYLE = """
 body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 60rem;
        color: #1a1a1a; }
 h1 { border-bottom: 3px solid #f0b429; padding-bottom: .3rem; }
 h2 { margin-top: 2rem; }
 table { border-collapse: collapse; width: 100%; }
 th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #ddd;
          vertical-align: top; font-size: .9rem; }
 th { background: #faf3e0; }
 .sev-2 td:first-child { border-left: 4px solid #e8871e; }
 .sev-3 td:first-child { border-left: 4px solid #cb2431; }
 .meta { color: #666; font-size: .85rem; }
 code { background: #f5f5f5; padding: .1rem .3rem; font-size: .85em;
        word-break: break-all; }
 .badge { display: inline-block; padding: .1rem .5rem; border-radius: 1rem;
          font-size: .8rem; background: #eee; }
"""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@lru_cache(maxsize=1)
def _logo_data_uri() -> str:
    """Embedded logo so exported reports stay self-contained offline files."""
    path = Path(__file__).parent / "static" / "logo-256.png"
    try:
        encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    except OSError:
        return ""
    return f"data:image/png;base64,{encoded}"


def case_report_data(db: Database, case_id: int) -> dict | None:
    """Everything a report needs, as plain data (also the JSON export)."""
    case = get_case(db, case_id)
    if case is None:
        return None
    return {
        "generated_at": _now(),
        "generator": f"HexBee Hive {__version__}",
        "integrity": verify_chain(db),
        "case": case,
        "timeline": case_timeline(db, case_id),
    }


def render_json(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


def render_csv(data: dict) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["occurred_at", "device", "event_type", "severity", "narrative", "event_id", "payload"]
    )
    for entry in data["timeline"]:
        writer.writerow(
            [
                entry["at"],
                entry["device"],
                entry["event_type"],
                _SEV_NAMES.get(entry["severity"], entry["severity"]),
                entry["narrative"],
                entry["event_id"],
                json.dumps(entry["payload"], ensure_ascii=False),
            ]
        )
    return buf.getvalue()


def render_html(data: dict) -> str:
    case = data["case"]
    integ = data["integrity"]
    integ_line = (
        f"<span class='badge' style='background:#d4edda'>chain verified "
        f"({integ['checked']} events)</span>"
        if integ["ok"]
        else f"<span class='badge' style='background:#f8d7da'>CHAIN BROKEN at event "
        f"{integ['first_bad_id']}</span>"
    )

    rows = []
    for entry in data["timeline"]:
        rows.append(
            f"<tr class='sev-{entry['severity']}'>"
            f"<td>{escape(entry['at'])}</td>"
            f"<td>{escape(entry['device'])}</td>"
            f"<td>{escape(entry['narrative'])}</td>"
            f"<td><code>{escape(json.dumps(entry['payload'], ensure_ascii=False))}</code></td>"
            f"</tr>"
        )

    notes = "".join(
        f"<p><strong>{escape(n['author'])}</strong> "
        f"<span class='meta'>{escape(n['created_at'])}</span><br>{escape(n['body'])}</p>"
        for n in case["notes"]
    ) or "<p class='meta'>No investigator notes.</p>"

    incidents = "".join(
        f"<li>#{i['id']} — {escape(i['title'])} "
        f"<span class='badge'>{escape(i['status'])}</span></li>"
        for i in case["incidents"]
    ) or "<li class='meta'>No incidents assigned.</li>"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>HexBee Case Report — {escape(case['case_number'])}</title>
<style>{_HTML_STYLE}</style></head><body>
<div style="display:flex; align-items:center; gap:1rem;">
  {f'<img src="{_logo_data_uri()}" alt="HexBee Forensics" style="height:5.5rem">' if _logo_data_uri() else ''}
  <div>
    <h1 style="margin-bottom:.1rem">HexBee Forensics — Case Report {escape(case['case_number'])}</h1>
    <p class="meta" style="letter-spacing:.25em; margin-top:0">DETECT · ISOLATE · ANALYSE</p>
  </div>
</div>
<p class="meta">Generated {escape(data['generated_at'])} by {escape(data['generator'])}
 &nbsp;|&nbsp; {integ_line}</p>

<h2>Case</h2>
<p><strong>{escape(case['title'])}</strong>
 <span class="badge">{escape(case['status'])}</span></p>
<p>{escape(case['description']) or '<span class="meta">No description.</span>'}</p>
<p class="meta">Opened {escape(case['created_at'])} by {escape(case['created_by'])}</p>

<h2>Incidents</h2>
<ul>{incidents}</ul>

<h2>Timeline ({len(data['timeline'])} events)</h2>
<table>
<tr><th>Time (UTC)</th><th>Device</th><th>Event</th><th>Payload</th></tr>
{''.join(rows)}
</table>

<h2>Investigator Notes</h2>
{notes}
</body></html>"""
