"""Automatic engagement report — the deliverable everything else feeds.

    hexbee-queen report engagement 3 -o HB-2026-0003.html --pdf

Pulls every event in a case, groups them by ATT&CK tactic, asks Hive Mind for
a narrative paragraph per finding group, and renders a standalone HTML
report. `--pdf` runs it through wkhtmltopdf.

Two constraints from the hardware shaped this:

  * **Ollama calls are strictly sequential.** `phi3:mini` needs ~2.2 GB of the
    T470's 4 GB. Summarising ten finding groups in parallel would mean ten
    concurrent generations; here they are queued one at a time, with a cap on
    how many groups get narrated at all.
  * **The report never depends on the AI.** If Ollama is not running (or you
    are on battery and would rather it did not), every section falls back to a
    deterministic template built from the same data. The report is always
    produced; only the prose quality changes.

The HTML is fully self-contained — no CDN, no external font, no JS — because
this gets read on an air-gapped machine and emailed to a client.
"""

from __future__ import annotations

import html
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# Tactic order for the narrative. Matches the Hive's attack module.
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion",
    "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
]

SEVERITY_LABELS = {0: "Informational", 1: "Low", 2: "Medium", 3: "High"}

# How many groups get an AI paragraph. Each call is a full generation on a
# 4 GB laptop; ten is already a couple of minutes.
MAX_NARRATED_GROUPS = 10


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


# -- data gathering -------------------------------------------------------

def gather(client, case_id: int) -> dict:
    """Everything the report needs.

    Assembly happens on the Hive (`/api/v1/cases/<id>/engagement`), which is
    where the data already is — grouping five thousand events is two SQLite
    reads there and five thousand rows over the wire here. The dashboard's
    preview page consumes the identical structure, so the preview and the
    deliverable cannot drift apart.

    The endpoint is required: a Hive older than this feature returns 404 and
    the caller is told to upgrade, rather than silently producing a thinner
    report that looks complete.
    """
    from .client import HiveError

    try:
        data = client.engagement_data(case_id)
    except HiveError as exc:
        if exc.status == 404:
            raise HiveError(404, (
                "this Hive does not provide engagement data — either the case "
                "does not exist, or the Hive predates this feature and needs "
                "upgrading")) from exc
        raise
    try:
        data["ai"] = client.ai_status()
    except Exception:
        data["ai"] = {"available": False, "model": ""}
    return data


# -- narration ------------------------------------------------------------

def _fallback_paragraph(group: dict) -> str:
    window = (group["first_seen"] if group["first_seen"] == group["last_seen"]
              else f"{group['first_seen']} to {group['last_seen']}")
    devices = group["devices"]
    return (f"{group['count']} {group['title'].lower()} record(s) at "
            f"{group['severity_label'].lower()} severity, observed {window} "
            f"from {', '.join(devices[:4])}"
            f"{' and others' if len(devices) > 4 else ''}. "
            f"Each record is held in the evidence chain and is listed in the "
            f"technical findings below.")


def narrate(client, groups: list[dict], *, use_ai: bool = True,
            max_groups: int = MAX_NARRATED_GROUPS, progress=None) -> dict:
    """One paragraph per finding group, keyed by (event_type, kind).

    Sequential by design. `phi3:mini` holds ~2.2 GB of the T470's 4 GB while
    it generates; issuing these concurrently is how you get an OOM kill
    halfway through a client deliverable. AI failure on any single group
    degrades that group to the template, never the whole report.
    """
    narratives: dict[tuple, str] = {}
    ai_ok = use_ai
    if ai_ok:
        try:
            ai_ok = bool(client.ai_status().get("available"))
        except Exception:
            ai_ok = False

    for index, group in enumerate(groups):
        key = (group["event_type"], group["kind"])
        if progress:
            progress(index + 1, len(groups), group["event_type"], group["kind"])
        if not ai_ok or index >= max_groups:
            narratives[key] = _fallback_paragraph(group)
            continue
        try:
            answer = client.ai_ask(_prompt_for(group)).get("answer", "").strip()
        except Exception:
            answer = ""
        narratives[key] = answer or _fallback_paragraph(group)
    return narratives


def _prompt_for(group: dict) -> str:
    sample = []
    for ev in group["events"][:5]:
        payload = {k: v for k, v in (ev.get("payload") or {}).items()
                   if k not in ("material", "matched_strings")}
        sample.append({"at": ev["occurred_at"], "device": ev["device"],
                       "severity": ev["severity"], "payload": payload})
    return (
        "You are writing one paragraph of a professional penetration test "
        "report. Describe the finding below factually: what was observed, "
        "why it matters to the client, and the recommended remediation. "
        "Three to five sentences. No headings, no bullet points, no "
        "speculation beyond the data.\n\n"
        f"Finding type: {group['event_type']} {group['kind']}\n"
        f"Occurrences: {group['count']}\n"
        f"Sample records: {json.dumps(sample, default=str)[:2500]}"
    )


def executive_summary(client, data: dict, groups: list[dict], *,
                      use_ai: bool = True) -> str:
    case = data["case"]
    stats = data["stats"]
    tactics = [t["label"] for t in data["coverage"].get("tactics", [])
               if t.get("events")]

    # The Hive already computed a deterministic summary from the same data.
    fallback = data.get("summary") or ""
    fallback += (
        (f" Activity mapped to {len(tactics)} MITRE ATT&CK tactic(s): "
         f"{', '.join(tactics)}." if tactics else "")
        + f" The evidence hash chain "
          f"{'verified successfully' if data['verify'].get('ok') else 'FAILED verification'} "
          f"over {data['verify'].get('checked', 0)} records.")

    if not use_ai or not data["ai"].get("available"):
        return fallback
    prompt = (
        "Write a three-sentence executive summary for a penetration test "
        "report, aimed at a non-technical reader. State the overall risk "
        "posture and the single most important action to take. No headings, "
        "no bullets.\n\n"
        f"Engagement: {case['case_number']} — {case['title']}\n"
        f"Findings: {stats['high']} high, {stats['medium']} medium, "
        f"{stats['groups']} groups\n"
        f"Tactics observed: {', '.join(tactics) or 'none attributed'}\n"
        f"Finding groups: {', '.join(g['title'] for g in groups[:12])}")
    try:
        answer = client.ai_ask(prompt).get("answer", "").strip()
    except Exception:
        answer = ""
    return answer or fallback


# -- rendering ------------------------------------------------------------

CSS = """
:root{--ink:#16161a;--muted:#5f6470;--line:#d9dbe1;--honey:#f9b912;
      --crit:#b3261e;--warn:#b26b00;--ok:#1e7a44;--bg:#fff}
*{box-sizing:border-box}
body{font-family:"Segoe UI",system-ui,-apple-system,sans-serif;color:var(--ink);
     background:var(--bg);margin:0;padding:0;line-height:1.55;font-size:11pt}
.page{max-width:60rem;margin:0 auto;padding:2.5rem 2rem 4rem}
h1{font-size:1.9rem;margin:0 0 .2rem;letter-spacing:-.02em}
h2{font-size:1.15rem;margin:2.4rem 0 .7rem;padding-bottom:.3rem;
   border-bottom:2px solid var(--honey)}
h3{font-size:.98rem;margin:1.5rem 0 .4rem}
.sub{color:var(--muted);margin:0 0 1.5rem}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(12rem,1fr));
      gap:.6rem;margin:1.2rem 0;padding:1rem;border:1px solid var(--line);
      border-radius:8px;background:#fbfbfc}
.meta div span{display:block;font-size:.68rem;text-transform:uppercase;
      letter-spacing:.1em;color:var(--muted)}
.meta div strong{font-size:.95rem}
table{border-collapse:collapse;width:100%;font-size:.82rem;margin:.6rem 0}
th,td{text-align:left;padding:.4rem .55rem;border-bottom:1px solid var(--line);
      vertical-align:top}
th{background:#f4f4f6;font-size:.7rem;text-transform:uppercase;
   letter-spacing:.08em;color:var(--muted)}
code{font-family:ui-monospace,Consolas,monospace;font-size:.85em;
     background:#f4f4f6;padding:.05rem .3rem;border-radius:3px;
     word-break:break-all}
.sev{font-weight:700;font-size:.72rem;text-transform:uppercase;letter-spacing:.06em}
.sev-3{color:var(--crit)}.sev-2{color:var(--warn)}.sev-1{color:#1f5fa8}
.sev-0{color:var(--muted)}
.finding{border:1px solid var(--line);border-left:4px solid var(--honey);
         border-radius:6px;padding:.9rem 1.1rem;margin:1rem 0;
         page-break-inside:avoid}
.finding.high{border-left-color:var(--crit)}
.finding.medium{border-left-color:var(--warn)}
.tags{color:var(--muted);font-size:.76rem;margin:.3rem 0 .6rem}
.heat{display:grid;grid-template-columns:repeat(auto-fit,minmax(7.5rem,1fr));
      gap:.4rem;margin:.8rem 0}
.heat .cell{border:1px solid var(--line);border-radius:6px;padding:.5rem .6rem;
      background:#fbfbfc}
.heat .cell.hit{background:rgba(249,185,18,.16);border-color:var(--honey)}
.heat .cell .t{font-size:.66rem;text-transform:uppercase;letter-spacing:.06em;
      color:var(--muted)}
.heat .cell .n{font-size:1.2rem;font-weight:700}
.chain-ok{color:var(--ok);font-weight:700}
.chain-bad{color:var(--crit);font-weight:700}
.note{background:#fbfbfc;border:1px solid var(--line);border-radius:6px;
      padding:.7rem .9rem;font-size:.85rem;color:var(--muted)}
footer{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--line);
       color:var(--muted);font-size:.76rem}
@media print{.page{padding:0}h2{page-break-after:avoid}}
"""


def render_html(data: dict, groups: list[dict], narratives: dict,
                summary: str) -> str:
    case = data["case"]
    verify = data["verify"]
    stats = data["stats"]

    scope_rows = "".join(
        f"<tr><td><code>{_esc(r['kind'])}:{_esc(r['value'])}</code></td>"
        f"<td>{_esc(r.get('auth_ref') or '—')}</td>"
        f"<td>{_esc(r.get('starts_at') or '—')} → {_esc(r.get('ends_at') or '—')}</td>"
        f"<td>{'active' if r.get('active') else 'inactive'}</td></tr>"
        for r in data["scope"]) or (
        "<tr><td colspan='4'>No scope rules recorded for this engagement.</td></tr>")

    heat = "".join(
        f"<div class='cell{' hit' if t.get('events') else ''}'>"
        f"<div class='t'>{_esc(t['label'])}</div>"
        f"<div class='n'>{t.get('events', 0)}</div>"
        f"<div class='t'>{len(t.get('techniques', []))} technique(s)</div></div>"
        for t in data["coverage"].get("tactics", []))

    finding_blocks = []
    for index, group in enumerate(groups, 1):
        worst = group["severity"]
        css = "high" if worst >= 3 else ("medium" if worst == 2 else "")
        rows = "".join(
            f"<tr><td>{_esc(e['occurred_at'])}</td><td>{_esc(e['device'])}</td>"
            f"<td class='sev sev-{e['severity']}'>{SEVERITY_LABELS[e['severity']]}</td>"
            f"<td><code>{_esc(json.dumps(_redact(e.get('payload') or {}), default=str)[:400])}</code></td>"
            f"</tr>" for e in group["events"][:25])
        hidden = max(0, group["count"] - 25)
        more = (f"<p class='tags'>… and {hidden} further record(s) in "
                f"the evidence log.</p>" if hidden else "")
        finding_blocks.append(
            f"<div class='finding {css}'>"
            f"<h3>{index}. {_esc(group['title'])}</h3>"
            f"<p class='tags'>{group['count']} record(s) · highest severity "
            f"<span class='sev sev-{worst}'>{group['severity_label']}</span> · "
            f"{_esc(', '.join(group['devices'][:5]))}</p>"
            f"<p>{_esc(narratives.get((group['event_type'], group['kind']), ''))}</p>"
            f"<table><tr><th>Occurred</th><th>Source</th><th>Severity</th>"
            f"<th>Detail</th></tr>{rows}</table>{more}</div>")

    notes = "".join(
        f"<tr><td>{_esc(n['created_at'])}</td><td>{_esc(n['author'])}</td>"
        f"<td>{_esc(n['body'])}</td></tr>" for n in case.get("notes", [])) or (
        "<tr><td colspan='3'>No analyst notes recorded.</td></tr>")

    timeline = "".join(
        f"<tr><td>{_esc(t['at'])}</td><td>{_esc(t['device'])}</td>"
        f"<td>{_esc(t['narrative'])}</td></tr>"
        for t in data.get("timeline", [])[:120]) or (
        "<tr><td colspan='3'>No timeline entries.</td></tr>")

    chain_class = "chain-ok" if verify.get("ok") else "chain-bad"
    chain_text = (f"Verified over {verify.get('checked', 0)} records"
                  if verify.get("ok") else
                  f"FAILED at record {verify.get('first_bad_id')}")
    ai_note = (f"Narrative sections drafted locally by "
               f"{_esc(data['ai'].get('model', 'the local model'))} and reviewed "
               f"by the analyst."
               if data["ai"].get("available") else
               "No local model was available; narrative sections are generated "
               "from the evidence data directly.")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{_esc(case['case_number'])} — Engagement Report</title>
<style>{CSS}</style></head><body><div class="page">

<h1>{_esc(case['case_number'])} — Engagement Report</h1>
<p class="sub">{_esc(case['title'])}</p>

<div class="meta">
  <div><span>Case</span><strong>{_esc(case['case_number'])}</strong></div>
  <div><span>Status</span><strong>{_esc(case['status'])}</strong></div>
  <div><span>Mode</span><strong>{_esc(data.get('mode_label', 'Incident Response'))}</strong></div>
  <div><span>Opened</span><strong>{_esc(case['created_at'])}</strong></div>
  <div><span>Lead</span><strong>{_esc(case['created_by'])}</strong></div>
  <div><span>Generated</span><strong>{_esc(data['generated_at'])}</strong></div>
</div>

<h2>1. Executive summary</h2>
<p>{_esc(summary)}</p>

<h2>2. Scope and methodology</h2>
<p>Testing was confined to the authorised scope below. Every active tool in
the HexBee toolkit checks this scope before it transmits, and refusals are
recorded in the evidence chain alongside successful actions.</p>
<table><tr><th>Rule</th><th>Authorisation</th><th>Window (UTC)</th><th>State</th></tr>
{scope_rows}</table>
<p class="note">Evidence was collected with the HexBee kit: Scout (field
sensor), Forager (live-response collector), Comb (disk and file triage),
Netmon (passive network monitoring), and Queen-side active tooling. All
records are appended to a SHA-256 hash-chained log at the point of receipt.</p>

<h2>3. Attack narrative — MITRE ATT&amp;CK coverage</h2>
<p>{data['coverage'].get('distinct_techniques', 0)} distinct technique(s) were
attributed across {data['coverage'].get('total_attributions', 0)} evidence
record(s).</p>
<div class="heat">{heat}</div>

<h2>4. Technical findings</h2>
{''.join(finding_blocks) or '<p>No findings were recorded for this case.</p>'}

<h2>5. Evidence chain</h2>
<table>
  <tr><th>Property</th><th>Value</th></tr>
  <tr><td>Chain integrity</td><td class="{chain_class}">{_esc(chain_text)}</td></tr>
  <tr><td>Records in case</td><td>{stats['events']}</td></tr>
  <tr><td>Sources</td><td>{stats['devices']}</td></tr>
  <tr><td>Incidents</td><td>{stats['incidents']}</td></tr>
  <tr><td>Anchor head hash</td><td><code>{_esc(data['anchor'].get('head_hash', 'not available'))}</code></td></tr>
  <tr><td>Anchor signature</td><td><code>{_esc(data['anchor'].get('signature', 'not available'))}</code></td></tr>
</table>

<h3>Case timeline</h3>
<table><tr><th>At</th><th>Source</th><th>Event</th></tr>{timeline}</table>

<h3>Analyst notes</h3>
<table><tr><th>At</th><th>Author</th><th>Note</th></tr>{notes}</table>

<h2>Appendix — reproducing this report</h2>
<p>The complete signed evidence bundle for this case, including per-file
hashes and the audit trail, is produced with:</p>
<p><code>hexbee-queen export {case['id']}</code> and verified offline with
<code>hexbee-hive verify-bundle &lt;bundle&gt;</code>.</p>

<footer>{ai_note} Generated by HexBee on {_esc(data['generated_at'])}.
This document contains the findings of an authorised security assessment and
should be handled accordingly.</footer>
</div></body></html>"""


def _redact(payload: dict) -> dict:
    """Keep harvested secrets out of the client-facing document."""
    redacted = {}
    for key, value in payload.items():
        if key in ("material", "password", "hash", "secret"):
            redacted[key] = "[redacted — see evidence log]"
        else:
            redacted[key] = value
    return redacted


# -- PDF ------------------------------------------------------------------

def to_pdf(html_path: Path, pdf_path: Path) -> dict:
    """Convert with wkhtmltopdf, which is packaged for Kali/Debian and is far
    lighter than a headless browser on a 4 GB laptop."""
    binary = shutil.which("wkhtmltopdf")
    if binary is None:
        return {"ok": False,
                "reason": "wkhtmltopdf not installed (sudo apt install wkhtmltopdf)"}
    proc = subprocess.run(
        [binary, "--enable-local-file-access", "--quiet",
         "--margin-top", "16mm", "--margin-bottom", "16mm",
         str(html_path), str(pdf_path)],
        capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        return {"ok": False, "reason": (proc.stderr or "").strip()[:300]}
    return {"ok": True, "path": str(pdf_path)}


def build(client, case_id: int, output: str | Path, *, use_ai: bool = True,
          pdf: bool = False, progress=None) -> dict:
    """Gather, narrate, render, and optionally convert. Returns a summary."""
    data = gather(client, case_id)
    groups = data["groups"]
    narratives = narrate(client, groups, use_ai=use_ai, progress=progress)
    summary = executive_summary(client, data, groups, use_ai=use_ai)
    html_text = render_html(data, groups, narratives, summary)

    out = Path(output)
    out.write_text(html_text, encoding="utf-8")
    result = {"html": str(out), "events": data["stats"]["events"],
              "groups": len(groups),
              "ai_used": bool(use_ai and data["ai"].get("available")),
              "chain_ok": data["verify"].get("ok", False)}
    if pdf:
        result["pdf"] = to_pdf(out, out.with_suffix(".pdf"))
    return result
