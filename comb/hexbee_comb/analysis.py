"""The full scan pipeline: inventory + EXIF + browser artifacts → findings,
Hive events, and a branded HTML report."""

from __future__ import annotations

import json
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from . import __version__
from .browser import Visit, find_and_parse
from .exif import extract as extract_exif
from .inventory import FileRecord, walk

IMAGE_MAGIC = {"jpeg", "png", "gif"}


@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str = ""
    files: list[FileRecord] = field(default_factory=list)
    visits: list[Visit] = field(default_factory=list)
    exif: list[dict] = field(default_factory=list)   # {path, ...exif fields}

    @property
    def mismatches(self) -> list[FileRecord]:
        return [f for f in self.files if f.mismatch]

    @property
    def executables(self) -> list[FileRecord]:
        return [f for f in self.files if f.executable]

    @property
    def gps_points(self) -> list[dict]:
        return [e for e in self.exif if "lat" in e]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def scan(target: str | Path, max_files: int | None = None,
         web_limit: int = 500) -> ScanResult:
    target = Path(target)
    result = ScanResult(target=str(target), started_at=_now())
    for record in walk(target, max_files=max_files):
        result.files.append(record)
        if record.magic_type in IMAGE_MAGIC:
            exif = extract_exif(target / record.path)
            if exif:
                result.exif.append({"path": record.path, **exif})
    result.visits = find_and_parse(target, limit_per_profile=web_limit)
    result.finished_at = _now()
    return result


# -- Hive upload ----------------------------------------------------------

def to_hive_events(result: ScanResult, device: str, web_cap: int = 50) -> list[dict]:
    """Convert the interesting findings into Hive ingest events.

    Deliberately selective: every executable, every extension mismatch,
    every GPS-bearing image, the most recent `web_cap` browser visits, and
    scan start/finish markers — not all N thousand inventory rows.
    """
    events: list[dict] = []

    def ev(event_type: str, payload: dict, occurred_at: str | None = None) -> None:
        events.append({
            "device": device,
            "event_type": event_type,
            "occurred_at": occurred_at or _now(),
            "payload": payload,
        })

    ev("analysis_started", {"target": result.target, "tool": f"comb-{__version__}"},
       result.started_at)
    for f in result.executables:
        ev("executable_found",
           {"name": f.path, "sha256": f.sha256, "md5": f.md5, "sha1": f.sha1,
            "size": f.size, "magic": f.magic_type}, f.modified)
    for f in result.mismatches:
        if not f.executable:
            ev("artifact_mismatch",
               {"name": f.path, "sha256": f.sha256, "claims": f.path.rsplit(".", 1)[-1],
                "actually": f.magic_type}, f.modified)
    for e in result.gps_points:
        ev("artifact_image_gps",
           {"name": e["path"], "lat": e["lat"], "lon": e["lon"],
            "camera": f"{e.get('make', '')} {e.get('model', '')}".strip()})
    for v in result.visits[:web_cap]:
        ev("artifact_web_visit",
           {"url": v.url[:500], "title": v.title[:200], "browser": v.browser,
            "visits": v.visit_count}, v.visited_at)
    ev("analysis_completed",
       {"target": result.target, "files": len(result.files),
        "executables": len(result.executables), "mismatches": len(result.mismatches),
        "gps_images": len(result.gps_points), "web_visits": len(result.visits)},
       result.finished_at)
    return events


def upload(events: list[dict], hive_url: str, ingest_key: str) -> dict:
    req = urllib.request.Request(
        f"{hive_url.rstrip('/')}/api/v1/ingest",
        data=json.dumps(events).encode(),
        method="POST",
        headers={"Content-Type": "application/json",
                 "X-HexBee-Ingest-Key": ingest_key},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


# -- report ---------------------------------------------------------------

def render_report(result: ScanResult) -> str:
    def table(rows: list[str], headers: list[str]) -> str:
        if not rows:
            return "<p class='muted'>None found.</p>"
        head = "".join(f"<th>{h}</th>" for h in headers)
        return f"<table><tr>{head}</tr>{''.join(rows)}</table>"

    exe_rows = [
        f"<tr><td>{escape(f.path)}</td><td>{f.size}</td>"
        f"<td><code>{f.sha256[:16]}…</code></td><td>{f.modified}</td></tr>"
        for f in result.executables
    ]
    mm_rows = [
        f"<tr><td>{escape(f.path)}</td><td>{escape(f.magic_type or '?')}</td>"
        f"<td><code>{f.sha256[:16]}…</code></td></tr>"
        for f in result.mismatches
    ]
    gps_rows = [
        f"<tr><td>{escape(e['path'])}</td><td>{e['lat']}, {e['lon']}</td>"
        f"<td>{escape(e.get('make', ''))} {escape(e.get('model', ''))}</td>"
        f"<td>{escape(e.get('taken_at', ''))}</td></tr>"
        for e in result.gps_points
    ]
    web_rows = [
        f"<tr><td>{v.visited_at}</td><td>{escape(v.browser)}</td>"
        f"<td>{escape(v.title[:80])}</td><td><code>{escape(v.url[:120])}</code></td></tr>"
        for v in result.visits[:200]
    ]

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>HexBee Comb — Analysis Report</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 64rem; }}
 h1 {{ border-bottom: 3px solid #f9b912; padding-bottom: .3rem; }}
 table {{ border-collapse: collapse; width: 100%; font-size: .85rem; }}
 th, td {{ text-align: left; padding: .35rem .5rem; border-bottom: 1px solid #ddd; }}
 th {{ background: #faf3e0; }}
 code {{ background: #f5f5f5; font-size: .85em; word-break: break-all; }}
 .muted {{ color: #777; }}
</style></head><body>
<h1>🐝 HexBee Comb — Analysis Report</h1>
<p class="muted">Target <code>{escape(result.target)}</code> ·
 {result.started_at} → {result.finished_at} · comb {__version__}</p>
<p><strong>{len(result.files)}</strong> files inventoried ·
 <strong>{len(result.executables)}</strong> executables ·
 <strong>{len(result.mismatches)}</strong> extension mismatches ·
 <strong>{len(result.gps_points)}</strong> GPS-tagged images ·
 <strong>{len(result.visits)}</strong> browser visits</p>
<h2>Executables</h2>{table(exe_rows, ["Path", "Size", "SHA-256", "Modified"])}
<h2>Extension mismatches</h2>{table(mm_rows, ["Path", "Actual type", "SHA-256"])}
<h2>GPS-tagged images</h2>{table(gps_rows, ["Path", "Coordinates", "Camera", "Taken"])}
<h2>Browser history (most recent 200)</h2>{table(web_rows, ["Visited", "Browser", "Title", "URL"])}
</body></html>"""


def result_to_json(result: ScanResult) -> str:
    return json.dumps(
        {
            "target": result.target,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "files": [asdict(f) for f in result.files],
            "visits": [asdict(v) for v in result.visits],
            "exif": result.exif,
        },
        indent=2,
    )
