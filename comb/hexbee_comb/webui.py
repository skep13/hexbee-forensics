"""A tiny point-and-click web UI for Comb — `hexbee-comb serve`.

Stdlib only (http.server), so it adds no dependencies and runs on the Queen
next to the disks. Enter a path (a mounted image or extraction folder), click
Scan, view the report in the browser, and optionally push the findings into
the Hive — no command line needed.

Binds to 127.0.0.1 by default (local-only). This is an analyst convenience UI,
not a public service.
"""

from __future__ import annotations

import html
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__
from .analysis import render_report, scan, to_hive_events, upload

_STYLE = """
 body{font-family:system-ui,sans-serif;background:#1f1a10;color:#efe8d8;margin:0}
 header{background:#2b2416;border-bottom:2px solid #f0b429;padding:.8rem 1.2rem;
        color:#f0b429;font-weight:700;font-size:1.15rem}
 main{max-width:52rem;margin:1.5rem auto;padding:0 1.2rem}
 h2{color:#f0b429;font-size:1.05rem}
 .panel{background:#2b2416;border:1px solid #4a3f26;border-radius:8px;padding:1rem 1.2rem;margin:1rem 0}
 label{display:block;margin:.5rem 0 .2rem;color:#a89c80;font-size:.85rem}
 input[type=text],input[type=number]{width:100%;background:#1f1a10;color:#efe8d8;
        border:1px solid #4a3f26;border-radius:5px;padding:.5rem;font-size:1rem}
 button{background:#f0b429;color:#1f1a10;border:none;border-radius:5px;
        padding:.55rem 1.1rem;font-weight:700;font-size:1rem;cursor:pointer;margin-top:.8rem}
 .cards{display:flex;flex-wrap:wrap;gap:.8rem;margin:1rem 0}
 .card{background:#1f1a10;border:1px solid #4a3f26;border-radius:8px;padding:.6rem 1rem;min-width:7rem}
 .card .n{font-size:1.5rem;font-weight:700;color:#f0b429}
 .card .l{color:#a89c80;font-size:.75rem;text-transform:uppercase}
 a{color:#f0b429}
 .muted{color:#a89c80;font-size:.85rem}
 .row{display:flex;gap:1rem;flex-wrap:wrap}.row>div{flex:1;min-width:14rem}
"""

_FORM = """
<form method="post" action="/scan">
  <label>Target path (a mounted image, extraction folder, or directory)</label>
  <input type="text" name="path" value="{path}" placeholder="/mnt/evidence  or  C:\\cases\\usb" required>
  <div class="row">
    <div><label>Max files (blank = all)</label>
      <input type="number" name="max_files" value="{max_files}" min="1"></div>
  </div>
  <div class="panel" style="margin-top:1rem">
    <label style="margin-top:0"><input type="checkbox" name="upload" {upload_checked}> Upload findings to the Hive</label>
    <div class="row">
      <div><label>Hive URL</label><input type="text" name="hive" value="{hive}" placeholder="http://hive.local:8080"></div>
      <div><label>Ingest key</label><input type="text" name="key" value="{key}"></div>
    </div>
    <div><label>Device name</label><input type="text" name="device" value="{device}"></div>
  </div>
  <button type="submit">🔬 Scan</button>
</form>
"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # quiet

    def _send(self, body: str, status: int = 200, ctype: str = "text/html; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _page(self, inner: str) -> str:
        return (f"<!doctype html><html><head><meta charset='utf-8'>"
                f"<title>HexBee Comb</title><style>{_STYLE}</style></head><body>"
                f"<header>🔬 HexBee Comb — forensic triage</header><main>{inner}"
                f"<p class='muted'>Comb {__version__} · local analyst UI</p></main></body></html>")

    def do_GET(self):
        if self.path.startswith("/report"):
            report = getattr(self.server, "last_report", None)
            return self._send(report or self._page("<p>No scan run yet.</p>"))
        defaults = getattr(self.server, "defaults", {})
        form = _FORM.format(
            path=html.escape(defaults.get("path", "")),
            max_files="", upload_checked="",
            hive=html.escape(defaults.get("hive", "")),
            key=html.escape(defaults.get("key", "")),
            device=html.escape(defaults.get("device", "Comb01")))
        summary = getattr(self.server, "last_summary", "")
        self._send(self._page(summary + "<h2>New scan</h2>" + form))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        fields = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))

        def get(name, default=""):
            return fields.get(name, [default])[0]

        path = get("path").strip()
        if not path or not Path(path).exists():
            return self._send(self._page(
                f"<div class='panel'>Path not found: <code>{html.escape(path)}</code></div>"
                "<p><a href='/'>← back</a></p>"), status=400)

        max_files = get("max_files").strip()
        result = scan(path, max_files=int(max_files) if max_files.isdigit() else None)
        self.server.last_report = render_report(result)
        self.server.defaults = {"path": path, "hive": get("hive"),
                                "key": get("key"), "device": get("device", "Comb01")}

        ship_note = ""
        if get("upload") and get("hive") and get("key"):
            try:
                events = to_hive_events(result, device=get("device", "Comb01"))
                resp = upload(events, get("hive"), get("key"))
                ship_note = (f"<p>📤 Uploaded <strong>{resp.get('stored', 0)}</strong> "
                             f"events to the Hive.</p>")
            except Exception as exc:
                ship_note = f"<p style='color:#e8871e'>Upload failed: {html.escape(str(exc))}</p>"

        cards = "".join(
            f"<div class='card'><div class='n'>{n}</div><div class='l'>{lbl}</div></div>"
            for n, lbl in [
                (len(result.files), "files"),
                (len(result.executables), "executables"),
                (len(result.mismatches), "mismatches"),
                (len(result.gps_points), "GPS images"),
                (len(result.visits), "web visits")])
        self.server.last_summary = (
            f"<div class='panel'><h2 style='margin-top:0'>Last scan: "
            f"<code>{html.escape(path)}</code></h2><div class='cards'>{cards}</div>"
            f"{ship_note}<a href='/report' target='_blank'>📄 Open full report</a></div>")
        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()


def serve(host: str = "127.0.0.1", port: int = 8091, defaults: dict | None = None) -> None:
    server = ThreadingHTTPServer((host, port), _Handler)
    server.defaults = defaults or {}
    server.last_report = None
    server.last_summary = ""
    url = f"http://{host}:{port}"
    print(f"HexBee Comb UI on {url}  (Ctrl-C to stop)")
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
