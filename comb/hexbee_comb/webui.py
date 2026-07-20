"""Point-and-click web UI for the whole Comb toolkit — `hexbee-comb serve`.

Stdlib only (http.server), so it adds no dependencies and runs on the Queen
next to the disks. Every Comb operation that would otherwise need the command
line is a button here:

    Scan        directory / mounted image  -> inventory + artifacts (+ upload)
    Partitions  raw image                   -> MBR/GPT table
    Carve       raw image                   -> recover deleted files
    Files       raw image (Sleuth Kit)      -> filesystem listing incl. deleted

Binds to 127.0.0.1 by default (local-only analyst convenience UI).
"""

from __future__ import annotations

import html
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__, tsk
from .analysis import render_report, scan, to_hive_events, upload
from .carver import carve
from .diskimage import parse_partitions

_STYLE = """
 :root{--bg:#000;--pan:#0c0c0e;--line:#38383f;--txt:#f4f4f5;--gold:#f9b912;--mut:#9a9aa2}
 *{box-sizing:border-box}
 body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--txt);margin:0}
 header{background:var(--pan);border-bottom:2px solid var(--gold);padding:.7rem 1.2rem;
        display:flex;align-items:center;gap:1.4rem;position:sticky;top:0;z-index:2}
 header .brand{color:var(--gold);font-weight:800;font-size:1.1rem;letter-spacing:.04em}
 header nav a{color:var(--mut);text-decoration:none;font-size:.9rem;padding:.3rem .1rem;
        border-bottom:2px solid transparent}
 header nav a:hover{color:var(--txt)} header nav a.on{color:var(--gold);border-color:var(--gold)}
 main{max-width:60rem;margin:1.5rem auto;padding:0 1.2rem}
 h1{font-size:1.25rem} h2{color:var(--gold);font-size:1.02rem}
 .panel{background:var(--pan);border:1px solid var(--line);border-radius:8px;padding:1rem 1.2rem;margin:1rem 0}
 label{display:block;margin:.6rem 0 .25rem;color:var(--mut);font-size:.8rem;
        text-transform:uppercase;letter-spacing:.08em}
 input[type=text],input[type=number]{width:100%;background:var(--bg);color:var(--txt);
        border:1px solid var(--line);border-radius:6px;padding:.55rem;font-size:.95rem;font-family:ui-monospace,monospace}
 button{background:var(--gold);color:#000;border:none;border-radius:6px;
        padding:.6rem 1.2rem;font-weight:700;font-size:.95rem;cursor:pointer;margin-top:1rem}
 button.ghost{background:transparent;color:var(--txt);border:1px solid var(--line)}
 .cards{display:flex;flex-wrap:wrap;gap:.7rem;margin:1rem 0}
 .card{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:.6rem 1rem;min-width:6.5rem}
 .card .n{font-size:1.5rem;font-weight:700;color:var(--gold);font-family:ui-monospace,monospace}
 .card .l{color:var(--mut);font-size:.72rem;text-transform:uppercase}
 a{color:var(--gold)} .muted{color:var(--mut);font-size:.85rem}
 .row{display:flex;gap:1rem;flex-wrap:wrap}.row>div{flex:1;min-width:13rem}
 table{border-collapse:collapse;width:100%;font-size:.85rem;font-family:ui-monospace,monospace}
 th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid var(--line)}
 th{color:var(--mut);text-transform:uppercase;font-size:.68rem}
 .err{color:#e8871e}
"""

_NAV = [("/", "Scan"), ("/partitions", "Partitions"), ("/carve", "Carve"), ("/files", "Files")]


def _esc(s) -> str:
    return html.escape(str(s))


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    # -- plumbing ---------------------------------------------------------

    def _send(self, body: str, status: int = 200, ctype: str = "text/html; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _page(self, inner: str, active: str = "/") -> str:
        nav = "".join(
            f"<a href='{h}' class='{'on' if h == active else ''}'>{t}</a>" for h, t in _NAV)
        return (f"<!doctype html><html><head><meta charset='utf-8'>"
                f"<title>HexBee Comb</title><style>{_STYLE}</style></head><body>"
                f"<header><span class='brand'>🔬 HexBee Comb</span><nav>{nav}</nav></header>"
                f"<main>{inner}<p class='muted'>Comb {__version__} · local analyst UI · "
                f"read-only — never modifies evidence</p></main></body></html>")

    def _defaults(self) -> dict:
        return getattr(self.server, "defaults", {})

    def _fields(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
        return {k: v[0] for k, v in raw.items()}

    # -- routing ----------------------------------------------------------

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/report":
            return self._send(getattr(self.server, "last_report", None)
                              or self._page("<p>No scan run yet.</p>"))
        if path == "/":
            return self._send(self._page(self._scan_form(), "/"))
        if path == "/partitions":
            return self._send(self._page(self._image_form(
                "/partitions", "Partition table (MBR / GPT)",
                "Read the partition layout of a raw disk image."), "/partitions"))
        if path == "/carve":
            return self._send(self._page(self._carve_form(), "/carve"))
        if path == "/files":
            avail = tsk.available()
            note = ("" if avail else
                    "<p class='err'>Sleuth Kit (mmls/fls) not found. Install it "
                    "(<code>sudo apt install sleuthkit</code>) to enable file listing.</p>")
            return self._send(self._page(note + self._image_form(
                "/files", "Filesystem listing (Sleuth Kit)",
                "List every file — including deleted — inside an image.",
                extra="<label>Partition start (sectors, from Partitions)</label>"
                      "<input type='number' name='offset' value='0'>"), "/files"))
        return self._send(self._page("<p>Not found.</p>"), status=404)

    def do_POST(self):
        path = self.path.split("?")[0]
        f = self._fields()
        try:
            if path == "/scan":
                return self._do_scan(f)
            if path == "/partitions":
                return self._do_partitions(f)
            if path == "/carve":
                return self._do_carve(f)
            if path == "/files":
                return self._do_files(f)
        except Exception as exc:  # never crash the UI on a bad path/format
            return self._send(self._page(
                f"<div class='panel err'>Error: {_esc(exc)}</div>"
                f"<p><a href='{_esc(path)}'>← back</a></p>"), status=400)
        return self._send(self._page("<p>Not found.</p>"), status=404)

    # -- forms ------------------------------------------------------------

    def _image_form(self, action: str, title: str, blurb: str, extra: str = "") -> str:
        d = self._defaults()
        return (f"<h1>{title}</h1><p class='muted'>{blurb}</p>"
                f"<div class='panel'><form method='post' action='{action}'>"
                f"<label>Raw image path</label>"
                f"<input type='text' name='image' value='{_esc(d.get('image',''))}' "
                f"placeholder='/evidence/disk.dd  or  C:\\cases\\usb.raw' required>{extra}"
                f"<button type='submit'>Run</button></form></div>")

    def _scan_form(self) -> str:
        d = self._defaults()
        summary = getattr(self.server, "last_summary", "")
        return (summary + "<h1>Scan a directory or mount</h1>"
                "<p class='muted'>Inventory, hashing, extension-mismatch, EXIF/GPS and browser "
                "history from a mounted image or extraction folder.</p>"
                "<div class='panel'><form method='post' action='/scan'>"
                f"<label>Target path</label><input type='text' name='path' value='{_esc(d.get('path',''))}' "
                "placeholder='/mnt/evidence  or  C:\\cases\\usb' required>"
                "<div class='row'><div><label>Max files (blank = all)</label>"
                "<input type='number' name='max_files' min='1'></div></div>"
                "<div class='panel'><label style='margin-top:0'>"
                "<input type='checkbox' name='upload'> Upload findings to the Hive</label>"
                "<div class='row'><div><label>Hive URL</label>"
                f"<input type='text' name='hive' value='{_esc(d.get('hive',''))}' placeholder='http://hive.local:8080'></div>"
                f"<div><label>Ingest key</label><input type='text' name='key' value='{_esc(d.get('key',''))}'></div></div>"
                f"<label>Device name</label><input type='text' name='device' value='{_esc(d.get('device','Comb01'))}'></div>"
                "<button type='submit'>🔬 Scan</button></form></div>")

    def _carve_form(self) -> str:
        d = self._defaults()
        return ("<h1>Carve files from a raw image</h1>"
                "<p class='muted'>Recover deleted / unallocated files (JPEG, PNG, PDF, ZIP, "
                "SQLite) straight from the image bytes.</p>"
                "<div class='panel'><form method='post' action='/carve'>"
                f"<label>Raw image path</label><input type='text' name='image' value='{_esc(d.get('image',''))}' "
                "placeholder='/evidence/disk.dd' required>"
                "<label>Output directory (recovered files written here)</label>"
                "<input type='text' name='out_dir' placeholder='/cases/carved' required>"
                "<button type='submit'>Carve</button></form></div>")

    # -- actions ----------------------------------------------------------

    def _do_scan(self, f: dict):
        path = f.get("path", "").strip()
        if not path or not Path(path).exists():
            return self._send(self._page(
                f"<div class='panel err'>Path not found: <code>{_esc(path)}</code></div>"
                "<p><a href='/'>← back</a></p>"), status=400)
        mf = f.get("max_files", "").strip()
        result = scan(path, max_files=int(mf) if mf.isdigit() else None)
        self.server.last_report = render_report(result)
        self.server.defaults = {**self._defaults(), "path": path, "hive": f.get("hive", ""),
                                "key": f.get("key", ""), "device": f.get("device", "Comb01")}
        ship = ""
        if f.get("upload") and f.get("hive") and f.get("key"):
            try:
                resp = upload(to_hive_events(result, device=f.get("device", "Comb01")),
                              f["hive"], f["key"])
                ship = f"<p>📤 Uploaded <strong>{resp.get('stored', 0)}</strong> events to the Hive.</p>"
            except Exception as exc:
                ship = f"<p class='err'>Upload failed: {_esc(exc)}</p>"
        cards = "".join(
            f"<div class='card'><div class='n'>{n}</div><div class='l'>{lbl}</div></div>"
            for n, lbl in [(len(result.files), "files"), (len(result.executables), "executables"),
                           (len(result.mismatches), "mismatches"), (len(result.gps_points), "GPS"),
                           (len(result.visits), "web visits")])
        self.server.last_summary = (
            f"<div class='panel'><h2 style='margin-top:0'>Last scan: <code>{_esc(path)}</code></h2>"
            f"<div class='cards'>{cards}</div>{ship}"
            "<a href='/report' target='_blank'>📄 Open full report</a></div>")
        self.send_response(303); self.send_header("Location", "/"); self.end_headers()

    def _do_partitions(self, f: dict):
        image = f.get("image", "").strip()
        if not image or not Path(image).is_file():
            raise FileNotFoundError(f"image not found: {image}")
        self.server.defaults = {**self._defaults(), "image": image}
        parts = parse_partitions(image)
        if not parts:
            body = "<div class='panel'>No partition table found (superfloppy or unknown).</div>"
        else:
            rows = "".join(
                f"<tr><td>{p.index}</td><td>{p.scheme}</td><td>{_esc(p.type_name)}</td>"
                f"<td>{p.start_lba}</td><td>{p.sectors}</td>"
                f"<td>{'boot' if p.bootable else ''}</td></tr>" for p in parts)
            body = ("<div class='panel'><table><tr><th>#</th><th>Scheme</th><th>Type</th>"
                    "<th>Start LBA</th><th>Sectors</th><th></th></tr>"
                    f"{rows}</table><p class='muted'>Use a partition's Start LBA as the offset "
                    "on the <a href='/files'>Files</a> tab.</p></div>")
        self._send(self._page(f"<h1>Partitions — <code>{_esc(image)}</code></h1>{body}", "/partitions"))

    def _do_carve(self, f: dict):
        image, out = f.get("image", "").strip(), f.get("out_dir", "").strip()
        if not image or not Path(image).is_file():
            raise FileNotFoundError(f"image not found: {image}")
        self.server.defaults = {**self._defaults(), "image": image}
        results = carve(image, out)
        rows = "".join(
            f"<tr><td>{_esc(r.kind)}</td><td>{r.offset}</td><td>{r.size}</td>"
            f"<td><code>{r.sha256[:16]}…</code></td><td>{_esc(r.path)}</td></tr>" for r in results)
        table = (f"<div class='panel'><p><strong>{len(results)}</strong> file(s) carved into "
                 f"<code>{_esc(out)}</code></p><table><tr><th>Type</th><th>Offset</th><th>Size</th>"
                 f"<th>SHA-256</th><th>Path</th></tr>{rows}</table></div>") if results else \
                "<div class='panel'>No carvable files found.</div>"
        self._send(self._page(f"<h1>Carve — <code>{_esc(image)}</code></h1>{table}", "/carve"))

    def _do_files(self, f: dict):
        image = f.get("image", "").strip()
        if not tsk.available():
            raise RuntimeError("Sleuth Kit not installed")
        if not image or not Path(image).is_file():
            raise FileNotFoundError(f"image not found: {image}")
        self.server.defaults = {**self._defaults(), "image": image}
        offset = f.get("offset", "0")
        entries = tsk.list_files(image, int(offset) if offset.isdigit() else 0)
        rows = "".join(
            f"<tr><td>{e.size}</td><td>{_esc(e.path)}</td>"
            f"<td>{'deleted' if e.deleted else ''}</td></tr>" for e in entries[:2000])
        self._send(self._page(
            f"<h1>Files — <code>{_esc(image)}</code></h1>"
            f"<div class='panel'><p class='muted'>{len(entries)} entries</p>"
            f"<table><tr><th>Size</th><th>Path</th><th></th></tr>{rows}</table></div>", "/files"))


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
