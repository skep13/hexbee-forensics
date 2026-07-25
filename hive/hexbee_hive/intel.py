"""Offline threat intelligence.

`hexbee-hive sync-intel` is a **pre-deployment** command: run it at home while
you still have internet, and it pulls structured feeds into a local SQLite
database. In the field the Hive never touches the network — the IOC engine
queries that local database instead.

Design constraints that shaped this module:

  * The intel DB lives in its own file (`<data_dir>/intel/intel.db`), not in
    `hive.db`. Point `HEXBEE_DATA_DIR` at the external HDD and a large feed
    never lands on the Pi's SD card, and the evidence database stays small
    enough to copy off quickly.
  * Feeds are streamed to a temporary file and inserted in batches. A full
    MalwareBazaar dump is millions of lines; nothing is ever read whole
    into RAM.
  * Lookups are **exact-match on an indexed column**, unlike the analyst IOC
    watchlist which does substring matching. A linear scan across a few
    hundred thousand intel rows for every ingested event would flatten a
    Pi 3B+, so candidate values (hashes, IPs, domains, URLs) are extracted
    from the payload first and then looked up by index.
"""

from __future__ import annotations

import csv
import logging
import os
import re
import sqlite3
import threading
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("hexbee.intel")

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS indicators (
    kind        TEXT NOT NULL,     -- sha256 | md5 | sha1 | ip | domain | url
    value       TEXT NOT NULL,
    source      TEXT NOT NULL,
    tag         TEXT NOT NULL DEFAULT '',
    first_seen  TEXT NOT NULL DEFAULT '',
    synced_at   TEXT NOT NULL,
    PRIMARY KEY (kind, value)
);
CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(value);
CREATE TABLE IF NOT EXISTS feeds (
    name        TEXT PRIMARY KEY,
    url         TEXT NOT NULL,
    last_sync   TEXT NOT NULL DEFAULT '',
    rows        INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL DEFAULT ''
);
"""

# Candidate extraction — cheap regexes that keep lookups to a handful of
# indexed reads per event.
_HASH_RE = re.compile(r"\b([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]{4,400}", re.I)
_DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b", re.I)

_HASH_KIND = {32: "md5", 40: "sha1", 64: "sha256"}

# Private/link-local space is never interesting intel; skip the lookups.
_PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "169.254.", "0.", "255.")


@dataclass
class Feed:
    name: str
    url: str
    kind: str           # indicator kind produced, or "mixed"
    column: str         # CSV column name (or index as a string) holding the value
    fmt: str = "csv"    # csv | lines | zip-csv
    tag: str = ""
    comment_prefix: str = "#"
    member: str = ""    # file inside the zip, for fmt="zip-csv"


# abuse.ch "recent" endpoints are small (tens of thousands of rows) and are
# the sane default for a field kit. The full dumps are listed too; enable them
# explicitly when the external HDD is attached.
FEEDS: dict[str, Feed] = {
    "urlhaus": Feed(
        "urlhaus", "https://urlhaus.abuse.ch/downloads/csv_recent/",
        kind="url", column="url", fmt="csv", tag="malware-url"),
    "urlhaus-full": Feed(
        "urlhaus-full", "https://urlhaus.abuse.ch/downloads/csv/",
        kind="url", column="url", fmt="zip-csv", tag="malware-url"),
    "malwarebazaar": Feed(
        "malwarebazaar", "https://bazaar.abuse.ch/export/csv/recent/",
        kind="sha256", column="sha256_hash", fmt="csv", tag="malware-sample"),
    "malwarebazaar-full": Feed(
        "malwarebazaar-full", "https://bazaar.abuse.ch/export/csv/full/",
        kind="sha256", column="sha256_hash", fmt="zip-csv", tag="malware-sample"),
    "threatfox": Feed(
        "threatfox", "https://threatfox.abuse.ch/export/csv/recent/",
        kind="mixed", column="ioc", fmt="csv", tag="threatfox"),
    "feodo": Feed(
        "feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        kind="ip", column="dst_ip", fmt="csv", tag="botnet-c2"),
}

DEFAULT_FEEDS = ("urlhaus", "malwarebazaar", "threatfox", "feodo")

# A MISP community feed is any directory serving `manifest.json` + event JSON.
MISP_FEED_ENV = "HEXBEE_MISP_FEED_URL"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def intel_db_path(cfg) -> Path:
    d = cfg.data_dir / "intel"
    d.mkdir(parents=True, exist_ok=True)
    return d / "intel.db"


# -- store ----------------------------------------------------------------

class IntelStore:
    """Read/write access to the local intel database.

    Opened lazily and tolerantly: if the file does not exist yet (nobody has
    run `sync-intel`), every lookup simply returns no hits rather than
    raising. That keeps the Hive fully functional on a fresh install.
    """

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None

    def _connect(self, create: bool = False) -> sqlite3.Connection | None:
        with self._lock:
            if self._conn is not None:
                return self._conn
            if not create and not self.path.exists():
                return None
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.executescript(SCHEMA)
            self._conn = conn
            return conn

    def available(self) -> bool:
        return self._connect() is not None

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    # -- writes -----------------------------------------------------------

    def upsert(self, rows: list[tuple[str, str, str, str, str]]) -> int:
        """rows: (kind, value, source, tag, first_seen)."""
        conn = self._connect(create=True)
        stamp = _now()
        with self._lock:
            conn.executemany(
                """INSERT INTO indicators (kind, value, source, tag, first_seen, synced_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(kind, value) DO UPDATE SET
                       source = excluded.source, synced_at = excluded.synced_at""",
                [(k, v, s, t, f, stamp) for k, v, s, t, f in rows],
            )
            conn.commit()
        return len(rows)

    def record_feed(self, name: str, url: str, rows: int, status: str) -> None:
        conn = self._connect(create=True)
        with self._lock:
            conn.execute(
                """INSERT INTO feeds (name, url, last_sync, rows, status)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET url = excluded.url,
                       last_sync = excluded.last_sync, rows = excluded.rows,
                       status = excluded.status""",
                (name, url, _now(), rows, status),
            )
            conn.commit()

    def prune(self, before_iso: str) -> int:
        conn = self._connect()
        if conn is None:
            return 0
        with self._lock:
            cur = conn.execute("DELETE FROM indicators WHERE synced_at < ?", (before_iso,))
            conn.commit()
            return cur.rowcount

    # -- reads ------------------------------------------------------------

    def stats(self) -> dict:
        conn = self._connect()
        if conn is None:
            return {"available": False, "indicators": 0, "feeds": [],
                    "path": str(self.path)}
        with self._lock:
            total = conn.execute("SELECT COUNT(*) AS n FROM indicators").fetchone()["n"]
            by_kind = {r["kind"]: r["n"] for r in conn.execute(
                "SELECT kind, COUNT(*) AS n FROM indicators GROUP BY kind")}
            feeds = [dict(r) for r in conn.execute(
                "SELECT * FROM feeds ORDER BY name")]
        size = self.path.stat().st_size if self.path.exists() else 0
        return {"available": True, "indicators": total, "by_kind": by_kind,
                "feeds": feeds, "path": str(self.path), "size_bytes": size}

    def lookup(self, values: list[tuple[str, str]]) -> list[dict]:
        """values: (kind, value) candidates. Returns matching indicator rows."""
        conn = self._connect()
        if conn is None or not values:
            return []
        hits = []
        with self._lock:
            for kind, value in values:
                row = conn.execute(
                    "SELECT * FROM indicators WHERE kind = ? AND value = ?",
                    (kind, value)).fetchone()
                if row:
                    hits.append(dict(row))
        return hits


# -- candidate extraction -------------------------------------------------

def candidates(payload, cap: int = 40) -> list[tuple[str, str]]:
    """Extract (kind, value) pairs worth an indexed lookup from an event
    payload. Capped so a pathological payload cannot cause a query storm."""
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        key = (kind, value.lower())
        if key not in seen and len(out) < cap:
            seen.add(key)
            out.append(key)

    def walk(node) -> None:
        if isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
        elif isinstance(node, str):
            scan(node)

    def scan(text: str) -> None:
        if len(text) > 4000:
            text = text[:4000]
        for m in _HASH_RE.finditer(text):
            value = m.group(1)
            kind = _HASH_KIND.get(len(value))
            if kind:
                add(kind, value)
        for m in _URL_RE.finditer(text):
            add("url", m.group(0))
        for m in _IP_RE.finditer(text):
            ip = m.group(1)
            if not ip.startswith(_PRIVATE_PREFIXES) and not ip.startswith("172.1"):
                add("ip", ip)
        for m in _DOMAIN_RE.finditer(text):
            domain = m.group(1)
            # Skip things that are really filenames ("report.pdf").
            if not domain.rsplit(".", 1)[-1].isdigit() and len(domain) > 4:
                add("domain", domain)

    walk(payload)
    return out


def match_intel(store: IntelStore, payload: dict) -> list[dict]:
    """Intel hits for one event payload; empty when no intel DB is present."""
    if not store.available():
        return []
    return store.lookup(candidates(payload))


# -- sync (online, pre-deployment) ----------------------------------------

def _download(url: str, dest: Path, timeout: int = 120) -> Path:
    """Stream a feed to disk. Never buffers the body in memory."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "HexBee-Hive/intel-sync",
        "Accept": "text/csv, application/zip, */*",
    })
    # abuse.ch requires an Auth-Key on most downloads since 2025.
    key = os.environ.get("HEXBEE_ABUSE_CH_KEY", "")
    if key and "abuse.ch" in url:
        req.add_header("Auth-Key", key)
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest, "wb") as fh:
        while True:
            chunk = resp.read(64 * 1024)
            if not chunk:
                break
            fh.write(chunk)
    return dest


def _iter_csv_rows(path: Path, member: str = ""):
    """Yield csv rows from a plain or zipped feed, skipping comment lines.

    abuse.ch CSVs put the header inside a comment block, so the last comment
    line that looks like a header is used for field names.
    """
    def rows_from(handle):
        header: list[str] | None = None
        pending_comment = ""
        for raw in handle:
            line = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            if line.startswith("#"):
                pending_comment = line.lstrip("# ").strip()
                continue
            if header is None:
                if "," in pending_comment:
                    header = [h.strip().strip('"') for h in pending_comment.split(",")]
                    # fall through: this line is data
                else:
                    header = [h.strip().strip('"') for h in next(csv.reader([line]))]
                    continue
            values = next(csv.reader([line]), [])
            yield {header[i] if i < len(header) else str(i): v.strip().strip('"')
                   for i, v in enumerate(values)}

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            name = member or zf.namelist()[0]
            with zf.open(name) as fh:
                yield from rows_from(fh)
    else:
        with open(path, "rb") as fh:
            yield from rows_from(fh)


def _classify(value: str, declared: str) -> tuple[str, str] | None:
    """Normalize one raw indicator into (kind, value); None to skip."""
    value = (value or "").strip().strip('"')
    if not value:
        return None
    if declared != "mixed":
        return declared, value.lower() if declared != "url" else value
    # ThreatFox mixes types in one column.
    if _HASH_RE.fullmatch(value):
        return _HASH_KIND[len(value)], value.lower()
    if value.lower().startswith(("http://", "https://")):
        return "url", value
    host = value.split(":")[0]
    if _IP_RE.fullmatch(host):
        return "ip", host
    if _DOMAIN_RE.fullmatch(host):
        return "domain", host.lower()
    return None


def sync_feed(store: IntelStore, feed: Feed, work_dir: Path,
              max_rows: int = 250_000, batch: int = 5_000) -> dict:
    """Download and import one feed. Returns a per-feed summary."""
    work_dir.mkdir(parents=True, exist_ok=True)
    tmp = work_dir / f"{feed.name}.download"
    try:
        _download(feed.url, tmp)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = str(exc)
        if isinstance(exc, urllib.error.HTTPError) and exc.code in (401, 403):
            reason = (f"HTTP {exc.code} — abuse.ch now requires an account. Set "
                      f"HEXBEE_ABUSE_CH_KEY to your Auth-Key and retry.")
        store.record_feed(feed.name, feed.url, 0, f"failed: {reason}")
        log.warning("feed %s failed: %s", feed.name, reason)
        return {"feed": feed.name, "ok": False, "rows": 0, "error": reason}

    imported, skipped, buf = 0, 0, []
    try:
        for row in _iter_csv_rows(tmp, feed.member):
            raw = row.get(feed.column) or row.get(feed.column.replace("_", " ")) or ""
            classified = _classify(raw, feed.kind)
            if classified is None:
                skipped += 1
                continue
            kind, value = classified
            first_seen = (row.get("first_seen_utc") or row.get("dateadded")
                          or row.get("first_seen") or "")
            buf.append((kind, value, feed.name, feed.tag, first_seen))
            if len(buf) >= batch:
                imported += store.upsert(buf)
                buf.clear()
            if imported + len(buf) >= max_rows:
                log.info("feed %s hit the %d-row cap", feed.name, max_rows)
                break
        if buf:
            imported += store.upsert(buf)
    except (OSError, csv.Error, zipfile.BadZipFile) as exc:
        store.record_feed(feed.name, feed.url, imported, f"partial: {exc}")
        return {"feed": feed.name, "ok": False, "rows": imported, "error": str(exc)}
    finally:
        tmp.unlink(missing_ok=True)

    store.record_feed(feed.name, feed.url, imported, "ok")
    log.info("feed %s: %d indicators (%d skipped)", feed.name, imported, skipped)
    return {"feed": feed.name, "ok": True, "rows": imported, "skipped": skipped}


def sync(cfg, feed_names: list[str] | None = None,
         max_rows: int = 250_000) -> dict:
    """Sync the named feeds (default: the small 'recent' set).

    Run this with internet access before deployment. It is the only Hive
    command that talks to the outside world.
    """
    store = IntelStore(intel_db_path(cfg))
    work_dir = cfg.data_dir / "intel" / "tmp"
    results = []
    for name in (feed_names or list(DEFAULT_FEEDS)):
        feed = FEEDS.get(name)
        if feed is None:
            results.append({"feed": name, "ok": False, "rows": 0,
                            "error": f"unknown feed (known: {', '.join(FEEDS)})"})
            continue
        results.append(sync_feed(store, feed, work_dir, max_rows=max_rows))
    misp_url = os.environ.get(MISP_FEED_ENV, "")
    if misp_url:
        results.append(sync_misp(store, misp_url, work_dir, max_rows))
    summary = {"results": results,
               "total_rows": sum(r["rows"] for r in results),
               "failed": [r["feed"] for r in results if not r["ok"]],
               "stats": store.stats()}
    store.close()
    return summary


def sync_misp(store: IntelStore, base_url: str, work_dir: Path,
              max_rows: int = 250_000) -> dict:
    """Import a MISP community feed (a directory of event JSON + manifest).

    Only attribute types HexBee can act on offline are kept.
    """
    import json

    keep = {"sha256": "sha256", "sha1": "sha1", "md5": "md5",
            "ip-src": "ip", "ip-dst": "ip", "domain": "domain",
            "hostname": "domain", "url": "url"}
    work_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = work_dir / "misp-manifest.json"
    try:
        _download(base_url.rstrip("/") + "/manifest.json", manifest_path)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as exc:
        store.record_feed("misp", base_url, 0, f"failed: {exc}")
        return {"feed": "misp", "ok": False, "rows": 0, "error": str(exc)}

    imported, buf = 0, []
    for event_uuid in list(manifest)[:500]:
        event_path = work_dir / f"misp-{event_uuid}.json"
        try:
            _download(f"{base_url.rstrip('/')}/{event_uuid}.json", event_path)
            doc = json.loads(event_path.read_text(encoding="utf-8"))
        except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
            continue
        finally:
            event_path.unlink(missing_ok=True)
        for attr in doc.get("Event", {}).get("Attribute", []):
            kind = keep.get(attr.get("type", ""))
            if not kind:
                continue
            value = str(attr.get("value", "")).strip()
            if value:
                buf.append((kind, value if kind == "url" else value.lower(),
                            "misp", str(attr.get("category", "")), ""))
        if len(buf) >= 5000:
            imported += store.upsert(buf)
            buf.clear()
        if imported >= max_rows:
            break
    if buf:
        imported += store.upsert(buf)
    manifest_path.unlink(missing_ok=True)
    store.record_feed("misp", base_url, imported, "ok")
    return {"feed": "misp", "ok": True, "rows": imported}
