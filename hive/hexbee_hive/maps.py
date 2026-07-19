"""Offline evidence map: MBTiles tile server + evidence GPS points.

Drop any raster MBTiles file (the standard offline map container — exports
from OpenMapTiles, Mobile Atlas Creator, QGIS, tilemill, etc.) into
`<data_dir>/maps/`. The Hive serves its tiles to the dashboard's built-in
viewer with zero internet access.

With no MBTiles installed the viewer still works: tiles fall back to a
generated placeholder grid so evidence coordinates can always be plotted
relative to each other in the field.
"""

from __future__ import annotations

import json
import sqlite3
import struct
import threading
import zlib
from pathlib import Path


class TileStore:
    def __init__(self, maps_dir: Path):
        self.maps_dir = Path(maps_dir)
        self.maps_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._path: Path | None = None
        self._format = "png"

    def _connect(self) -> sqlite3.Connection | None:
        """Lazily open the first .mbtiles in maps_dir (re-checked so the user
        can drop a file in without restarting the Hive)."""
        with self._lock:
            if self._conn is not None and self._path is not None and self._path.exists():
                return self._conn
            candidates = sorted(self.maps_dir.glob("*.mbtiles"))
            if not candidates:
                self._conn = None
                return None
            self._path = candidates[0]
            self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
            row = self._conn.execute(
                "SELECT value FROM metadata WHERE name = 'format'").fetchone()
            self._format = (row[0] if row else "png").lower()
            return self._conn

    @property
    def source_name(self) -> str | None:
        conn = self._connect()
        return self._path.name if conn else None

    @property
    def content_type(self) -> str:
        return {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                "webp": "image/webp"}.get(self._format, "image/png")

    def tile(self, z: int, x: int, y: int) -> bytes | None:
        """XYZ tile from the MBTiles (which stores TMS: y is flipped)."""
        conn = self._connect()
        if conn is None:
            return None
        tms_y = (2 ** z) - 1 - y
        with self._lock:
            row = conn.execute(
                "SELECT tile_data FROM tiles WHERE zoom_level=? AND tile_column=? "
                "AND tile_row=?",
                (z, x, tms_y),
            ).fetchone()
        return row[0] if row else None


def evidence_points(db) -> list[dict]:
    """Every event whose payload carries lat/lon becomes a map marker."""
    points = []
    rows = db.query(
        """SELECT e.id, e.event_type, e.occurred_at, e.payload, e.incident_id,
                  d.name AS device
           FROM events e JOIN devices d ON d.id = e.device_id
           WHERE e.payload LIKE '%"lat"%' AND e.payload LIKE '%"lon"%'
           ORDER BY e.id DESC LIMIT 1000"""
    )
    for row in rows:
        payload = json.loads(row["payload"])
        lat, lon = payload.get("lat"), payload.get("lon")
        if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
            continue
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            continue
        label = payload.get("name") or payload.get("note") or row["event_type"]
        points.append({
            "event_id": row["id"], "lat": lat, "lon": lon,
            "label": f"{label} ({row['device']}, {row['occurred_at']})",
            "event_type": row["event_type"], "incident_id": row["incident_id"],
        })
    return points


# -- placeholder tile (no PIL needed: hand-built PNG) ---------------------

def _build_placeholder_tile() -> bytes:
    """256×256 dark tile with a border, generated with stdlib only."""
    width = height = 256
    bg = (26, 22, 12)        # hive dark
    line = (74, 63, 38)      # hive line color
    raw = bytearray()
    for y in range(height):
        raw.append(0)  # filter: none
        for x in range(width):
            on_border = x == 0 or y == 0
            raw.extend(line if on_border else bg)

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(bytes(raw), 6))
            + chunk(b"IEND", b""))


PLACEHOLDER_TILE = _build_placeholder_tile()
