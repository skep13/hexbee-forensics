"""EXIF extraction — camera identity, timestamps, and crucially GPS.

Coordinates recovered here become `artifact_image_gps` events in the Hive
and light up as markers on its offline evidence map.
"""

from __future__ import annotations

from pathlib import Path

from PIL import ExifTags, Image

_GPS_TAG = 34853  # GPSInfo IFD pointer
_DT_ORIGINAL = 36867


def _to_float(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        num, den = value
        return num / den


def _dms_to_degrees(dms, ref: str) -> float:
    degrees = _to_float(dms[0]) + _to_float(dms[1]) / 60 + _to_float(dms[2]) / 3600
    return -degrees if ref in ("S", "W") else degrees


def extract(path: str | Path) -> dict | None:
    """EXIF summary for one image, or None if unreadable/absent.

    {"make", "model", "taken_at", "lat", "lon"} — GPS keys only when present.
    """
    try:
        with Image.open(path) as img:
            exif = img.getexif()
            if not exif:
                return None
            out: dict = {}
            make = exif.get(271)
            model = exif.get(272)
            if make:
                out["make"] = str(make).strip("\x00 ")
            if model:
                out["model"] = str(model).strip("\x00 ")

            try:
                sub = exif.get_ifd(ExifTags.IFD.Exif)
                taken = sub.get(_DT_ORIGINAL)
                if taken:
                    out["taken_at"] = str(taken)
            except (KeyError, AttributeError):
                pass

            try:
                gps = exif.get_ifd(ExifTags.IFD.GPSInfo)
            except (KeyError, AttributeError):
                gps = None
            if gps and 2 in gps and 4 in gps:
                try:
                    out["lat"] = round(_dms_to_degrees(gps[2], gps.get(1, "N")), 6)
                    out["lon"] = round(_dms_to_degrees(gps[4], gps.get(3, "E")), 6)
                except (TypeError, ValueError, ZeroDivisionError, IndexError):
                    pass
            return out or None
    except (OSError, ValueError):
        return None
