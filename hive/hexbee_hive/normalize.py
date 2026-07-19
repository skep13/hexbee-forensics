"""Event normalization.

Scouts send loosely-structured JSON; this module converts it into the one
canonical shape everything downstream (storage, correlation, timeline,
reporting) relies on:

    {
        "device":     str,     # Scout name, e.g. "Scout01"
        "event_type": str,     # snake_case type, e.g. "usb_inserted"
        "occurred_at": str,    # UTC ISO-8601
        "payload":    dict,    # type-specific details
    }

Anything that can't be coerced into that shape raises NormalizationError and
is rejected (rejections are still audit-logged by the ingest pipeline so a
misbehaving Scout is visible).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

# Known event types with default severities (0=info .. 3=critical).
# Unknown types are accepted at severity 0 so new Scout capabilities don't
# require a Hive upgrade first.
EVENT_SEVERITY = {
    "scout_online": 0,
    "scout_offline": 0,
    "heartbeat": 0,
    "usb_inserted": 1,
    "usb_removed": 0,
    "usb_scan": 1,
    "file_metadata": 0,
    "executable_found": 2,
    "script_found": 2,
    "autorun_found": 3,
    "process_launched": 1,
    "powershell_launched": 2,
    "network_discovered": 1,
    "network_beacon": 3,
    "host_info": 0,
    "evidence_uploaded": 1,
    # Comb (Queen-side analysis) artifacts
    "analysis_started": 0,
    "analysis_completed": 0,
    "artifact_mismatch": 2,
    "artifact_image_gps": 1,
    "artifact_web_visit": 0,
    "carved_file": 1,
    # iPhone field companion
    "field_photo": 1,
}

_NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
_TYPE_RE = re.compile(r"^[a-z0-9_]{1,64}$")


class NormalizationError(ValueError):
    pass


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_timestamp(value) -> str:
    """Accept ISO-8601 strings or unix epoch numbers; return UTC ISO-8601."""
    if value is None:
        return _utcnow_iso()
    if isinstance(value, (int, float)):
        try:
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise NormalizationError(f"bad epoch timestamp: {value!r}") from exc
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise NormalizationError(f"bad timestamp: {value!r}") from exc
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    raise NormalizationError(f"unsupported timestamp type: {type(value).__name__}")


def normalize(raw: dict) -> dict:
    if not isinstance(raw, dict):
        raise NormalizationError("event must be a JSON object")

    device = raw.get("device") or raw.get("device_id") or raw.get("scout")
    if not isinstance(device, str) or not _NAME_RE.match(device):
        raise NormalizationError(f"missing or invalid device name: {device!r}")

    event_type = raw.get("event_type") or raw.get("type")
    if not isinstance(event_type, str):
        raise NormalizationError("missing event_type")
    event_type = event_type.strip().lower().replace("-", "_").replace(" ", "_")
    if not _TYPE_RE.match(event_type):
        raise NormalizationError(f"invalid event_type: {event_type!r}")

    payload = raw.get("payload", {})
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise NormalizationError("payload must be a JSON object")

    occurred_at = _parse_timestamp(raw.get("occurred_at") or raw.get("timestamp"))

    return {
        "device": device,
        "event_type": event_type,
        "occurred_at": occurred_at,
        "payload": payload,
        "severity": EVENT_SEVERITY.get(event_type, 0),
    }
