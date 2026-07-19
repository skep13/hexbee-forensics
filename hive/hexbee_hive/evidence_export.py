"""Forensic-grade evidence export: signed case bundles and chain anchors.

Two integrity primitives on top of the append-only hash chain:

1. **Chain anchor** — a signed, point-in-time receipt of the evidence log's
   head hash and event count. Print it / show it as a QR at the start of an
   engagement; later, `verify_anchor` proves the log still contains that exact
   prefix and nobody rewound history. (A02/A08.)

2. **Signed case bundle** — a self-contained, court-ready export: a manifest
   (case, timeline, chain verification, anchor, audit trail, and the SHA-256
   of every included evidence file), the evidence files themselves, and an
   HMAC-SHA256 signature over the manifest. `verify_bundle` re-checks the
   signature and re-hashes every file, so any post-export tampering is caught
   offline with only the signing key.

The HMAC key is the Hive's persistent signing key (see HiveConfig.signing_key).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .integrity import canonical_json, verify_chain
from .reports import case_report_data
from .timeline import case_timeline


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sign(key: bytes, payload: str) -> str:
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


# -- chain anchor ---------------------------------------------------------

def chain_anchor(db, key: bytes) -> dict:
    """A signed receipt pinning the current head of the evidence chain."""
    row = db.query_one("SELECT COUNT(*) AS n FROM events")
    count = row["n"] if row else 0
    head = db.query_one("SELECT event_hash FROM events ORDER BY id DESC LIMIT 1")
    head_hash = head["event_hash"] if head else "0" * 64
    body = {"head_hash": head_hash, "event_count": count, "generated_at": _now(),
            "tool": f"hexbee-hive {__version__}"}
    body["signature"] = _sign(key, canonical_json(body))
    return body


def verify_anchor(db, anchor: dict, key: bytes) -> dict:
    """Check a prior anchor against the current log."""
    body = {k: anchor.get(k) for k in ("head_hash", "event_count", "generated_at", "tool")}
    sig_ok = hmac.compare_digest(_sign(key, canonical_json(body)), anchor.get("signature", ""))
    if not sig_ok:
        return {"ok": False, "reason": "signature mismatch (wrong key or altered anchor)"}
    count = anchor["event_count"]
    if count == 0:
        return {"ok": True, "reason": "empty-log anchor"}
    row = db.query_one("SELECT event_hash FROM events ORDER BY id LIMIT 1 OFFSET ?",
                       (count - 1,))
    if row is None:
        return {"ok": False, "reason": "log now has fewer events than the anchor — truncated"}
    if row["event_hash"] != anchor["head_hash"]:
        return {"ok": False, "reason": "event at anchored position has a different hash — history was rewritten"}
    # The stored head still matches; also recompute the chain to catch an
    # in-place edit of any event *inside* the anchored prefix (which wouldn't
    # change later stored hashes on its own).
    chain = verify_chain(db)
    if not chain["ok"] and chain["first_bad_id"] is not None and chain["first_bad_id"] <= count:
        return {"ok": False, "reason": "history was rewritten within the anchored prefix "
                f"(chain breaks at event {chain['first_bad_id']})"}
    return {"ok": True, "reason": f"log still contains the anchored prefix of {count} events"}


# -- signed case bundle ---------------------------------------------------

def export_case(db, cfg, case_id: int, key: bytes, actor: str = "system") -> dict | None:
    """Write a signed evidence bundle for a case. Returns a summary or None
    if the case doesn't exist."""
    report = case_report_data(db, case_id)
    if report is None:
        return None

    number = report["case"]["case_number"]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    bundle_dir = Path(cfg.data_dir) / "exports" / f"{number}_{stamp}"
    files_dir = bundle_dir / "files"
    files_dir.mkdir(parents=True, exist_ok=True)

    # Collect evidence files referenced by this case's timeline that physically
    # exist in the evidence store; verify each against its chained hash.
    evidence_files = []
    seen = set()
    for entry in case_timeline(db, case_id):
        payload = entry.get("payload", {})
        name = payload.get("name")
        recorded = payload.get("sha256")
        if not name or name in seen:
            continue
        src = Path(cfg.evidence_dir) / name
        if not src.is_file():
            continue
        seen.add(name)
        actual = _sha256_file(src)
        shutil.copy2(src, files_dir / Path(name).name)
        evidence_files.append({
            "name": Path(name).name,
            "sha256": actual,
            "size": src.stat().st_size,
            "chain_sha256": recorded,
            "hash_matches_chain": (recorded == actual) if recorded else None,
        })

    audit_trail = [dict(r) for r in db.query("SELECT * FROM audit_log ORDER BY id")]

    manifest = {
        "format": "hexbee-evidence-bundle/1",
        "generated_at": _now(),
        "generated_by": actor,
        "tool": f"hexbee-hive {__version__}",
        "case": report["case"],
        "timeline": report["timeline"],
        "chain_verification": report["integrity"],
        "anchor": chain_anchor(db, key),
        "evidence_files": evidence_files,
        "audit_trail": audit_trail,
    }
    manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False)
    (bundle_dir / "manifest.json").write_text(manifest_bytes, encoding="utf-8")
    signature = _sign(key, canonical_json(manifest))
    (bundle_dir / "manifest.sig").write_text(
        json.dumps({"algorithm": "HMAC-SHA256", "signature": signature}, indent=2),
        encoding="utf-8")
    (bundle_dir / "VERIFY.txt").write_text(
        "HexBee evidence bundle\n"
        "Verify offline with:  hexbee-hive verify-bundle <this-directory>\n"
        "This re-checks the HMAC signature over manifest.json and re-hashes\n"
        "every file in files/ against manifest.json.\n", encoding="utf-8")

    return {
        "bundle_dir": str(bundle_dir),
        "case_number": number,
        "evidence_files": len(evidence_files),
        "chain_ok": report["integrity"]["ok"],
        "signature": signature,
    }


def verify_bundle(bundle_dir: str | Path, key: bytes) -> dict:
    """Re-verify a bundle offline: signature + every evidence file hash."""
    bundle_dir = Path(bundle_dir)
    manifest_path = bundle_dir / "manifest.json"
    sig_path = bundle_dir / "manifest.sig"
    if not manifest_path.is_file() or not sig_path.is_file():
        return {"ok": False, "reason": "manifest.json or manifest.sig missing"}

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = json.loads(sig_path.read_text(encoding="utf-8")).get("signature", "")
    if not hmac.compare_digest(_sign(key, canonical_json(manifest)), expected):
        return {"ok": False, "reason": "manifest signature invalid (altered or wrong key)"}

    file_issues = []
    for ef in manifest.get("evidence_files", []):
        fpath = bundle_dir / "files" / ef["name"]
        if not fpath.is_file():
            file_issues.append(f"{ef['name']}: missing")
        elif _sha256_file(fpath) != ef["sha256"]:
            file_issues.append(f"{ef['name']}: hash mismatch")
    if file_issues:
        return {"ok": False, "reason": "evidence file integrity failure", "files": file_issues}

    return {"ok": True, "reason": "signature valid and all evidence files intact",
            "case_number": manifest.get("case", {}).get("case_number"),
            "evidence_files": len(manifest.get("evidence_files", []))}
