"""Operational helpers shared by the CLI and the web Admin page:
the security-posture report."""

from __future__ import annotations

from .integrity import verify_chain


def security_report(cfg, db) -> dict:
    """Structured security posture: {'ok': [...], 'warn': [...], 'critical': [...]}.

    Used by `hexbee-hive security-check` and the dashboard Admin page.
    """
    ok: list[str] = []
    warn: list[str] = []
    critical: list[str] = []

    if cfg.ingest_key:
        if len(cfg.ingest_key) >= 16:
            ok.append("ingest key set (>=16 chars)")
        else:
            warn.append("ingest key is short (<16 chars)")
    else:
        warn.append("REST ingest disabled (no ingest key) — MQTT-only")

    if cfg.secure_cookies:
        ok.append("secure cookies + HSTS enabled (HTTPS deployment)")
    else:
        warn.append("secure cookies off — serve behind HTTPS in production")

    if cfg.signing_key_env:
        ok.append("explicit signing key configured")
    else:
        ok.append("signing key auto-generated and persisted (0600)")

    admins = db.query_one(
        "SELECT COUNT(*) AS n FROM users WHERE role='administrator' AND disabled=0")
    if not admins or admins["n"] == 0:
        warn.append("no active administrator account exists yet")
    else:
        ok.append(f"{admins['n']} active administrator account(s)")

    chain = verify_chain(db)
    if chain["ok"]:
        ok.append(f"evidence chain verified ({chain['checked']} events)")
    else:
        critical.append(f"EVIDENCE CHAIN BROKEN at event {chain['first_bad_id']}")

    ok.append(f"password policy: min {cfg.min_password_length} chars + screening")
    ok.append(f"login lockout: {cfg.login_max_attempts} attempts / {cfg.login_lockout_seconds}s")

    return {"ok": ok, "warn": warn, "critical": critical, "chain": chain}
