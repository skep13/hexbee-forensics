"""Authentication and role-based access control.

Stdlib-only on purpose (pbkdf2 via hashlib, tokens via secrets): the Hive
targets a 1 GB Pi and an air-gap-friendly dependency footprint.

Roles:
    administrator — everything, including user management
    investigator  — create/edit cases, tag evidence, close incidents
    viewer        — read-only
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from .db import Database
from .store import audit

ROLES = ("administrator", "investigator", "viewer")
# Role inheritance: an administrator can do anything an investigator can, etc.
_ROLE_RANK = {"viewer": 0, "investigator": 1, "administrator": 2}

_PBKDF2_ITERATIONS = 600_000
DEFAULT_MIN_PASSWORD_LENGTH = 12

# Rejected outright regardless of length (NIST 800-63B "known bad" list).
_COMMON_PASSWORDS = frozenset({
    "password", "password1", "password123", "passw0rd", "12345678", "123456789",
    "1234567890", "qwertyuiop", "letmein", "changeme", "admin123", "iloveyou",
    "welcome1", "hexbee", "hexbee123", "forensics", "administrator",
})


def validate_password(password: str, username: str = "", min_length: int = DEFAULT_MIN_PASSWORD_LENGTH) -> None:
    """Raise ValueError if the password fails policy. NIST 800-63B style:
    reward length, screen against known-bad and username-derived values."""
    if len(password) < min_length:
        raise ValueError(f"password must be at least {min_length} characters")
    if password.lower() in _COMMON_PASSWORDS:
        raise ValueError("password is too common; choose something unique")
    if username and password.lower() == username.lower():
        raise ValueError("password must not equal the username")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), _PBKDF2_ITERATIONS
    ).hex()
    return f"pbkdf2:sha256:{_PBKDF2_ITERATIONS}:{salt}:{digest}"


def check_password(password: str, stored: str) -> bool:
    try:
        _, _, iters, salt, digest = stored.split(":")
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt), int(iters)
        ).hex()
        return hmac.compare_digest(candidate, digest)
    except (ValueError, TypeError):
        return False


def create_user(db: Database, username: str, password: str, role: str,
                actor: str = "system", min_length: int = DEFAULT_MIN_PASSWORD_LENGTH) -> int:
    if role not in ROLES:
        raise ValueError(f"invalid role {role!r}; must be one of {ROLES}")
    if not username or not username.strip():
        raise ValueError("username is required")
    validate_password(password, username, min_length)
    cur = db.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
        (username, hash_password(password), role, _fmt(_now())),
    )
    audit(db, actor, "user_created", f"{username} ({role})")
    return cur.lastrowid


def authenticate(db: Database, username: str, password: str, ttl_hours: int = 12,
                 source_ip: str = "") -> dict | None:
    """Verify credentials; on success mint an API token. `source_ip` is
    recorded in the audit trail for incident response."""
    ip_note = f"ip={source_ip}" if source_ip else ""
    row = db.query_one(
        "SELECT * FROM users WHERE username = ? AND disabled = 0", (username,)
    )
    # Always run the KDF (even for unknown users) to avoid a username-
    # enumeration timing oracle.
    stored = row["password_hash"] if row else (
        "pbkdf2:sha256:600000:" + "00" * 16 + ":" + "0" * 64)
    ok = check_password(password, stored)
    if row is None or not ok:
        audit(db, username or "(blank)", "login_failed", ip_note)
        return None
    token = secrets.token_urlsafe(32)
    db.execute(
        "INSERT INTO api_tokens (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (token, row["id"], _fmt(_now()), _fmt(_now() + timedelta(hours=ttl_hours))),
    )
    audit(db, username, "login_ok", ip_note)
    return {"token": token, "username": row["username"], "role": row["role"]}


def resolve_token(db: Database, token: str) -> dict | None:
    """Return {'username', 'role'} for a live token, else None."""
    if not token:
        return None
    row = db.query_one(
        """SELECT u.username, u.role, t.expires_at
           FROM api_tokens t JOIN users u ON u.id = t.user_id
           WHERE t.token = ? AND u.disabled = 0""",
        (token,),
    )
    if row is None:
        return None
    if row["expires_at"] < _fmt(_now()):
        db.execute("DELETE FROM api_tokens WHERE token = ?", (token,))
        return None
    return {"username": row["username"], "role": row["role"]}


def revoke_token(db: Database, token: str) -> None:
    db.execute("DELETE FROM api_tokens WHERE token = ?", (token,))


def role_allows(user_role: str, required_role: str) -> bool:
    return _ROLE_RANK.get(user_role, -1) >= _ROLE_RANK.get(required_role, 99)


def set_user_disabled(db: Database, username: str, disabled: bool, actor: str) -> bool:
    cur = db.execute(
        "UPDATE users SET disabled = ? WHERE username = ?", (1 if disabled else 0, username)
    )
    if cur.rowcount:
        if disabled:
            db.execute(
                "DELETE FROM api_tokens WHERE user_id = "
                "(SELECT id FROM users WHERE username = ?)",
                (username,),
            )
        audit(db, actor, "user_disabled" if disabled else "user_enabled", username)
    return bool(cur.rowcount)
