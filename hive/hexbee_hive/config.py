"""Configuration for the HexBee Hive.

All settings come from environment variables with sane defaults for a
Raspberry Pi 3B+ deployment. A `HEXBEE_` prefix is used throughout so the
Hive can coexist with other services on the same host.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(f"HEXBEE_{name}", default)


@dataclass
class HiveConfig:
    # Storage
    data_dir: Path = field(
        default_factory=lambda: Path(_env("DATA_DIR", str(Path.home() / "hexbee-data")))
    )

    # MQTT broker (Mosquitto on localhost by default)
    mqtt_host: str = field(default_factory=lambda: _env("MQTT_HOST", "127.0.0.1"))
    mqtt_port: int = field(default_factory=lambda: int(_env("MQTT_PORT", "1883")))
    mqtt_topic: str = field(default_factory=lambda: _env("MQTT_TOPIC", "hexbee/events/#"))
    mqtt_username: str = field(default_factory=lambda: _env("MQTT_USERNAME", ""))
    mqtt_password: str = field(default_factory=lambda: _env("MQTT_PASSWORD", ""))
    # Path to a CA certificate enables TLS for MQTT.
    mqtt_tls_ca: str = field(default_factory=lambda: _env("MQTT_TLS_CA", ""))

    # Web dashboard / REST API
    web_host: str = field(default_factory=lambda: _env("WEB_HOST", "0.0.0.0"))
    web_port: int = field(default_factory=lambda: int(_env("WEB_PORT", "8080")))

    # Shared key Scouts present when using the REST ingest endpoint.
    # Empty string disables REST ingest entirely (MQTT-only mode).
    ingest_key: str = field(default_factory=lambda: _env("INGEST_KEY", ""))

    # Correlation engine tuning
    correlation_window_seconds: int = field(
        default_factory=lambda: int(_env("CORRELATION_WINDOW", "600"))
    )

    # Session tokens expire after this many hours.
    token_ttl_hours: int = field(default_factory=lambda: int(_env("TOKEN_TTL_HOURS", "12")))

    # Local AI (Ollama / llama.cpp server on the LAN; never the internet).
    ai_url: str = field(default_factory=lambda: _env("AI_URL", "http://127.0.0.1:11434"))
    ai_model: str = field(default_factory=lambda: _env("AI_MODEL", "llama3.2"))

    # -- Security --------------------------------------------------------
    # Set when the Hive is served over HTTPS (behind a reverse proxy). Adds
    # the Secure flag to cookies and enables HSTS.
    secure_cookies: bool = field(
        default_factory=lambda: _env("SECURE_COOKIES", "0") in ("1", "true", "yes"))
    # Minimum password length (NIST 800-63B: length over complexity).
    min_password_length: int = field(
        default_factory=lambda: int(_env("MIN_PASSWORD_LENGTH", "12")))
    # Brute-force lockout: N failures within the window locks the account/IP.
    login_max_attempts: int = field(
        default_factory=lambda: int(_env("LOGIN_MAX_ATTEMPTS", "5")))
    login_lockout_seconds: int = field(
        default_factory=lambda: int(_env("LOGIN_LOCKOUT_SECONDS", "300")))
    # Explicit HMAC key for signing exports/CSRF/anchors. If empty, a random
    # key is generated once and persisted to <data_dir>/.hexbee_signing_key.
    signing_key_env: str = field(default_factory=lambda: _env("SIGNING_KEY", ""))

    @property
    def maps_dir(self) -> Path:
        return self.data_dir / "maps"

    @property
    def reference_dir(self) -> Path:
        return self.data_dir / "reference"

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "hive.db"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        for sub in ("exports", "maps", "reference", "evidence"):
            (self.data_dir / sub).mkdir(exist_ok=True)

    @property
    def signing_key(self) -> bytes:
        """Stable secret for HMAC (signed exports, chain anchors, CSRF).

        Prefers HEXBEE_SIGNING_KEY; otherwise generates a random key once and
        persists it 0600 in the data dir so signatures survive restarts.
        """
        if self.signing_key_env:
            return self.signing_key_env.encode("utf-8")
        key_path = self.data_dir / ".hexbee_signing_key"
        if key_path.exists():
            return key_path.read_bytes()
        import secrets
        key = secrets.token_bytes(32)
        key_path.write_bytes(key)
        try:
            key_path.chmod(0o600)
        except OSError:
            pass  # Windows / unsupported FS
        return key


def load_config() -> HiveConfig:
    cfg = HiveConfig()
    cfg.ensure_dirs()
    return cfg
