"""Envelope boundary for integration secrets stored by the local application."""

from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


ROOT = Path(__file__).resolve().parents[2]
KEY_FILE = ROOT / "data" / ".credential_key"
PREFIX = "enc:v1:"


def _load_key() -> bytes:
    configured = os.environ.get("AI_SOC_CREDENTIAL_KEY", "").strip()
    if configured:
        try:
            raw = base64.urlsafe_b64decode(configured.encode("ascii"))
            if len(raw) != 32:
                raise ValueError
            return base64.urlsafe_b64encode(raw)
        except Exception as exc:
            raise RuntimeError("AI_SOC_CREDENTIAL_KEY must be a URL-safe base64 encoded 32-byte key") from exc

    if os.environ.get("AI_SOC_ENV", "development").lower() == "production":
        raise RuntimeError("AI_SOC_CREDENTIAL_KEY is required in production")

    # Local mode keeps a stable, owner-readable key outside version control.
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not KEY_FILE.exists():
        KEY_FILE.write_bytes(Fernet.generate_key())
        try:
            KEY_FILE.chmod(0o600)
        except OSError:
            pass
    return KEY_FILE.read_bytes().strip()


def seal_secret(value: str) -> str:
    if not value or value.startswith(PREFIX):
        return value
    token = Fernet(_load_key()).encrypt(value.encode("utf-8")).decode("ascii")
    return PREFIX + token


def open_secret(value: str) -> str:
    if not value or not value.startswith(PREFIX):
        return value
    try:
        return Fernet(_load_key()).decrypt(value[len(PREFIX):].encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError("Stored credential cannot be decrypted with the configured key") from exc


def is_sealed(value: str) -> bool:
    return bool(value and value.startswith(PREFIX))


def migrate_plaintext_credentials(conn) -> int:
    """Seal legacy rows in one transaction without exposing their values."""
    migrated = 0
    for row in conn.execute("SELECT id, key_value FROM credentials").fetchall():
        if row["key_value"] and not is_sealed(row["key_value"]):
            conn.execute("UPDATE credentials SET key_value = ? WHERE id = ?", (seal_secret(row["key_value"]), row["id"]))
            migrated += 1
    if migrated:
        conn.commit()
    return migrated
