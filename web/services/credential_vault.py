"""Envelope boundary for integration secrets stored by the local application."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


ROOT = Path(__file__).resolve().parents[2]
KEY_FILE = ROOT / "data" / ".credential_key"
PREFIX = "enc:v1:"
PREFIX_V2 = "enc:v2:"


def _validated_key(value: str, variable: str) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(value.encode("ascii"))
        if len(raw) != 32:
            raise ValueError
        return base64.urlsafe_b64encode(raw)
    except Exception as exc:
        raise RuntimeError(f"{variable} must contain URL-safe base64 encoded 32-byte keys") from exc


def _keyring() -> tuple[str | None, dict[str, bytes]]:
    configured = os.environ.get("AI_SOC_CREDENTIAL_KEYS", "").strip()
    if not configured:
        return None, {}
    try:
        values = json.loads(configured)
    except json.JSONDecodeError as exc:
        raise RuntimeError("AI_SOC_CREDENTIAL_KEYS must be a JSON object") from exc
    if not isinstance(values, dict) or not values:
        raise RuntimeError("AI_SOC_CREDENTIAL_KEYS must be a non-empty JSON object")
    keys = {str(key_id): _validated_key(str(value), "AI_SOC_CREDENTIAL_KEYS") for key_id, value in values.items()}
    active = os.environ.get("AI_SOC_CREDENTIAL_ACTIVE_KEY", "").strip()
    if active not in keys:
        raise RuntimeError("AI_SOC_CREDENTIAL_ACTIVE_KEY must name an entry in AI_SOC_CREDENTIAL_KEYS")
    return active, keys


def _load_key() -> bytes:
    configured = os.environ.get("AI_SOC_CREDENTIAL_KEY", "").strip()
    if configured:
        return _validated_key(configured, "AI_SOC_CREDENTIAL_KEY")

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
    if not value or value.startswith((PREFIX, PREFIX_V2)):
        return value
    active, keys = _keyring()
    if active:
        token = Fernet(keys[active]).encrypt(value.encode("utf-8")).decode("ascii")
        return f"{PREFIX_V2}{active}:{token}"
    token = Fernet(_load_key()).encrypt(value.encode("utf-8")).decode("ascii")
    return PREFIX + token


def open_secret(value: str) -> str:
    if not value or not value.startswith((PREFIX, PREFIX_V2)):
        return value
    try:
        if value.startswith(PREFIX_V2):
            key_id, token = value[len(PREFIX_V2):].split(":", 1)
            _active, keys = _keyring()
            if key_id not in keys:
                raise RuntimeError(f"Stored credential requires unavailable key id {key_id!r}")
            return Fernet(keys[key_id]).decrypt(token.encode("ascii")).decode("utf-8")
        return Fernet(_load_key()).decrypt(value[len(PREFIX):].encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError("Stored credential cannot be decrypted with the configured key") from exc


def is_sealed(value: str) -> bool:
    return bool(value and value.startswith((PREFIX, PREFIX_V2)))


def rotate_credentials(conn) -> int:
    """Re-encrypt every credential with the active keyring key in one transaction."""
    active, _keys = _keyring()
    if not active:
        raise RuntimeError("credential rotation requires AI_SOC_CREDENTIAL_KEYS and AI_SOC_CREDENTIAL_ACTIVE_KEY")
    rotated = 0
    try:
        for row in conn.execute("SELECT id, key_value FROM credentials").fetchall():
            value = str(row["key_value"] or "")
            if not value or value.startswith(f"{PREFIX_V2}{active}:"):
                continue
            plaintext = open_secret(value)
            # seal_secret always selects the active key; plaintext never leaves process memory.
            conn.execute("UPDATE credentials SET key_value = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (seal_secret(plaintext), row["id"]))
            rotated += 1
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return rotated


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
