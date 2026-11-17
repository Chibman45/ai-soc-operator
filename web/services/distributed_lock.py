"""Database-backed leases used to serialize multi-host worker operations."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

LOCK_SCHEMA = """
CREATE TABLE IF NOT EXISTS worker_leases (
    lock_name TEXT PRIMARY KEY,
    owner_token TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""


def init_lock_schema(conn) -> None:
    conn.execute(LOCK_SCHEMA)
    conn.commit()


def acquire_lease(conn, lock_name: str, *, ttl_seconds: int = 300, owner_token: str | None = None) -> str | None:
    """Acquire or replace an expired lease atomically across SQLite/PostgreSQL."""
    if not lock_name.strip():
        raise ValueError("lock name is required")
    owner = owner_token or secrets.token_urlsafe(24)
    now = datetime.now(timezone.utc)  # noqa: UP017 - Python 3.10 support.
    expires = now + timedelta(seconds=max(15, int(ttl_seconds)))
    cursor = conn.execute(
        """
        INSERT INTO worker_leases (lock_name, owner_token, expires_at, updated_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(lock_name) DO UPDATE SET
            owner_token = excluded.owner_token,
            expires_at = excluded.expires_at,
            updated_at = CURRENT_TIMESTAMP
        WHERE worker_leases.expires_at <= ? OR worker_leases.owner_token = excluded.owner_token
        """,
        (lock_name.strip()[:240], owner, expires.isoformat(), now.isoformat()),
    )
    conn.commit()
    return owner if int(cursor.rowcount) > 0 else None


def release_lease(conn, lock_name: str, owner_token: str) -> bool:
    cursor = conn.execute("DELETE FROM worker_leases WHERE lock_name = ? AND owner_token = ?", (lock_name, owner_token))
    conn.commit()
    return int(cursor.rowcount) == 1
