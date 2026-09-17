"""Shared web security boundaries for authentication, authorization, and CSRF."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from flask import abort, jsonify, redirect, request, session, url_for

from scripts.common import audit


ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "data" / "soc_operator.db"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
CSRF_EXEMPT_ENDPOINTS = {
    "webhooks.webhook_test",
}


def get_security_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def consume_rate_limit(conn: sqlite3.Connection, bucket_key: str, limit: int, window_seconds: int = 60) -> bool:
    """Consume one database-backed request slot shared by all WSGI workers."""
    now = int(datetime.now(timezone.utc).timestamp())
    window = datetime.fromtimestamp(now - (now % window_seconds), timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        """
        INSERT INTO api_rate_limits (bucket_key, window_start, request_count)
        VALUES (?, ?, 1)
        ON CONFLICT(bucket_key, window_start) DO UPDATE SET request_count = request_count + 1
        """,
        (bucket_key[:200], window),
    )
    count = conn.execute(
        "SELECT request_count FROM api_rate_limits WHERE bucket_key = ? AND window_start = ?",
        (bucket_key[:200], window),
    ).fetchone()["request_count"]
    # Opportunistic cleanup keeps this security table bounded.
    conn.execute("DELETE FROM api_rate_limits WHERE window_start < datetime('now', '-1 day')")
    conn.commit()
    return int(count) <= max(1, limit)


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def enforce_csrf() -> None:
    """Reject state-changing session requests without a session-bound token."""
    if request.method in SAFE_METHODS or request.endpoint in CSRF_EXEMPT_ENDPOINTS:
        return
    # Cookie-less service clients use bearer authentication. A request carrying
    # a browser session must still pass CSRF even if it adds a bogus bearer header.
    if request.headers.get("Authorization", "").startswith("Bearer ") and session.get("user_id") is None:
        return
    expected = session.get("csrf_token")
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    if not expected or not supplied or not hmac.compare_digest(str(expected), str(supplied)):
        audit("csrf_rejected", route=request.path, method=request.method, user_id=session.get("user_id"))
        abort(400, description="CSRF validation failed")


def current_org_id(conn: sqlite3.Connection | None = None) -> int | None:
    org_id = session.get("org_id")
    user_id = session.get("user_id")
    if user_id is None:
        return None
    own_conn = conn is None
    conn = conn or get_security_db()
    try:
        if org_id is not None:
            row = conn.execute(
                """
                SELECT om.org_id FROM organization_memberships om
                JOIN users u ON u.id = om.user_id
                WHERE om.user_id = ? AND om.org_id = ? AND om.status = 'active'
                  AND u.disabled_at IS NULL AND COALESCE(u.session_version, 0) = ?
                """,
                (user_id, int(org_id), int(session.get("session_version", 0))),
            ).fetchone()
        else:
            row = conn.execute(
                """
                SELECT om.org_id FROM organization_memberships om
                JOIN users u ON u.id = om.user_id
                WHERE om.user_id = ? AND om.status = 'active'
                  AND u.disabled_at IS NULL AND COALESCE(u.session_version, 0) = ?
                ORDER BY om.id LIMIT 1
                """,
                (user_id, int(session.get("session_version", 0))),
            ).fetchone()
        if row:
            session["org_id"] = int(row["org_id"])
            return int(row["org_id"])
        return None
    finally:
        if own_conn:
            conn.close()


def permissions_for_user(conn: sqlite3.Connection, user_id: int, org_id: int | None) -> set[str]:
    if org_id is None:
        return set()
    else:
        rows = conn.execute(
            """
            SELECT r.permissions
            FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            JOIN organization_memberships om ON om.user_id = ur.user_id AND om.org_id = ? AND om.status = 'active'
            WHERE ur.user_id = ? AND ur.org_id = ?
            """,
            (org_id, user_id, org_id),
        ).fetchall()
    permissions: set[str] = set()
    for row in rows:
        try:
            permissions.update(json.loads(row["permissions"] or "[]"))
        except (TypeError, json.JSONDecodeError):
            continue
    return permissions


def roles_for_user(conn: sqlite3.Connection, user_id: int, org_id: int | None) -> set[str]:
    if org_id is None:
        return set()
    query = "SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ?"
    params: list[Any] = [user_id]
    query += " AND ur.org_id = ? AND EXISTS (SELECT 1 FROM organization_memberships om WHERE om.user_id = ur.user_id AND om.org_id = ur.org_id AND om.status = 'active')"
    params.append(org_id)
    return {str(row["name"]) for row in conn.execute(query, params).fetchall()}


def _deny(permission: str | None = None):
    audit(
        "authorization_denied",
        user_id=session.get("user_id"),
        org_id=session.get("org_id"),
        route=request.path,
        permission=permission,
    )
    if request.path.startswith("/api/"):
        body = {"error": "forbidden"}
        if permission:
            body["required_permission"] = permission
        return jsonify(body), 403
    abort(403)


def login_required(view: Callable):
    @wraps(view)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login"))
        conn = get_security_db()
        try:
            org_id = current_org_id(conn)
        finally:
            conn.close()
        if org_id is None:
            # Membership suspension takes effect immediately, even for an
            # already-issued signed session cookie.
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"error": "active organization membership required"}), 403
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return decorated


def permission_required(permission: str):
    def decorator(view: Callable):
        @wraps(view)
        def decorated(*args, **kwargs):
            user_id = session.get("user_id")
            if user_id is None:
                if request.path.startswith("/api/"):
                    return jsonify({"error": "unauthorized"}), 401
                return redirect(url_for("login"))
            conn = get_security_db()
            try:
                org_id = current_org_id(conn)
                permissions = permissions_for_user(conn, int(user_id), org_id)
            finally:
                conn.close()
            if permission not in permissions:
                return _deny(permission)
            return view(*args, **kwargs)
        return decorated
    return decorator


def role_required(role_name: str):
    def decorator(view: Callable):
        @wraps(view)
        def decorated(*args, **kwargs):
            user_id = session.get("user_id")
            if user_id is None:
                return jsonify({"error": "unauthorized"}), 401
            conn = get_security_db()
            try:
                roles = roles_for_user(conn, int(user_id), current_org_id(conn))
            finally:
                conn.close()
            if role_name not in roles and "admin" not in roles:
                return _deny(f"role:{role_name}")
            return view(*args, **kwargs)
        return decorated
    return decorator


def authenticate_api_client(required_scope: str) -> tuple[int, int] | None:
    """Authenticate a service token without ever persisting the plaintext token."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header[7:].strip()
    if not token:
        return None
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    conn = get_security_db()
    try:
        row = conn.execute(
            "SELECT id, org_id, scopes_json FROM api_clients WHERE token_hash = ? AND active = 1",
            (digest,),
        ).fetchone()
        if not row:
            return None
        scopes = set(json.loads(row["scopes_json"] or "[]"))
        if required_scope not in scopes:
            return None
        conn.execute("UPDATE api_clients SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?", (row["id"],))
        conn.commit()
        return int(row["id"]), int(row["org_id"])
    finally:
        conn.close()


def session_or_api_scope(permission: str):
    """Allow either an authorized analyst session or a scoped service token."""
    def decorator(view: Callable):
        @wraps(view)
        def decorated(*args, **kwargs):
            has_bearer = request.headers.get("Authorization", "").startswith("Bearer ")
            api_identity = authenticate_api_client(permission)
            if api_identity:
                request.api_client_id, request.api_org_id = api_identity
                return view(*args, **kwargs)
            if has_bearer:
                return jsonify({"error": "invalid or insufficient service token"}), 401
            user_id = session.get("user_id")
            if user_id is None:
                return jsonify({"error": "unauthorized"}), 401
            conn = get_security_db()
            try:
                org_id = current_org_id(conn)
                allowed = permission in permissions_for_user(conn, int(user_id), org_id)
            finally:
                conn.close()
            if not allowed:
                return _deny(permission)
            request.api_client_id, request.api_org_id = None, org_id
            return view(*args, **kwargs)
        return decorated
    return decorator
