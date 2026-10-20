"""Administrative AI provider and ChatGPT OAuth connection routes."""

from __future__ import annotations

import re
import subprocess
import threading
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, session

from scripts.common import audit
from scripts.soc_client.codex_oauth import (
    codex_command,
    codex_environment,
    codex_home_for_org,
    codex_login_status,
)
from web.security import current_org_id, permission_required
from web.services.credential_vault import open_secret, seal_secret


ai_provider_bp = Blueprint("ai_provider", __name__)
_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_URL_RE = re.compile(r"https://auth\.openai\.com/[^\s]+")
_CODE_RE = re.compile(r"\b[A-Z0-9]{4,8}-[A-Z0-9]{4,8}\b")
_processes: dict[int, subprocess.Popen[str]] = {}
_process_lock = threading.Lock()


def _db():
    # Imported lazily because app.py registers this blueprint after defining get_db.
    from web.app import get_db

    return get_db()


def _update_session(session_id: int, **values) -> None:
    if not values:
        return
    allowed = {"verification_uri", "user_code", "status", "error_message", "process_id"}
    unknown = set(values) - allowed
    if unknown:
        raise ValueError(f"unsupported device-session fields: {', '.join(sorted(unknown))}")
    conn = _db()
    try:
        assignments = ", ".join(f"{name} = ?" for name in values)
        # Column names are constrained to the fixed allowlist above.
        conn.execute(
            f"UPDATE codex_device_sessions SET {assignments}, updated_at = CURRENT_TIMESTAMP WHERE id = ?",  # nosec B608
            (*values.values(), session_id),
        )
        conn.commit()
    finally:
        conn.close()


def _watch_device_login(org_id: int, session_id: int, process: subprocess.Popen[str]) -> None:
    """Capture only the verification URL/code, never the resulting OAuth token."""
    error_lines: list[str] = []
    try:
        assert process.stdout is not None
        for raw_line in process.stdout:
            line = _ANSI_RE.sub("", raw_line).strip()
            url = _URL_RE.search(line)
            code = _CODE_RE.search(line)
            updates: dict[str, str] = {}
            if url:
                updates["verification_uri"] = url.group(0)
            if code:
                updates["user_code"] = seal_secret(code.group(0))
                updates["status"] = "waiting"
            if updates:
                _update_session(session_id, **updates)
            elif line:
                error_lines.append(line[:300])
                error_lines = error_lines[-5:]
        return_code = process.wait()
        if return_code == 0 and codex_login_status(org_id):
            _update_session(session_id, status="connected", user_code=None, error_message=None)
            audit("ai_oauth_connected", org_id=org_id, device_session_id=session_id)
        else:
            detail = " ".join(error_lines)[-500:] or f"Codex login exited with status {return_code}"
            _update_session(session_id, status="failed", user_code=None, error_message=detail)
            audit("ai_oauth_failed", org_id=org_id, device_session_id=session_id)
    except Exception as exc:
        _update_session(session_id, status="failed", user_code=None, error_message=str(exc)[:500])
        audit("ai_oauth_failed", org_id=org_id, device_session_id=session_id)
    finally:
        with _process_lock:
            if _processes.get(org_id) is process:
                _processes.pop(org_id, None)


def _terminate_active_login(org_id: int) -> None:
    with _process_lock:
        process = _processes.pop(org_id, None)
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


@ai_provider_bp.route("/api/ai/codex/connect", methods=["POST"])
@permission_required("credential.manage")
def connect_codex():
    conn = _db()
    org_id = int(current_org_id(conn))
    user_id = int(session["user_id"])
    conn.close()
    _terminate_active_login(org_id)

    try:
        home = codex_home_for_org(org_id)
        process = subprocess.Popen(
            codex_command("login", "--device-auth"),
            cwd=str(home),
            env=codex_environment(home),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except (OSError, RuntimeError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503

    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    try:
        conn = _db()
        try:
            conn.execute(
                "UPDATE codex_device_sessions SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP "
                "WHERE org_id = ? AND status IN ('starting', 'waiting')",
                (org_id,),
            )
            cursor = conn.execute(
                """
                INSERT INTO codex_device_sessions
                    (org_id, requested_by, status, process_id, expires_at)
                VALUES (?, ?, 'starting', ?, ?)
                """,
                (org_id, user_id, process.pid, expires_at),
            )
            session_id = int(cursor.lastrowid)
            conn.commit()
        finally:
            conn.close()
    except Exception:
        # Do not leave a login helper alive when its auditable database record
        # could not be created.
        process.terminate()
        raise

    with _process_lock:
        _processes[org_id] = process
    threading.Thread(
        target=_watch_device_login,
        args=(org_id, session_id, process),
        name=f"codex-login-org-{org_id}",
        daemon=True,
    ).start()
    audit("ai_oauth_requested", org_id=org_id, user_id=user_id, device_session_id=session_id)
    return jsonify({"ok": True, "status": "starting"}), 202


@ai_provider_bp.route("/api/ai/codex/status", methods=["GET"])
@permission_required("credential.manage")
def codex_status():
    conn = _db()
    org_id = int(current_org_id(conn))
    row = conn.execute(
        "SELECT * FROM codex_device_sessions WHERE org_id = ? ORDER BY id DESC LIMIT 1", (org_id,)
    ).fetchone()
    conn.close()
    connected = codex_login_status(org_id)
    payload = {
        "ok": True,
        "connected": connected,
        "status": "connected" if connected else (str(row["status"]) if row else "disconnected"),
    }
    if row and row["status"] in {"starting", "waiting"}:
        payload.update(
            verification_uri=row["verification_uri"],
            user_code=open_secret(row["user_code"] or ""),
            expires_at=row["expires_at"],
        )
    if row and row["status"] == "failed":
        payload["error"] = row["error_message"]
    return jsonify(payload)


@ai_provider_bp.route("/api/ai/codex/disconnect", methods=["POST"])
@permission_required("credential.manage")
def disconnect_codex():
    conn = _db()
    org_id = int(current_org_id(conn))
    user_id = int(session["user_id"])
    _terminate_active_login(org_id)
    try:
        home = codex_home_for_org(org_id)
        result = subprocess.run(
            codex_command("logout"),
            cwd=str(home),
            env=codex_environment(home),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if result.returncode != 0 and codex_login_status(org_id):
            return jsonify({"ok": False, "error": "Codex logout failed"}), 502
        conn.execute(
            "UPDATE codex_device_sessions SET status = 'disconnected', user_code = NULL, "
            "updated_at = CURRENT_TIMESTAMP WHERE org_id = ? AND status IN ('starting', 'waiting', 'connected')",
            (org_id,),
        )
        conn.execute("DELETE FROM ai_provider_config WHERE org_id = ? AND provider = 'codex_oauth'", (org_id,))
        conn.commit()
    finally:
        conn.close()
    audit("ai_oauth_disconnected", org_id=org_id, user_id=user_id)
    return jsonify({"ok": True, "status": "disconnected"})
