"""Organization-local user administration and reviewed access-policy routes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import generate_password_hash

from scripts.common import ROOT, audit
from web.security import current_org_id, permission_required
from web.services.credential_vault import open_secret
from web.services.organization_policy import (
    active_policy,
    apply_active_policy_roles,
    approve_policy_draft,
    create_policy_draft,
    reject_policy_draft,
    roles_for_policy_username,
)


admin_bp = Blueprint("admin", __name__)
DB_PATH = ROOT / "data" / "soc_operator.db"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def _request_data() -> dict:
    return request.get_json(silent=True) or request.form.to_dict(flat=True)


def _role_ids(data: dict) -> list[int]:
    values = data.get("role_ids", [])
    if not isinstance(values, list):
        values = request.form.getlist("role_ids") if request.form else [values]
    try:
        return sorted({int(value) for value in values if str(value).strip()})
    except (TypeError, ValueError) as exc:
        raise ValueError("role_ids must contain numeric role IDs") from exc


def _new_invitation(conn, *, org_id: int, user_id: int, created_by: int) -> str:
    # Persist only a digest so a database copy cannot be used as an activation link.
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "UPDATE user_invitations SET used_at = CURRENT_TIMESTAMP WHERE org_id = ? AND user_id = ? AND used_at IS NULL",
        (org_id, user_id),
    )
    conn.execute(
        """
        INSERT INTO user_invitations (org_id, user_id, token_hash, created_by, expires_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (org_id, user_id, digest, created_by, expires_at),
    )
    return token


def _activation_url(token: str) -> str:
    path = url_for("admin.activate_user", token=token)
    public_url = os.environ.get("AI_SOC_PUBLIC_URL", "").strip().rstrip("/")
    if public_url.startswith(("https://", "http://")):
        return f"{public_url}{path}"
    # A relative URL avoids constructing a security-sensitive link from an
    # untrusted Host header; the browser UI resolves it against its own origin.
    return path


@admin_bp.get("/admin/users")
@permission_required("user.manage")
def users_page():
    conn = _get_db()
    org_id = int(current_org_id(conn))
    user_rows = conn.execute(
        """
        SELECT u.id, u.username, u.display_name, u.email, u.disabled_at,
               u.must_change_password, om.status
        FROM organization_memberships om
        JOIN users u ON u.id = om.user_id
        WHERE om.org_id = ?
        ORDER BY lower(u.username)
        """,
        (org_id,),
    ).fetchall()
    roles = conn.execute("SELECT id, name FROM roles ORDER BY name").fetchall()
    users = []
    for row in user_rows:
        assignments = conn.execute(
            """
            SELECT r.id, r.name, ur.source FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            WHERE ur.org_id = ? AND ur.user_id = ? ORDER BY r.name
            """,
            (org_id, row["id"]),
        ).fetchall()
        users.append(
            {
                **dict(row),
                "role_names": ", ".join(item["name"] for item in assignments),
                "assigned_role_ids": {int(item["id"]) for item in assignments},
                "policy_role_ids": {int(item["id"]) for item in assignments if item["source"] == "policy"},
            }
        )
    conn.close()
    return render_template("admin_users.html", users=users, roles=roles)


@admin_bp.get("/api/admin/users")
@permission_required("user.manage")
def list_users():
    conn = _get_db()
    org_id = int(current_org_id(conn))
    rows = conn.execute(
        """
        SELECT u.id, u.username, u.display_name, u.email, u.disabled_at,
               u.must_change_password, om.status
        FROM users u JOIN organization_memberships om ON om.user_id = u.id
        WHERE om.org_id = ? ORDER BY lower(u.username)
        """,
        (org_id,),
    ).fetchall()
    result = []
    for row in rows:
        roles = conn.execute(
            """
            SELECT r.id, r.name, ur.source FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            WHERE ur.org_id = ? AND ur.user_id = ? ORDER BY r.name
            """,
            (org_id, row["id"]),
        ).fetchall()
        result.append({**dict(row), "roles": [dict(role) for role in roles]})
    conn.close()
    return jsonify({"ok": True, "users": result})


@admin_bp.post("/api/admin/users")
@permission_required("user.manage")
def create_user():
    data = _request_data()
    username = str(data.get("username", "")).strip()
    display_name = str(data.get("display_name", "")).strip()[:120] or None
    email = str(data.get("email", "")).strip().lower()[:254] or None
    if not USERNAME_RE.fullmatch(username):
        return jsonify({"error": "username must be 3-64 letters, numbers, dots, underscores, or hyphens"}), 400
    if email and not EMAIL_RE.fullmatch(email):
        return jsonify({"error": "email address is invalid"}), 400
    try:
        selected_role_ids = _role_ids(data)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    conn = _get_db()
    org_id = int(current_org_id(conn))
    policy = active_policy(conn, org_id)
    policy_roles = roles_for_policy_username(policy, username)
    known_roles = {
        int(row["id"]): row["name"]
        for row in conn.execute("SELECT id, name FROM roles").fetchall()
    }
    if any(role_id not in known_roles for role_id in selected_role_ids):
        conn.close()
        return jsonify({"error": "one or more roles do not exist"}), 400
    if not selected_role_ids and not policy_roles:
        conn.close()
        return jsonify({"error": "select a role or approve a policy assignment for this username"}), 400
    try:
        # Account, membership, roles, and invitation commit as one operation.
        cursor = conn.execute(
            """
            INSERT INTO users
                (username, password_hash, display_name, email, default_org_id, must_change_password)
            VALUES (?, ?, ?, ?, ?, 1)
            """,
            (username, generate_password_hash(secrets.token_urlsafe(48), method="scrypt"), display_name, email, org_id),
        )
        user_id = int(cursor.lastrowid)
        conn.execute(
            "INSERT INTO organization_memberships (org_id, user_id, status) VALUES (?, ?, 'active')",
            (org_id, user_id),
        )
        for role_id in selected_role_ids:
            conn.execute(
                "INSERT INTO user_roles (user_id, role_id, org_id, source) VALUES (?, ?, ?, 'manual')",
                (user_id, role_id, org_id),
            )
        apply_active_policy_roles(conn, org_id=org_id, user_id=user_id, username=username)
        token = _new_invitation(conn, org_id=org_id, user_id=user_id, created_by=int(session["user_id"]))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        conn.close()
        return jsonify({"error": "username already exists"}), 409
    conn.close()
    audit("organization_user_invited", org_id=org_id, user_id=user_id, actor_id=session["user_id"])
    return jsonify(
        {
            "ok": True,
            "user_id": user_id,
            "activation_url": _activation_url(token),
            "expires_in_hours": 24,
            "policy_roles": policy_roles,
        }
    ), 201


def _membership_admin_count(conn: sqlite3.Connection, org_id: int) -> int:
    return int(
        conn.execute(
            """
            SELECT COUNT(DISTINCT ur.user_id) FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            JOIN organization_memberships om ON om.user_id = ur.user_id AND om.org_id = ur.org_id
            JOIN users u ON u.id = ur.user_id
            WHERE ur.org_id = ? AND r.name = 'admin' AND om.status = 'active' AND u.disabled_at IS NULL
            """,
            (org_id,),
        ).fetchone()[0]
    )


@admin_bp.post("/api/admin/users/<int:user_id>/suspend")
@permission_required("user.manage")
def suspend_user(user_id: int):
    conn = _get_db()
    org_id = int(current_org_id(conn))
    if user_id == int(session["user_id"]):
        conn.close()
        return jsonify({"error": "you cannot suspend your own account"}), 409
    is_admin = conn.execute(
        """
        SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id
        WHERE ur.org_id = ? AND ur.user_id = ? AND r.name = 'admin'
        """,
        (org_id, user_id),
    ).fetchone()
    if is_admin and _membership_admin_count(conn, org_id) <= 1:
        conn.close()
        return jsonify({"error": "organization must retain at least one active admin"}), 409
    updated = conn.execute(
        "UPDATE organization_memberships SET status = 'suspended' WHERE org_id = ? AND user_id = ? AND status = 'active'",
        (org_id, user_id),
    ).rowcount
    if not updated:
        conn.close()
        return jsonify({"error": "active organization user not found"}), 404
    conn.commit()
    conn.close()
    audit("organization_user_suspended", org_id=org_id, user_id=user_id, actor_id=session["user_id"])
    return jsonify({"ok": True, "status": "suspended"})


@admin_bp.post("/api/admin/users/<int:user_id>/resume")
@permission_required("user.manage")
def resume_user(user_id: int):
    conn = _get_db()
    org_id = int(current_org_id(conn))
    updated = conn.execute(
        "UPDATE organization_memberships SET status = 'active' WHERE org_id = ? AND user_id = ? AND status = 'suspended'",
        (org_id, user_id),
    ).rowcount
    if not updated:
        conn.close()
        return jsonify({"error": "suspended organization user not found"}), 404
    user = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if user:
        apply_active_policy_roles(conn, org_id=org_id, user_id=user_id, username=user["username"])
    conn.commit()
    conn.close()
    audit("organization_user_resumed", org_id=org_id, user_id=user_id, actor_id=session["user_id"])
    return jsonify({"ok": True, "status": "active"})


@admin_bp.post("/api/admin/users/<int:user_id>/reset-activation")
@permission_required("user.manage")
def reset_activation(user_id: int):
    conn = _get_db()
    org_id = int(current_org_id(conn))
    member = conn.execute(
        "SELECT 1 FROM organization_memberships WHERE org_id = ? AND user_id = ?",
        (org_id, user_id),
    ).fetchone()
    if not member:
        conn.close()
        return jsonify({"error": "organization user not found"}), 404
    conn.execute(
        """
        UPDATE users SET password_hash = ?, must_change_password = 1,
            session_version = COALESCE(session_version, 0) + 1
        WHERE id = ?
        """,
        (generate_password_hash(secrets.token_urlsafe(48), method="scrypt"), user_id),
    )
    token = _new_invitation(conn, org_id=org_id, user_id=user_id, created_by=int(session["user_id"]))
    conn.commit()
    conn.close()
    audit("organization_user_activation_reset", org_id=org_id, user_id=user_id, actor_id=session["user_id"])
    return jsonify({"ok": True, "activation_url": _activation_url(token), "expires_in_hours": 24})


def _invitation(conn: sqlite3.Connection, token: str):
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return conn.execute(
        """
        SELECT i.*, u.username FROM user_invitations i JOIN users u ON u.id = i.user_id
        WHERE i.token_hash = ? AND i.used_at IS NULL AND i.expires_at > CURRENT_TIMESTAMP
        """,
        (digest,),
    ).fetchone()


@admin_bp.route("/activate/<token>", methods=["GET", "POST"])
def activate_user(token: str):
    conn = _get_db()
    invitation = _invitation(conn, token)
    if not invitation:
        conn.close()
        return render_template("activate.html", invalid=True), 400
    if request.method == "POST":
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        if len(password) < 12 or password != confirmation:
            conn.close()
            flash("Passwords must match and contain at least 12 characters", "error")
            return render_template("activate.html", username=invitation["username"]), 400
        conn.execute(
            """
            UPDATE users SET password_hash = ?, must_change_password = 0,
                password_changed_at = CURRENT_TIMESTAMP WHERE id = ?
            """,
            (generate_password_hash(password, method="scrypt"), invitation["user_id"]),
        )
        claimed = conn.execute(
            "UPDATE user_invitations SET used_at = CURRENT_TIMESTAMP WHERE id = ? AND used_at IS NULL",
            (invitation["id"],),
        ).rowcount
        if not claimed:
            conn.rollback()
            conn.close()
            return render_template("activate.html", invalid=True), 409
        conn.commit()
        conn.close()
        audit("organization_user_activated", org_id=invitation["org_id"], user_id=invitation["user_id"])
        flash("Account activated. Sign in with your new password.", "success")
        return redirect(url_for("login"))
    username = invitation["username"]
    conn.close()
    return render_template("activate.html", username=username)


@admin_bp.get("/admin/policy")
@permission_required("policy.manage")
def policy_page():
    conn = _get_db()
    org_id = int(current_org_id(conn))
    active = conn.execute(
        "SELECT * FROM organization_policies WHERE org_id = ? AND active = 1 ORDER BY version DESC LIMIT 1",
        (org_id,),
    ).fetchone()
    drafts = conn.execute(
        "SELECT * FROM organization_policy_drafts WHERE org_id = ? ORDER BY created_at DESC LIMIT 20",
        (org_id,),
    ).fetchall()
    conn.close()
    return render_template("admin_policy.html", active=active, drafts=drafts)


@admin_bp.post("/admin/policy/upload")
@permission_required("policy.manage")
def upload_policy():
    uploaded = request.files.get("policy")
    if not uploaded or not uploaded.filename:
        flash("Select an organization playbook", "error")
        return redirect(url_for("admin.policy_page"))
    suffix = Path(uploaded.filename).suffix.lower()
    if suffix not in {".yaml", ".yml", ".json", ".pdf", ".docx", ".md", ".txt"}:
        flash("Unsupported organization playbook format", "error")
        return redirect(url_for("admin.policy_page"))
    conn = _get_db()
    org_id = int(current_org_id(conn))
    known_playbooks = sorted(path.name for path in (ROOT / "playbooks").glob("*.yaml"))
    llm_callback = None
    if suffix not in {".yaml", ".yml", ".json"}:
        credential = conn.execute(
            "SELECT key_value FROM credentials WHERE org_id = ? AND key_name = 'OPENAI_API_KEY'",
            (org_id,),
        ).fetchone()
        if credential:
            from scripts.soc_client.openai import OpenAIClient

            client = OpenAIClient(open_secret(credential["key_value"]))
            llm_callback = lambda system, prompt: client.chat(prompt, system=system)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp:
            uploaded.save(temp.name)
            temp_path = Path(temp.name)
        result = create_policy_draft(
            conn,
            org_id=org_id,
            source_path=temp_path,
            source_name=uploaded.filename,
            created_by=int(session["user_id"]),
            llm_callback=llm_callback,
            known_playbooks=known_playbooks,
        )
        conn.commit()
        flash(f"Policy draft {result['id']} extracted. Review it before approval.", "success")
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        conn.rollback()
        flash(str(exc)[:300], "error")
    finally:
        conn.close()
        if temp_path:
            temp_path.unlink(missing_ok=True)
    return redirect(url_for("admin.policy_page"))


@admin_bp.post("/api/admin/policies/<int:draft_id>/approve")
@permission_required("policy.approve")
def approve_policy(draft_id: int):
    conn = _get_db()
    org_id = int(current_org_id(conn))
    try:
        result = approve_policy_draft(conn, draft_id, org_id=org_id, approved_by=int(session["user_id"]))
        conn.commit()
    except (ValueError, PermissionError) as exc:
        conn.rollback()
        conn.close()
        return jsonify({"error": str(exc)}), 409
    conn.close()
    return jsonify({"ok": True, **result})


@admin_bp.post("/api/admin/policies/<int:draft_id>/reject")
@permission_required("policy.approve")
def reject_policy(draft_id: int):
    data = _request_data()
    reason = str(data.get("reason", "")).strip()
    if not reason:
        return jsonify({"error": "rejection reason is required"}), 400
    conn = _get_db()
    org_id = int(current_org_id(conn))
    try:
        reject_policy_draft(conn, draft_id, org_id=org_id, rejected_by=int(session["user_id"]), reason=reason)
        conn.commit()
    except ValueError as exc:
        conn.rollback()
        conn.close()
        return jsonify({"error": str(exc)}), 409
    conn.close()
    return jsonify({"ok": True, "status": "rejected"})
