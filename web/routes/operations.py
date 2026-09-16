"""Production workflow APIs for jobs, responders, service clients, and learning."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from pathlib import Path

from flask import Blueprint, jsonify, request, session

from scripts.common import audit
from scripts.learning import LearningStore
from web.security import current_org_id, permission_required
from web.services.responders import (
    approve_responder_action,
    create_responder_action,
    execute_responder_action,
    reject_responder_action,
)


ROOT = Path(__file__).resolve().parents[2]
operations_bp = Blueprint("operations", __name__)
ALLOWED_API_SCOPES = {"alert.ingest"}


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(ROOT / "data" / "soc_operator.db"))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def _case_exists(conn: sqlite3.Connection, case_id: int, org_id: int) -> bool:
    return conn.execute("SELECT 1 FROM cases WHERE id = ? AND org_id = ?", (case_id, org_id)).fetchone() is not None


@operations_bp.get("/api/cases/<int:case_id>/responders")
@permission_required("chat.read")
def list_case_responders(case_id: int):
    conn = _db()
    org_id = int(current_org_id(conn))
    if not _case_exists(conn, case_id, org_id):
        conn.close()
        return jsonify({"error": "not found"}), 404
    rows = conn.execute(
        "SELECT * FROM responder_actions WHERE case_id = ? AND org_id = ? ORDER BY created_at DESC",
        (case_id, org_id),
    ).fetchall()
    conn.close()
    return jsonify({"ok": True, "actions": [_public_responder(row) for row in rows]})


@operations_bp.post("/api/cases/<int:case_id>/responders")
@permission_required("case.update")
def propose_case_responder(case_id: int):
    payload = request.get_json(silent=True) or {}
    action_type = str(payload.get("action_type", "")).strip()
    target = str(payload.get("target", "")).strip()
    if not action_type or not target or len(target) > 512:
        return jsonify({"error": "action_type and a target of at most 512 characters are required"}), 400
    conn = _db()
    org_id = int(current_org_id(conn))
    if not _case_exists(conn, case_id, org_id):
        conn.close()
        return jsonify({"error": "not found"}), 404
    try:
        action = create_responder_action(
            conn,
            action_type=action_type,
            target=target,
            case_id=case_id,
            requested_by=int(session["user_id"]),
            org_id=org_id,
        )
        conn.commit()
    except ValueError as exc:
        conn.close()
        return jsonify({"error": str(exc)}), 400
    conn.close()
    return jsonify({"ok": True, "action": action}), 201


@operations_bp.post("/api/responders/<int:action_id>/approve")
@permission_required("responder.approve")
def approve_responder(action_id: int):
    conn = _db()
    org_id = int(current_org_id(conn))
    try:
        result = approve_responder_action(conn, action_id, int(session["user_id"]), org_id)
        conn.commit()
    except PermissionError as exc:
        conn.close()
        return jsonify({"error": str(exc)}), 403
    except ValueError as exc:
        conn.close()
        return jsonify({"error": str(exc)}), 400
    conn.close()
    return jsonify({"ok": True, **result})


@operations_bp.post("/api/responders/<int:action_id>/reject")
@permission_required("responder.approve")
def reject_responder(action_id: int):
    payload = request.get_json(silent=True) or {}
    conn = _db()
    org_id = int(current_org_id(conn))
    try:
        result = reject_responder_action(conn, action_id, int(session["user_id"]), org_id, str(payload.get("reason", "")))
        conn.commit()
    except ValueError as exc:
        conn.close()
        return jsonify({"error": str(exc)}), 400
    conn.close()
    return jsonify({"ok": True, **result})


@operations_bp.post("/api/responders/<int:action_id>/execute")
@permission_required("responder.execute")
def execute_responder(action_id: int):
    conn = _db()
    org_id = int(current_org_id(conn))
    try:
        # Phase 0-7 intentionally records a completed dry-run; live adapters stay disabled.
        result = execute_responder_action(conn, action_id, org_id, real_execution_enabled=False)
        conn.commit()
    except PermissionError as exc:
        conn.close()
        return jsonify({"error": str(exc)}), 403
    except ValueError as exc:
        conn.close()
        return jsonify({"error": str(exc)}), 400
    conn.close()
    return jsonify({"ok": True, **result})


@operations_bp.get("/api/jobs/<job_id>")
@permission_required("chat.read")
def get_job(job_id: str):
    conn = _db()
    org_id = int(current_org_id(conn))
    row = conn.execute(
        "SELECT id, run_id, status, progress, attempt_count, max_attempts, error_message, created_at, started_at, finished_at FROM jobs WHERE id = ? AND org_id = ?",
        (job_id, org_id),
    ).fetchone()
    conn.close()
    return (jsonify(dict(row)), 200) if row else (jsonify({"error": "not found"}), 404)


@operations_bp.post("/api/jobs/<job_id>/<action>")
@permission_required("tool.execute")
def control_job(job_id: str, action: str):
    from web.app import job_queue

    conn = _db()
    org_id = int(current_org_id(conn))
    exists = conn.execute("SELECT 1 FROM jobs WHERE id = ? AND org_id = ?", (job_id, org_id)).fetchone()
    conn.close()
    if not exists:
        return jsonify({"error": "not found"}), 404
    controls = {"pause": job_queue.pause_job, "resume": job_queue.resume_job, "cancel": job_queue.cancel_job}
    handler = controls.get(action)
    if not handler:
        return jsonify({"error": "unsupported job action"}), 400
    changed = handler(job_id)
    return jsonify({"ok": changed, "job_id": job_id, "action": action}), (200 if changed else 409)


@operations_bp.get("/api/service-clients")
@permission_required("api_client.manage")
def list_service_clients():
    conn = _db()
    rows = conn.execute(
        "SELECT id, name, scopes_json, active, created_at, last_used_at FROM api_clients WHERE org_id = ? ORDER BY created_at DESC",
        (current_org_id(conn),),
    ).fetchall()
    conn.close()
    return jsonify({"ok": True, "clients": [dict(row) for row in rows]})


@operations_bp.post("/api/service-clients")
@permission_required("api_client.manage")
def create_service_client():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    scopes = set(payload.get("scopes") or [])
    if not name or len(name) > 120 or not scopes or not scopes.issubset(ALLOWED_API_SCOPES):
        return jsonify({"error": "valid name and supported scopes are required"}), 400
    token = "soc_" + secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    conn = _db()
    cursor = conn.execute(
        "INSERT INTO api_clients (org_id, name, token_hash, scopes_json, created_by) VALUES (?, ?, ?, ?, ?)",
        (current_org_id(conn), name, digest, json.dumps(sorted(scopes)), session["user_id"]),
    )
    conn.commit()
    client_id = int(cursor.lastrowid)
    conn.close()
    audit("api_client_created", client_id=client_id, org_id=session.get("org_id"), scopes=sorted(scopes))
    # This is the sole response containing the service secret; only its hash is stored.
    return jsonify({"ok": True, "id": client_id, "token": token, "scopes": sorted(scopes)}), 201


@operations_bp.delete("/api/service-clients/<int:client_id>")
@permission_required("api_client.manage")
def revoke_service_client(client_id: int):
    conn = _db()
    updated = conn.execute(
        "UPDATE api_clients SET active = 0 WHERE id = ? AND org_id = ?",
        (client_id, current_org_id(conn)),
    ).rowcount
    conn.commit()
    conn.close()
    if not updated:
        return jsonify({"error": "not found"}), 404
    audit("api_client_revoked", client_id=client_id, org_id=session.get("org_id"))
    return jsonify({"ok": True})


@operations_bp.post("/api/learning/suggestions/<int:suggestion_id>/evaluate")
@permission_required("learning.review")
def evaluate_learning_suggestion(suggestion_id: int):
    payload = request.get_json(silent=True) or {}
    try:
        score = float(payload.get("score"))
    except (TypeError, ValueError):
        return jsonify({"error": "numeric score is required"}), 400
    passed = bool(payload.get("passed")) and score >= 0.8
    try:
        evaluation_id = LearningStore().record_evaluation(
            suggestion_id,
            org_id=int(current_org_id()),
            corpus_version=str(payload.get("corpus_version", "")).strip() or "manual-v1",
            score=score,
            passed=passed,
            evaluated_by=int(session["user_id"]),
            details=payload.get("details") if isinstance(payload.get("details"), dict) else {},
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify({"ok": True, "evaluation_id": evaluation_id, "passed": passed}), 201


@operations_bp.post("/api/learning/suggestions/<int:suggestion_id>/transition")
@permission_required("learning.review")
def transition_learning_suggestion(suggestion_id: int):
    payload = request.get_json(silent=True) or {}
    try:
        result = LearningStore().transition_suggestion(
            suggestion_id,
            org_id=int(current_org_id()),
            status=str(payload.get("status", "")),
            reviewed_by=int(session["user_id"]),
        )
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 403
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"ok": True, **result})


def _public_responder(row) -> dict:
    result = dict(row)
    result["preview"] = json.loads(result.pop("preview_json") or "{}")
    result["result"] = json.loads(result.pop("result_json") or "null")
    result.pop("approval_digest", None)
    return result

