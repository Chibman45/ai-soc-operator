"""Routes for features 1-6: alerts, RBAC, credentials health, queue, case assignment, IOC correlation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from flask import Blueprint, jsonify, request, session
from scripts.common import audit
from web.security import (
    current_org_id,
    login_required as _login_required,
    permission_required as _require_permission,
    role_required as _require_role,
    session_or_api_scope,
)

ROOT = Path(__file__).resolve().parents[2]

features_bp = Blueprint("features", __name__)


def _get_db():
    import sqlite3
    db_path = ROOT / "data" / "soc_operator.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def _parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _hours_between(start: str | None, end: str | None) -> float | None:
    try:
        start_at = _parse_utc(start)
        end_at = _parse_utc(end)
        if not start_at or not end_at:
            return None
        return round(max(0.0, (end_at - start_at).total_seconds() / 3600), 2)
    except (TypeError, ValueError):
        return None


# ═══════════════════════════════════════════
# Feature 1: Alert Ingestion
# ═══════════════════════════════════════════

@features_bp.post("/api/ingest/alert")
@session_or_api_scope("alert.ingest")
def ingest_alert():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"ok": False, "error": "JSON object required"}), 400

    source = payload.get("source", "manual")
    source_alert_id = payload.get("source_alert_id")
    supplied_observables = payload.get("observables", [])

    # The alert body may be nested under "payload" or be the top-level object.
    alert_body = payload.get("payload") if isinstance(payload.get("payload"), dict) else dict(payload)
    # Carry caller-supplied title/severity into the body so generic
    # normalization picks them up.
    if payload.get("title") and "title" not in alert_body:
        alert_body["title"] = payload["title"]
    if payload.get("severity") and "severity" not in alert_body:
        alert_body["severity"] = payload["severity"]

    conn = _get_db()
    org_id = getattr(request, "api_org_id", None) or current_org_id(conn)
    try:
        from web.services.schema_features import init_feature_db
        from web.services.alert_ingest import ingest_alert_record

        init_feature_db(conn)
        result = ingest_alert_record(
            conn,
            source=source,
            source_alert_id=source_alert_id,
            payload=alert_body,
            supplied_observables=supplied_observables,
            org_id=org_id,
        )
    except ValueError as e:
        conn.close()
        return jsonify({"ok": False, "error": str(e)[:300]}), 400
    except Exception as e:
        conn.close()
        return jsonify({"ok": False, "error": str(e)[:300]}), 500

    conn.close()
    return jsonify({
        "ok": True,
        "alert_id": result["alert_id"],
        "case_id": result["case_id"],
        "job_id": result["job_id"],
        "status": result["status"],
        "playbook": result["playbook"],
    })


# ═══════════════════════════════════════════
# Feature 4: Alert Queue
# ═══════════════════════════════════════════

@features_bp.get("/api/alerts/queue")
@_require_permission("chat.read")
def alert_queue():
    mode = request.args.get("mode", "new")
    try:
        limit = min(max(int(request.args.get("limit", "50")), 1), 200)
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400

    conn = _get_db()
    from web.services.schema_features import init_feature_db
    init_feature_db(conn)
    org_id = current_org_id(conn)

    if mode == "new":
        alerts = conn.execute(
            "SELECT a.*, j.status AS job_status FROM alerts a LEFT JOIN jobs j ON j.id = a.job_id AND j.org_id = a.org_id WHERE a.org_id = ? AND a.status IN ('new', 'queued') ORDER BY a.created_at DESC LIMIT ?",
            (org_id, limit),
        ).fetchall()
    elif mode == "all":
        alerts = conn.execute(
            "SELECT a.*, j.status AS job_status FROM alerts a LEFT JOIN jobs j ON j.id = a.job_id AND j.org_id = a.org_id WHERE a.org_id = ? ORDER BY a.created_at DESC LIMIT ?",
            (org_id, limit),
        ).fetchall()
    else:
        alerts = conn.execute(
            "SELECT a.*, j.status AS job_status FROM alerts a LEFT JOIN jobs j ON j.id = a.job_id AND j.org_id = a.org_id WHERE a.org_id = ? AND a.status = ? ORDER BY a.created_at DESC LIMIT ?",
            (org_id, mode, limit),
        ).fetchall()

    conn.close()
    return jsonify({
        "ok": True,
        "count": len(alerts),
        "alerts": [
            {
                "id": a["id"], "source": a["source"], "title": a["title"],
                "severity": a["severity"], "status": a["status"],
                "case_id": a["case_id"], "job_id": a["job_id"],
                "job_status": a["job_status"],
                "selected_playbook": a["selected_playbook"],
                "created_at": a["created_at"],
            }
            for a in alerts
        ],
    })


# ═══════════════════════════════════════════
# Feature 2: RBAC
# ═══════════════════════════════════════════

@features_bp.get("/api/roles")
@_require_permission("role.manage")
def list_roles():
    conn = _get_db()
    roles = conn.execute("SELECT * FROM roles").fetchall()
    conn.close()
    return jsonify({
        "ok": True,
        "roles": [
            {"id": r["id"], "name": r["name"], "permissions": json.loads(r["permissions"])}
            for r in roles
        ],
    })


@features_bp.post("/api/users/<int:user_id>/roles")
@_require_permission("role.manage")
def assign_role(user_id: int):
    payload = request.get_json(force=True)
    role_id = payload.get("role_id")
    if not role_id:
        return jsonify({"ok": False, "error": "role_id is required"}), 400

    conn = _get_db()
    org_id = current_org_id(conn)
    member = conn.execute("SELECT 1 FROM organization_memberships WHERE org_id = ? AND user_id = ? AND status = 'active'", (org_id, user_id)).fetchone()
    role = conn.execute("SELECT 1 FROM roles WHERE id = ?", (role_id,)).fetchone()
    if not member or not role:
        conn.close()
        return jsonify({"error": "user or role not found"}), 404
    existing = conn.execute(
        "SELECT id FROM user_roles WHERE user_id = ? AND role_id = ? AND org_id = ?",
        (user_id, role_id, org_id),
    ).fetchone()
    if existing:
        conn.close()
        return jsonify({"ok": False, "error": "role already assigned"}), 409

    conn.execute(
        "INSERT INTO user_roles (user_id, role_id, org_id, source, policy_id) VALUES (?, ?, ?, 'manual', NULL)",
        (user_id, role_id, org_id),
    )
    conn.commit()
    conn.close()
    audit(
        "organization_user_role_assigned",
        org_id=org_id,
        user_id=user_id,
        role_id=role_id,
        actor_id=session.get("user_id"),
        source="manual",
    )
    return jsonify({"ok": True})


@features_bp.delete("/api/users/<int:user_id>/roles/<int:role_id>")
@_require_permission("role.manage")
def remove_role(user_id: int, role_id: int):
    conn = _get_db()
    org_id = current_org_id(conn)
    assignment = conn.execute(
        "SELECT source FROM user_roles WHERE user_id = ? AND role_id = ? AND org_id = ?",
        (user_id, role_id, org_id),
    ).fetchone()
    if assignment and assignment["source"] == "policy":
        conn.close()
        return jsonify({"error": "role is managed by the active organization policy"}), 409
    role = conn.execute("SELECT name FROM roles WHERE id = ?", (role_id,)).fetchone()
    if role and role["name"] == "admin":
        admin_count = conn.execute(
            """
            SELECT COUNT(DISTINCT ur.user_id)
            FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            JOIN organization_memberships om ON om.user_id = ur.user_id AND om.org_id = ur.org_id
            JOIN users u ON u.id = ur.user_id
            WHERE ur.org_id = ? AND r.name = 'admin'
              AND om.status = 'active' AND u.disabled_at IS NULL
            """,
            (org_id,),
        ).fetchone()[0]
        target_has_role = conn.execute(
            "SELECT 1 FROM user_roles WHERE user_id = ? AND role_id = ? AND org_id = ?",
            (user_id, role_id, org_id),
        ).fetchone()
        if target_has_role and admin_count <= 1:
            conn.close()
            return jsonify({"error": "organization must retain at least one admin"}), 409
    removed = conn.execute(
        "DELETE FROM user_roles WHERE user_id = ? AND role_id = ? AND org_id = ?",
        (user_id, role_id, org_id),
    ).rowcount
    if not removed:
        conn.close()
        return jsonify({"error": "role assignment not found"}), 404
    conn.commit()
    conn.close()
    audit(
        "organization_user_role_removed",
        org_id=org_id,
        user_id=user_id,
        role_id=role_id,
        actor_id=session.get("user_id"),
        source="manual",
    )
    return jsonify({"ok": True})


@features_bp.get("/api/me")
@_login_required
def get_me():
    conn = _get_db()
    user = conn.execute("SELECT id, username FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    org_id = current_org_id(conn)
    roles = conn.execute(
        "SELECT r.name, r.permissions FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = ? AND ur.org_id = ?",
        (session["user_id"], org_id),
    ).fetchall()
    conn.close()

    if not user:
        return jsonify({"error": "not found"}), 404

    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "org_id": org_id,
        "roles": [role["name"] for role in roles],
        "permissions": sorted({p for role in roles for p in json.loads(role["permissions"] or "[]")}),
    })


# ═══════════════════════════════════════════
# Feature 3: Credential Health
# ═══════════════════════════════════════════

@features_bp.get("/api/credentials/status")
@_require_permission("credential.manage")
def credentials_status():
    conn = _get_db()
    from web.services.schema_features import init_feature_db
    init_feature_db(conn)

    # The credentials table stores one row per (platform, key_name). `provider`,
    # `active`, and the last_test_* columns are added by init_feature_db above.
    creds = conn.execute(
        "SELECT id, platform, key_name, provider, active, last_tested_at, last_test_result, last_test_message FROM credentials WHERE org_id = ?",
        (current_org_id(conn),),
    ).fetchall()
    conn.close()

    return jsonify({
        "ok": True,
        "items": [
            {
                "id": c["id"],
                "name": c["key_name"],
                "platform": c["platform"],
                "provider": c["provider"] or c["platform"],
                "active": bool(c["active"]),
                "last_tested_at": c["last_tested_at"],
                "last_test_result": c["last_test_result"],
                "last_test_message": c["last_test_message"],
            }
            for c in creds
        ],
    })


@features_bp.post("/api/credentials/<int:cred_id>/test")
@_require_permission("credential.manage")
def test_credential(cred_id: int):
    conn = _get_db()
    org_id = current_org_id(conn)
    cred = conn.execute(
        "SELECT * FROM credentials WHERE id = ? AND org_id = ?",
        (cred_id, org_id),
    ).fetchone()
    if not cred:
        conn.close()
        return jsonify({"error": "not found"}), 404

    # Test connectivity
    import urllib.request
    import ssl
    status = "unknown"
    message = ""

    # Simple connectivity test based on provider
    provider = (cred["provider"] or cred["platform"] or "").lower()
    test_urls = {
        "virustotal": "https://www.virustotal.com",
        "abuseipdb": "https://api.abuseipdb.com",
        "shodan": "https://api.shodan.io",
    }
    url = test_urls.get(provider)
    if url:
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, method="HEAD")
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
            opener.open(req, timeout=5)
            status = "pass"
            message = "200 OK"
        except Exception as e:
            status = "fail"
            message = str(e)[:200]
    else:
        status = "unknown"
        message = "No connectivity test available for this provider"

    conn.execute(
        "UPDATE credentials SET last_tested_at = CURRENT_TIMESTAMP, last_test_result = ?, last_test_message = ? WHERE id = ? AND org_id = ?",
        (status, message, cred_id, org_id),
    )
    conn.commit()
    conn.close()

    return jsonify({"ok": True, "status": status, "message": message})


# ═══════════════════════════════════════════
# Wazuh Alert Poller Control
# ═══════════════════════════════════════════

@features_bp.post("/api/wazuh/poller/start")
@_require_permission("credential.manage")
def poller_start():
    from web.services.wazuh_poller import get_poller
    started = get_poller().start()
    return jsonify({"ok": True, "started": started})


@features_bp.post("/api/wazuh/poller/stop")
@_require_permission("credential.manage")
def poller_stop():
    from web.services.wazuh_poller import get_poller
    stopped = get_poller().stop()
    return jsonify({"ok": True, "stopped": stopped})


@features_bp.get("/api/wazuh/poller/status")
@_require_permission("chat.read")
def poller_status():
    from web.services.wazuh_poller import get_poller
    return jsonify({"ok": True, **get_poller().status()})


@features_bp.post("/api/wazuh/poller/poll-once")
@_require_permission("credential.manage")
def poller_poll_once():
    from web.services.wazuh_poller import get_poller
    result = get_poller().poll_once()
    return jsonify({"ok": result.get("ok", False), **result})


# ═══════════════════════════════════════════
# Feature 5: Case Assignment + SLA
# ═══════════════════════════════════════════

@features_bp.post("/api/cases/<int:case_id>/assign")
@_require_permission("case.assign")
def assign_case(case_id: int):
    payload = request.get_json(force=True)
    assignee_id = payload.get("assignee_id")

    conn = _get_db()
    org_id = current_org_id(conn)
    if assignee_id is not None:
        member = conn.execute("SELECT 1 FROM organization_memberships WHERE org_id = ? AND user_id = ? AND status = 'active'", (org_id, assignee_id)).fetchone()
        if not member:
            conn.close()
            return jsonify({"error": "assignee is not an active organization member"}), 400
    updated = conn.execute(
        "UPDATE cases SET assignee_id = ?, first_response_at = COALESCE(first_response_at, CURRENT_TIMESTAMP) WHERE id = ? AND org_id = ?",
        (assignee_id, case_id, org_id),
    ).rowcount
    if not updated:
        conn.close()
        return jsonify({"error": "not found"}), 404
    conn.commit()
    conn.close()

    return jsonify({"ok": True})


@features_bp.get("/api/cases/<int:case_id>/sla")
@_require_permission("sla.view")
def case_sla(case_id: int):
    conn = _get_db()
    case = conn.execute("SELECT * FROM cases WHERE id = ? AND org_id = ?", (case_id, current_org_id(conn))).fetchone()
    if not case:
        conn.close()
        return jsonify({"error": "not found"}), 404

    opened = case["opened_at"] or case["created_at"]
    first_response = case["first_response_at"]
    closed = case["closed_at"]
    now = datetime.now(timezone.utc).isoformat()
    mtta = _hours_between(opened, first_response)
    mttr = _hours_between(opened, closed)
    age = _hours_between(opened, closed or now)

    conn.close()
    return jsonify({
        "ok": True,
        "case_id": case_id,
        "opened_at": opened,
        "first_response_at": first_response,
        "closed_at": closed,
        "mtta_hours": mtta,
        "mttr_hours": mttr,
        "age_hours": age,
        "status": case["status"],
    })


@features_bp.post("/api/cases/<int:case_id>/close")
@_require_permission("case.close")
def close_case(case_id: int):
    conn = _get_db()
    org_id = current_org_id(conn)
    updated = conn.execute(
        "UPDATE cases SET status = 'closed', closed_at = CURRENT_TIMESTAMP WHERE id = ? AND org_id = ? AND status != 'closed'",
        (case_id, org_id),
    ).rowcount
    if not updated:
        conn.close()
        return jsonify({"error": "not found or already closed"}), 404
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# ═══════════════════════════════════════════
# Feature 6: IOC Correlation
# ═══════════════════════════════════════════

@features_bp.get("/api/iocs/<value>/correlations")
@_require_permission("chat.read")
def ioc_correlations(value: str):
    conn = _get_db()
    from web.services.schema_features import init_feature_db
    init_feature_db(conn)

    org_id = current_org_id(conn)
    obs = conn.execute(
        "SELECT o.*, c.title as case_title, c.severity as case_severity FROM observables o JOIN cases c ON o.case_id = c.id WHERE o.org_id = ? AND c.org_id = ? AND o.value = ?",
        (org_id, org_id, value),
    ).fetchall()
    summary = conn.execute(
        """
        SELECT MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen,
               COUNT(DISTINCT case_id) AS case_count,
               COUNT(DISTINCT alert_id) AS alert_count,
               COUNT(DISTINCT type) AS type_count
        FROM observables WHERE org_id = ? AND value = ?
        """,
        (org_id, value),
    ).fetchone()

    cases = []
    seen = set()
    for row in obs:
        if row["case_id"] not in seen:
            seen.add(row["case_id"])
            cases.append({
                "case_id": row["case_id"],
                "case_title": row["case_title"],
                "case_severity": row["case_severity"],
                "type": row["type"],
            })

    conn.close()
    return jsonify({
        "ok": True,
        "value": value,
        "correlated_cases": cases,
        "total": len(cases),
        "first_seen": summary["first_seen"],
        "last_seen": summary["last_seen"],
        "case_count": summary["case_count"],
        "alert_count": summary["alert_count"],
        "campaign_hint": len(cases) > 1,
    })


@features_bp.post("/api/cases/<int:case_id>/observables")
@_require_permission("case.update")
def add_observable(case_id: int):
    payload = request.get_json(force=True)
    obs_type = payload.get("type", "")
    obs_value = payload.get("value", "")
    source = payload.get("source", "manual")

    if not obs_type or not obs_value:
        return jsonify({"ok": False, "error": "type and value are required"}), 400

    conn = _get_db()
    from web.services.schema_features import init_feature_db
    init_feature_db(conn)

    org_id = current_org_id(conn)
    case = conn.execute("SELECT 1 FROM cases WHERE id = ? AND org_id = ?", (case_id, org_id)).fetchone()
    if not case:
        conn.close()
        return jsonify({"error": "not found"}), 404
    conn.execute(
        "INSERT INTO observables (org_id, case_id, type, value, source) VALUES (?, ?, ?, ?, ?)",
        (org_id, case_id, obs_type, obs_value, source),
    )
    conn.commit()
    conn.close()

    return jsonify({"ok": True}), 201
