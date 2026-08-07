"""Routes for features 1-6: alerts, RBAC, credentials health, queue, case assignment, IOC correlation."""

from __future__ import annotations

import json
from datetime import datetime
from functools import wraps
from pathlib import Path
from flask import Blueprint, jsonify, request, session

ROOT = Path(__file__).resolve().parents[2]

features_bp = Blueprint("features", __name__)


def _get_db():
    import sqlite3
    db_path = ROOT / "data" / "soc_operator.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def _login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def _require_role(role_name):
    """Decorator: user must have the specified role."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                return jsonify({"error": "unauthorized"}), 401
            conn = _get_db()
            user_role = conn.execute(
                "SELECT r.name FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = ?",
                (session["user_id"],),
            ).fetchone()
            conn.close()
            if not user_role or user_role["name"] != role_name:
                # Admin always has access
                if user_role and user_role["name"] == "admin":
                    pass
                else:
                    return jsonify({"error": "forbidden", "required_role": role_name}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def _require_permission(perm_name):
    """Decorator: user must have the specified permission."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                return jsonify({"error": "unauthorized"}), 401
            conn = _get_db()
            row = conn.execute(
                "SELECT r.permissions FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = ?",
                (session["user_id"],),
            ).fetchone()
            conn.close()
            if not row:
                return jsonify({"error": "forbidden", "required_permission": perm_name}), 403
            try:
                perms = json.loads(row["permissions"])
            except (json.JSONDecodeError, TypeError):
                perms = []
            if perm_name not in perms:
                return jsonify({"error": "forbidden", "required_permission": perm_name}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ═══════════════════════════════════════════
# Feature 1: Alert Ingestion
# ═══════════════════════════════════════════

@features_bp.post("/api/ingest/alert")
@_login_required
def ingest_alert():
    payload = request.get_json(force=True) or {}

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
        )
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
@_login_required
def alert_queue():
    mode = request.args.get("mode", "new")
    limit = int(request.args.get("limit", "50"))

    conn = _get_db()
    from web.services.schema_features import init_feature_db
    init_feature_db(conn)

    if mode == "new":
        alerts = conn.execute(
            "SELECT * FROM alerts WHERE status IN ('new', 'queued') ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    elif mode == "all":
        alerts = conn.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    else:
        alerts = conn.execute(
            "SELECT * FROM alerts WHERE status = ? ORDER BY created_at DESC LIMIT ?",
            (mode, limit),
        ).fetchall()

    conn.close()
    return jsonify({
        "ok": True,
        "count": len(alerts),
        "alerts": [
            {
                "id": a["id"], "source": a["source"], "title": a["title"],
                "severity": a["severity"], "status": a["status"],
                "case_id": a["case_id"], "created_at": a["created_at"],
            }
            for a in alerts
        ],
    })


# ═══════════════════════════════════════════
# Feature 2: RBAC
# ═══════════════════════════════════════════

@features_bp.get("/api/roles")
@_login_required
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
@_require_role("admin")
def assign_role(user_id: int):
    payload = request.get_json(force=True)
    role_id = payload.get("role_id")
    if not role_id:
        return jsonify({"ok": False, "error": "role_id is required"}), 400

    conn = _get_db()
    existing = conn.execute(
        "SELECT id FROM user_roles WHERE user_id = ? AND role_id = ?",
        (user_id, role_id),
    ).fetchone()
    if existing:
        conn.close()
        return jsonify({"ok": False, "error": "role already assigned"}), 409

    conn.execute(
        "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
        (user_id, role_id),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@features_bp.delete("/api/users/<int:user_id>/roles/<int:role_id>")
@_require_role("admin")
def remove_role(user_id: int, role_id: int):
    conn = _get_db()
    conn.execute(
        "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?",
        (user_id, role_id),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@features_bp.get("/api/me")
@_login_required
def get_me():
    conn = _get_db()
    user = conn.execute("SELECT id, username FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    role = conn.execute(
        "SELECT r.name, r.permissions FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = ?",
        (session["user_id"],),
    ).fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "not found"}), 404

    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "role": role["name"] if role else None,
        "permissions": json.loads(role["permissions"]) if role else [],
    })


# ═══════════════════════════════════════════
# Feature 3: Credential Health
# ═══════════════════════════════════════════

@features_bp.get("/api/credentials/status")
@_login_required
def credentials_status():
    conn = _get_db()
    from web.services.schema_features import init_feature_db
    init_feature_db(conn)

    # The credentials table stores one row per (platform, key_name). `provider`,
    # `active`, and the last_test_* columns are added by init_feature_db above.
    creds = conn.execute(
        "SELECT id, platform, key_name, provider, active, last_tested_at, last_test_result, last_test_message FROM credentials"
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
    cred = conn.execute("SELECT * FROM credentials WHERE id = ?", (cred_id,)).fetchone()
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
        "UPDATE credentials SET last_tested_at = CURRENT_TIMESTAMP, last_test_result = ?, last_test_message = ? WHERE id = ?",
        (status, message, cred_id),
    )
    conn.commit()
    conn.close()

    return jsonify({"ok": True, "status": status, "message": message})


# ═══════════════════════════════════════════
# Wazuh Alert Poller Control
# ═══════════════════════════════════════════

@features_bp.post("/api/wazuh/poller/start")
@_login_required
def poller_start():
    from web.services.wazuh_poller import get_poller
    started = get_poller().start()
    return jsonify({"ok": True, "started": started})


@features_bp.post("/api/wazuh/poller/stop")
@_login_required
def poller_stop():
    from web.services.wazuh_poller import get_poller
    stopped = get_poller().stop()
    return jsonify({"ok": True, "stopped": stopped})


@features_bp.get("/api/wazuh/poller/status")
@_login_required
def poller_status():
    from web.services.wazuh_poller import get_poller
    return jsonify({"ok": True, **get_poller().status()})


@features_bp.post("/api/wazuh/poller/poll-once")
@_login_required
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
    conn.execute(
        "UPDATE cases SET assignee_id = ? WHERE id = ?",
        (assignee_id, case_id),
    )
    conn.commit()
    conn.close()

    return jsonify({"ok": True})


@features_bp.get("/api/cases/<int:case_id>/sla")
@_login_required
def case_sla(case_id: int):
    conn = _get_db()
    case = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if not case:
        conn.close()
        return jsonify({"error": "not found"}), 404

    opened = case["opened_at"] or case["created_at"]
    closed = case["closed_at"]
    now = datetime.utcnow().isoformat()

    # Calculate time to close or current age
    mttr = None
    if closed and opened:
        try:
            from datetime import datetime as dt
            open_dt = dt.fromisoformat(opened.replace("Z", "+00:00").replace("+00:00", ""))
            close_dt = dt.fromisoformat(closed.replace("Z", "+00:00").replace("+00:00", ""))
            mttr_hours = (close_dt - open_dt).total_seconds() / 3600
            mttr = round(mttr_hours, 1)
        except Exception:
            pass

    conn.close()
    return jsonify({
        "ok": True,
        "case_id": case_id,
        "opened_at": opened,
        "closed_at": closed,
        "mttr_hours": mttr,
        "status": case["status"],
    })


@features_bp.post("/api/cases/<int:case_id>/close")
@_require_permission("case.close")
def close_case(case_id: int):
    conn = _get_db()
    conn.execute(
        "UPDATE cases SET status = 'closed', closed_at = CURRENT_TIMESTAMP WHERE id = ?",
        (case_id,),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# ═══════════════════════════════════════════
# Feature 6: IOC Correlation
# ═══════════════════════════════════════════

@features_bp.get("/api/iocs/<value>/correlations")
@_login_required
def ioc_correlations(value: str):
    conn = _get_db()
    from web.services.schema_features import init_feature_db
    init_feature_db(conn)

    obs = conn.execute(
        "SELECT o.*, c.title as case_title, c.severity as case_severity FROM observables o JOIN cases c ON o.case_id = c.id WHERE o.value = ?",
        (value,),
    ).fetchall()

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
    })


@features_bp.post("/api/cases/<int:case_id>/observables")
@_login_required
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

    conn.execute(
        "INSERT INTO observables (case_id, type, value, source) VALUES (?, ?, ?, ?)",
        (case_id, obs_type, obs_value, source),
    )
    conn.commit()
    conn.close()

    return jsonify({"ok": True}), 201
