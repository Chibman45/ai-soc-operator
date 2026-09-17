"""Alert ingestion webhooks for real-time SOC automation.

Supports:
- Wazuh webhook alerts (native format)
- Generic JSON alert format
- Alert routing to playbooks based on triggers
"""

from __future__ import annotations

import os
from typing import Any

from flask import Blueprint, jsonify, request
from web.security import consume_rate_limit, current_org_id, session_or_api_scope

try:
    from .common import audit, utc_now
except ImportError:
    from scripts.common import audit, utc_now

webhooks_bp = Blueprint("webhooks", __name__, url_prefix="/api/webhooks")


@webhooks_bp.route("/wazuh", methods=["POST"])
@session_or_api_scope("alert.ingest")
def webhook_wazuh():
    """Receive alerts from Wazuh webhook.
    
    Expected format (Wazuh native):
    {
        "alert": {
            "title": "Alert title",
            "description": "Alert description",
            "rule": {"id": "5712", "name": "Brute Force Attack"},
            "agent": {"id": "001", "name": "web-server-01"},
            "data": {
                "srcip": "203.0.113.42",
                "dstip": "192.0.2.1",
                "user": "admin"
            },
            "timestamp": "2024-01-15T10:30:00Z"
        }
    }
    """
    try:
        payload = request.get_json()
        if not payload:
            return jsonify({"error": "Empty payload"}), 400

        # Normalization + routing is handled by the shared ingestion path.
        return _route_alert("wazuh", payload)

    except Exception as e:
        audit("webhook_wazuh_error", error=str(e))
        return jsonify({"error": str(e)[:200]}), 500


@webhooks_bp.route("/generic", methods=["POST"])
@session_or_api_scope("alert.ingest")
def webhook_generic():
    """Receive generic JSON alerts.
    
    Expected format:
    {
        "title": "Alert title",
        "description": "Alert description",
        "severity": "high",
        "rule": {"name": "Anomaly Detected"},
        "source": {"ip": "203.0.113.42"},
        "tags": ["brute-force", "credential-access"]
    }
    """
    try:
        alert = request.get_json()
        if not alert:
            return jsonify({"error": "Empty payload"}), 400

        return _route_alert("generic", alert)

    except Exception as e:
        audit("webhook_generic_error", error=str(e))
        return jsonify({"error": str(e)[:200]}), 500


@webhooks_bp.route("/test", methods=["GET", "POST"])
def webhook_test():
    """Test webhook connectivity."""
    return jsonify({
        "status": "ok",
        "timestamp": utc_now(),
        "message": "Webhook receiver is operational"
    })


def _route_alert(source: str, payload: dict[str, Any]) -> tuple[Any, int]:
    """Normalize, store, correlate, and queue an alert via the shared path.

    Delegates to web.services.alert_ingest.ingest_alert_record so webhook and
    manual ingestion share one implementation: normalization, observable
    correlation, alert-table lifecycle, and background job execution.

    Returns:
        (JSON response, HTTP status)
    """
    try:
        from web.app import get_db
        from web.services.alert_ingest import ingest_alert_record
        from web.services.schema_features import init_feature_db

        source_alert_id = (
            payload.get("source_alert_id") if isinstance(payload, dict) else None
        )
        conn = get_db()
        try:
            init_feature_db(conn)
            org_id = getattr(request, "api_org_id", None) or current_org_id(conn)
            rate_limit = max(1, int(os.environ.get("AI_SOC_INGEST_RATE_PER_MINUTE", "120")))
            identity = getattr(request, "api_client_id", None) or request.remote_addr or "session"
            if not consume_rate_limit(conn, f"ingest:{org_id}:{identity}", rate_limit):
                audit("alert_ingest_rate_limited", org_id=org_id, identity=str(identity))
                return jsonify({"status": "error", "error": "ingestion rate limit exceeded"}), 429
            result = ingest_alert_record(
                conn,
                source=source,
                source_alert_id=source_alert_id,
                payload=payload,
                org_id=org_id,
            )
        finally:
            conn.close()

        if not result.get("playbook"):
            audit("alert_no_playbook_match", source=source, alert_id=result.get("alert_id"))
            return jsonify({
                "status": "no_playbook",
                "message": "No matching playbook found for this alert",
                "alert_id": result.get("alert_id"),
            }), 202  # Accepted but not processed

        return jsonify({
            "status": result.get("status", "queued"),
            "alert_id": result.get("alert_id"),
            "case_id": result.get("case_id"),
            "job_id": result.get("job_id"),
            "playbook": result.get("playbook"),
            "message": "Alert queued for processing",
        }), 202

    except Exception as e:
        audit("alert_routing_error", source=source, error=str(e))
        return jsonify({
            "status": "error",
            "error": str(e)[:200],
        }), 500
