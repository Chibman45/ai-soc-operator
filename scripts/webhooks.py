"""Alert ingestion webhooks for real-time SOC automation.

Supports:
- Wazuh webhook alerts (native format)
- Generic JSON alert format
- Alert routing to playbooks based on triggers
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from flask import Blueprint, jsonify, request

try:
    from .common import ROOT, Session, audit, utc_now
    from .job_queue import JobQueue
    from .orchestrator import auto_select_playbook, extract_iocs, load_config
except ImportError:
    from scripts.common import ROOT, Session, audit, utc_now
    from scripts.job_queue import JobQueue
    from scripts.orchestrator import auto_select_playbook, extract_iocs, load_config

webhooks_bp = Blueprint("webhooks", __name__, url_prefix="/api/webhooks")
job_queue = JobQueue()


@webhooks_bp.route("/wazuh", methods=["POST"])
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

        # Extract alert from Wazuh wrapper
        alert = payload.get("alert", payload)
        if not alert:
            return jsonify({"error": "No alert data found"}), 400

        # Normalize to internal format
        normalized_alert = _normalize_wazuh_alert(alert)
        
        # Route to appropriate playbook
        return _route_alert(normalized_alert, source="wazuh")

    except Exception as e:
        audit("webhook_wazuh_error", error=str(e))
        return jsonify({"error": str(e)[:200]}), 500


@webhooks_bp.route("/generic", methods=["POST"])
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

        return _route_alert(alert, source="generic")

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


def _normalize_wazuh_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Normalize Wazuh alert to internal format."""
    normalized = {
        "title": alert.get("title", alert.get("description", "Wazuh Alert")),
        "description": alert.get("description", ""),
        "severity": _map_wazuh_severity(alert.get("level", 3)),
        "rule": alert.get("rule", {}),
        "agent": alert.get("agent", {}),
        "tags": alert.get("tags", []),
        "timestamp": alert.get("timestamp", utc_now()),
    }

    # Extract observables from data
    data = alert.get("data", {})
    if data:
        normalized["source"] = {}
        normalized["destination"] = {}
        
        if "srcip" in data:
            normalized["source"]["ip"] = data["srcip"]
        if "dstip" in data:
            normalized["destination"]["ip"] = data["dstip"]
        if "user" in data:
            normalized["user"] = {"name": data["user"]}
        if "file" in data:
            normalized["file"] = data["file"]

    return normalized


def _map_wazuh_severity(level: int) -> str:
    """Map Wazuh alert level (1-15) to severity."""
    if level >= 12:
        return "critical"
    elif level >= 9:
        return "high"
    elif level >= 6:
        return "medium"
    elif level >= 3:
        return "low"
    else:
        return "info"


def _route_alert(alert: dict[str, Any], source: str) -> tuple[Any, int]:
    """Route alert to appropriate playbook and create execution job.
    
    Returns:
        (JSON response, HTTP status)
    """
    try:
        # Find best matching playbook
        playbook_dir = ROOT / "playbooks"
        playbook_path = auto_select_playbook(alert, playbook_dir)
        
        if not playbook_path:
            audit("alert_no_playbook_match", source=source, alert=alert.get("title", ""))
            return jsonify({
                "status": "no_playbook",
                "message": "No matching playbook found for this alert",
                "alert": alert,
            }), 202  # Accepted but not processed

        # Create database entry for run
        from web.app import get_db
        from scripts.learning import learn_alert
        conn = get_db()
        try:
            cursor = conn.execute(
                "INSERT INTO runs (playbook, status, alert_file) VALUES (?, ?, ?)",
                (playbook_path.name, "ingested", json.dumps(alert)),
            )
            run_id = cursor.lastrowid
            conn.commit()
        finally:
            conn.close()

        # Create job
        config = load_config()
        job_id = job_queue.create_job(
            run_id=run_id,
            playbook_path=str(playbook_path),
            alert=alert,
            config=config,
        )
        learn_alert(alert, source=source, playbook=playbook_path.name)

        # Execute asynchronously
        def execute(alert_data: dict, progress_cb):
            from web.app import _execute_run_job

            return _execute_run_job(
                run_id,
                playbook_path,
                alert_data,
                config,
                progress_cb,
            )

        job_queue.execute_job(job_id, execute)

        audit(
            "alert_ingested",
            source=source,
            alert_title=alert.get("title", ""),
            playbook=playbook_path.name,
            run_id=run_id,
            job_id=job_id,
        )

        return jsonify({
            "status": "queued",
            "run_id": run_id,
            "job_id": job_id,
            "playbook": playbook_path.name,
            "message": "Alert queued for processing",
        }), 202

    except Exception as e:
        audit("alert_routing_error", source=source, error=str(e))
        return jsonify({
            "status": "error",
            "error": str(e)[:200],
        }), 500
