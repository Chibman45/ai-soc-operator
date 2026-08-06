"""Approval-gated responder dry-run framework."""

from __future__ import annotations

import json
from typing import Any

from scripts.common import audit
from scripts.learning import LearningStore


RESPONDER_DEFINITIONS = {
    "block_ip": {
        "platform": "firewall",
        "risk_tier": 3,
        "required_role": "senior_analyst",
        "rollback": "Remove the firewall block rule for the IP address.",
        "template": "Block IP {target} on the configured firewall.",
    },
    "isolate_host": {
        "platform": "wazuh",
        "risk_tier": 3,
        "required_role": "senior_analyst",
        "rollback": "Release host isolation from the Wazuh endpoint action console.",
        "template": "Isolate host {target} through Wazuh.",
    },
    "disable_user": {
        "platform": "identity",
        "risk_tier": 3,
        "required_role": "senior_analyst",
        "rollback": "Re-enable the account after identity owner approval.",
        "template": "Disable user account {target}.",
    },
    "reset_user_credential": {
        "platform": "identity",
        "risk_tier": 3,
        "required_role": "senior_analyst",
        "rollback": "Coordinate account recovery and reissue credentials.",
        "template": "Reset credentials for user {target}.",
    },
    "add_thehive_observable": {
        "platform": "thehive",
        "risk_tier": 2,
        "required_role": "senior_analyst",
        "rollback": "Remove the observable from the TheHive case if added in error.",
        "template": "Add observable {target} to the TheHive case.",
    },
    "add_thehive_comment": {
        "platform": "thehive",
        "risk_tier": 2,
        "required_role": "senior_analyst",
        "rollback": "Append a corrective comment to the TheHive case.",
        "template": "Add analyst comment to TheHive case: {target}.",
    },
    "run_cortex_analyzer": {
        "platform": "cortex",
        "risk_tier": 2,
        "required_role": "senior_analyst",
        "rollback": "No direct rollback; annotate the case if analyzer output is stale or incorrect.",
        "template": "Run a Cortex analyzer against {target}.",
    },
    "push_misp_indicator": {
        "platform": "misp",
        "risk_tier": 3,
        "required_role": "senior_analyst",
        "rollback": "Delete or revoke the MISP attribute/event created for this indicator.",
        "template": "Push indicator {target} to MISP.",
    },
}


def build_preview(action_type: str, target: str, case_id: int | None = None) -> dict[str, Any]:
    definition = RESPONDER_DEFINITIONS.get(action_type)
    if not definition:
        raise ValueError(f"Unsupported responder action: {action_type}")
    return {
        "action_type": action_type,
        "case_id": case_id,
        "target": target,
        "platform": definition["platform"],
        "risk_tier": definition["risk_tier"],
        "required_role": definition["required_role"],
        "intended_action": definition["template"].format(target=target),
        "rollback_note": definition["rollback"],
        "mode": "dry_run",
        "real_execution_enabled": False,
    }


def create_responder_action(
    conn,
    *,
    action_type: str,
    target: str,
    case_id: int | None,
    requested_by: int | None,
    org_id: int | None = None,
) -> dict[str, Any]:
    preview = build_preview(action_type, target, case_id)
    cursor = conn.execute(
        """
        INSERT INTO responder_actions
            (org_id, case_id, action_type, target, platform, risk_tier, status,
             requested_by, preview_json, rollback_note)
        VALUES (?, ?, ?, ?, ?, ?, 'dry_run_ready', ?, ?, ?)
        """,
        (
            org_id,
            case_id,
            action_type,
            target,
            preview["platform"],
            preview["risk_tier"],
            requested_by,
            json.dumps(preview, sort_keys=True),
            preview["rollback_note"],
        ),
    )
    action_id = int(cursor.lastrowid)
    audit("responder_dry_run_created", action_id=action_id, action_type=action_type, case_id=case_id)
    LearningStore().record_event(
        source="responder",
        category="responder_dry_run",
        subject=action_type,
        severity="medium",
        summary=f"Responder dry-run created for {action_type}",
        evidence={"case_id": case_id, "target": target, "platform": preview["platform"]},
    )
    return {"id": action_id, **preview, "status": "dry_run_ready"}


def approve_responder_action(conn, action_id: int, approved_by: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM responder_actions WHERE id = ?", (action_id,)).fetchone()
    if not row:
        raise ValueError("Responder action not found")
    conn.execute(
        """
        UPDATE responder_actions
        SET status = 'approved', approved_by = ?, approved_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (approved_by, action_id),
    )
    audit("responder_action_approved", action_id=action_id, approved_by=approved_by)
    return {"id": action_id, "status": "approved"}


def execute_responder_action(conn, action_id: int, real_execution_enabled: bool = False) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM responder_actions WHERE id = ?", (action_id,)).fetchone()
    if not row:
        raise ValueError("Responder action not found")
    if row["status"] != "approved":
        raise PermissionError("Responder action must be approved before execution")
    if not real_execution_enabled:
        result = {
            "executed": False,
            "mode": "dry_run",
            "message": "Real responder execution is disabled for v1.",
        }
        status = "executed"
    else:
        result = {
            "executed": False,
            "mode": "blocked",
            "message": "No real responder adapter is configured.",
        }
        status = "failed"
    conn.execute(
        """
        UPDATE responder_actions
        SET status = ?, result_json = ?, executed_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (status, json.dumps(result, sort_keys=True), action_id),
    )
    audit("responder_action_execution_recorded", action_id=action_id, status=status)
    return {"id": action_id, "status": status, "result": result}
