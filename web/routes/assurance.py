"""Detection assurance pages and organization-scoped APIs."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request, send_file, session

from scripts.common import ROOT
from scripts.orchestrator import build_clients
from web.security import current_org_id, permission_required
from web.services.ai_provider import load_ai_client, provider_config
from web.services.credential_vault import open_secret
from web.services.database import connect_database
from web.services.detection_assurance import (
    approve_architecture_draft,
    assurance_metrics,
    collect_live_configuration,
    create_architecture_draft,
    generate_rule_recommendations,
    recommend_alert_assessment,
    record_ground_truth_event,
    record_verdict,
    reject_architecture_draft,
    store_and_validate_configuration,
    transition_rule_recommendation,
)

assurance_bp = Blueprint("assurance", __name__)
DB_PATH = ROOT / "data" / "soc_operator.db"
TEMPLATE_PATH = ROOT / "docs" / "templates" / "organization-architecture-and-detection-assurance-template.docx"


def _db():
    return connect_database(DB_PATH)


def _payload() -> dict:
    value = request.get_json(silent=True) or request.form.to_dict(flat=True)
    return value if isinstance(value, dict) else {}


def _boolean(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "1", "yes", "on"}:
        return True
    if isinstance(value, str) and value.lower() in {"false", "0", "no", "off"}:
        return False
    raise ValueError("detection_occurred must be a boolean")


@assurance_bp.get("/assurance")
@permission_required("assurance.view")
def assurance_page():
    conn = _db()
    org_id = int(current_org_id(conn))
    metrics = assurance_metrics(conn, org_id)
    active = conn.execute(
        "SELECT id, version, architecture_digest, architecture_json, approved_at FROM organization_architecture_profiles WHERE org_id = ? AND active = 1 ORDER BY version DESC LIMIT 1",
        (org_id,),
    ).fetchone()
    drafts = conn.execute(
        "SELECT * FROM organization_architecture_drafts WHERE org_id = ? ORDER BY created_at DESC LIMIT 20", (org_id,)
    ).fetchall()
    alerts = conn.execute(
        """
        SELECT a.id, a.title, a.source, a.severity, a.status, a.created_at,
               (SELECT av.classification FROM alert_verdicts av WHERE av.org_id = a.org_id AND av.alert_id = a.id ORDER BY av.id DESC LIMIT 1) AS classification,
               (SELECT aa.recommended_classification FROM alert_assessments aa WHERE aa.org_id = a.org_id AND aa.alert_id = a.id ORDER BY aa.id DESC LIMIT 1) AS ai_classification
        FROM alerts a WHERE a.org_id = ? ORDER BY a.created_at DESC LIMIT 50
        """,
        (org_id,),
    ).fetchall()
    findings = conn.execute(
        "SELECT * FROM validation_findings WHERE org_id = ? ORDER BY created_at DESC LIMIT 50", (org_id,)
    ).fetchall()
    recommendations = conn.execute(
        "SELECT * FROM rule_recommendations WHERE org_id = ? ORDER BY created_at DESC LIMIT 50", (org_id,)
    ).fetchall()
    snapshots = conn.execute(
        "SELECT id, platform, source, configuration_digest, collected_at FROM configuration_snapshots WHERE org_id = ? ORDER BY collected_at DESC LIMIT 20",
        (org_id,),
    ).fetchall()
    conn.close()
    return render_template(
        "assurance.html",
        metrics=metrics,
        active_architecture=active,
        architecture_drafts=drafts,
        alerts=alerts,
        findings=findings,
        recommendations=recommendations,
        snapshots=snapshots,
    )


@assurance_bp.get("/downloads/organization-assurance-template.docx")
@permission_required("assurance.view")
def download_assurance_template():
    if not TEMPLATE_PATH.is_file():
        return jsonify({"error": "document template has not been generated"}), 404
    return send_file(TEMPLATE_PATH, as_attachment=True, download_name=TEMPLATE_PATH.name)


@assurance_bp.post("/admin/architecture/upload")
@permission_required("architecture.manage")
def upload_architecture():
    upload = request.files.get("document")
    if not upload or not upload.filename:
        return jsonify({"error": "architecture document is required"}), 400
    suffix = Path(upload.filename).suffix.lower()
    conn = _db()
    org_id = int(current_org_id(conn))
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp:
            upload.save(temp.name)
            temp_path = Path(temp.name)
        from web.services.document_ingestion import ingest_document

        result = ingest_document(
            conn,
            org_id=org_id,
            purpose="architecture",
            source_path=temp_path,
            source_name=upload.filename,
            declared_mime=upload.mimetype,
            created_by=int(session["user_id"]),
            evidence_root=ROOT / "evidence",
        )
        conn.commit()
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError) as exc:
        conn.rollback()
        conn.close()
        return jsonify({"error": str(exc)[:500]}), 400
    finally:
        if temp_path:
            temp_path.unlink(missing_ok=True)
    conn.close()
    if request.accept_mimetypes.best == "application/json":
        return jsonify({"ok": True, **result, "preview_url": f"/documents/{result['id']}/preview"}), 201
    from flask import redirect, url_for

    return redirect(url_for("documents.preview_document", ingestion_id=result["id"]))


@assurance_bp.post("/api/assurance/architecture/<int:draft_id>/approve")
@permission_required("architecture.approve")
def approve_architecture(draft_id: int):
    conn = _db()
    try:
        result = approve_architecture_draft(
            conn, draft_id, org_id=int(current_org_id(conn)), approved_by=int(session["user_id"])
        )
        conn.commit()
    except (ValueError, PermissionError) as exc:
        conn.rollback()
        conn.close()
        return jsonify({"error": str(exc)}), 409
    conn.close()
    return jsonify({"ok": True, **result})


@assurance_bp.post("/api/assurance/architecture/<int:draft_id>/reject")
@permission_required("architecture.approve")
def reject_architecture(draft_id: int):
    conn = _db()
    try:
        reject_architecture_draft(
            conn,
            draft_id,
            org_id=int(current_org_id(conn)),
            rejected_by=int(session["user_id"]),
            reason=str(_payload().get("reason", "")),
        )
        conn.commit()
    except ValueError as exc:
        conn.rollback()
        conn.close()
        return jsonify({"error": str(exc)}), 409
    conn.close()
    return jsonify({"ok": True})


@assurance_bp.post("/api/assurance/alerts/<int:alert_id>/recommend")
@permission_required("assurance.label")
def recommend_alert(alert_id: int):
    conn = _db()
    org_id = int(current_org_id(conn))
    client = load_ai_client(conn, org_id)
    config = provider_config(conn, org_id)
    if not client:
        conn.close()
        return jsonify({"error": "configure an organization AI provider first"}), 409
    try:
        result = recommend_alert_assessment(
            conn,
            org_id=org_id,
            alert_id=alert_id,
            created_by=int(session["user_id"]),
            llm_callback=lambda system, prompt: client.chat(prompt, system=system),
            model=config["model"],
        )
        conn.commit()
    except (ValueError, RuntimeError) as exc:
        conn.rollback()
        conn.close()
        return jsonify({"error": str(exc)[:500]}), 400
    conn.close()
    return jsonify({"ok": True, "assessment": result}), 201


@assurance_bp.post("/api/assurance/alerts/<int:alert_id>/verdict")
@permission_required("assurance.label")
def label_alert(alert_id: int):
    data = _payload()
    conn = _db()
    try:
        result = record_verdict(
            conn,
            org_id=int(current_org_id(conn)),
            decided_by=int(session["user_id"]),
            detection_occurred=True,
            ground_truth=str(data.get("ground_truth", "unknown")),
            confidence=float(data.get("confidence", 0.5)),
            rationale=str(data.get("rationale", "")),
            evidence=data.get("evidence") if isinstance(data.get("evidence"), dict) else {},
            alert_id=alert_id,
            case_id=int(data["case_id"]) if data.get("case_id") else None,
        )
        conn.commit()
    except (ValueError, TypeError) as exc:
        conn.rollback()
        conn.close()
        return jsonify({"error": str(exc)[:500]}), 400
    conn.close()
    return jsonify({"ok": True, "verdict": result}), 201


@assurance_bp.post("/api/assurance/ground-truth")
@permission_required("assurance.label")
def create_ground_truth():
    data = _payload()
    conn = _db()
    try:
        result = record_ground_truth_event(
            conn,
            org_id=int(current_org_id(conn)),
            created_by=int(session["user_id"]),
            title=str(data.get("title", "")),
            ground_truth=str(data.get("ground_truth", "")),
            detection_occurred=_boolean(data.get("detection_occurred")),
            source=str(data.get("source", "analyst")),
            event_time=str(data.get("event_time", "")) or None,
            evidence=data.get("evidence") if isinstance(data.get("evidence"), dict) else {},
            alert_id=int(data["alert_id"]) if data.get("alert_id") else None,
            case_id=int(data["case_id"]) if data.get("case_id") else None,
            rule_id=str(data.get("rule_id", "")),
            rule_name=str(data.get("rule_name", "")),
        )
        conn.commit()
    except (ValueError, TypeError) as exc:
        conn.rollback()
        conn.close()
        return jsonify({"error": str(exc)[:500]}), 400
    conn.close()
    return jsonify({"ok": True, "event": result}), 201


@assurance_bp.post("/api/assurance/validate")
@permission_required("assurance.manage")
def validate_platform():
    data = _payload()
    platform = str(data.get("platform", "")).lower().strip()
    conn = _db()
    org_id = int(current_org_id(conn))
    try:
        supplied = data.get("configuration")
        if supplied is not None:
            if not isinstance(supplied, dict):
                raise ValueError("configuration must be a JSON object")
            configuration = supplied
            source = "uploaded_snapshot"
        else:
            # Existing clients enforce TLS and timeout behavior; this path only
            # invokes bounded read operations and never a platform mutation.
            from web.app import load_config_for_web

            credentials = {
                row["key_name"]: open_secret(row["key_value"])
                for row in conn.execute(
                    "SELECT key_name, key_value FROM credentials WHERE org_id = ?", (org_id,)
                ).fetchall()
            }
            clients = build_clients(load_config_for_web(org_id), credentials=credentials)
            configuration = collect_live_configuration(clients, platform)
            platform_row = conn.execute(
                "SELECT base_url, enabled FROM platform_config WHERE org_id = ? AND platform IN (?, ?) ORDER BY platform LIMIT 1",
                (org_id, platform, "wazuh_manager" if platform == "wazuh" else platform),
            ).fetchone()
            if platform_row:
                configuration = {"base_url": platform_row["base_url"], "enabled": bool(platform_row["enabled"]), **configuration}
            source = "live_read_only"
        result = store_and_validate_configuration(
            conn,
            org_id=org_id,
            platform=platform,
            configuration=configuration,
            source=source,
            collected_by=int(session["user_id"]),
        )
        conn.commit()
    except (ValueError, RuntimeError, OSError) as exc:
        conn.rollback()
        conn.close()
        return jsonify({"error": str(exc)[:500]}), 400
    conn.close()
    return jsonify({"ok": True, **result}), 201


@assurance_bp.post("/api/assurance/recommendations/generate")
@permission_required("assurance.manage")
def generate_recommendations():
    conn = _db()
    result = generate_rule_recommendations(
        conn, org_id=int(current_org_id(conn)), created_by=int(session["user_id"])
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "recommendations": result}), 201


@assurance_bp.post("/api/assurance/recommendations/<int:recommendation_id>/transition")
@permission_required("assurance.manage")
def transition_recommendation(recommendation_id: int):
    conn = _db()
    try:
        result = transition_rule_recommendation(
            conn,
            org_id=int(current_org_id(conn)),
            recommendation_id=recommendation_id,
            status=str(_payload().get("status", "")),
            reviewed_by=int(session["user_id"]),
        )
        conn.commit()
    except ValueError as exc:
        conn.rollback()
        conn.close()
        return jsonify({"error": str(exc)}), 409
    conn.close()
    return jsonify({"ok": True, **result})
