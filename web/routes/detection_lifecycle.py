"""Tenant-scoped APIs for evidence-gated detection rule changes."""

from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request, session

from scripts.common import ROOT
from web.security import current_org_id, permission_required
from web.services.database import connect_database
from web.services.detection_lifecycle import (
    approve_canary,
    complete_deployment,
    create_corpus,
    create_deployment,
    create_rule_artifact,
    init_detection_lifecycle_db,
    lifecycle_summary,
    prepare_production_dry_run,
    prepare_rollback,
    record_drift_window,
    run_replay,
    seal_corpus,
    verify_rollback,
)

detection_lifecycle_bp = Blueprint("detection_lifecycle", __name__)
DB_PATH = ROOT / "data" / "soc_operator.db"


def _db():
    conn = connect_database(DB_PATH)
    init_detection_lifecycle_db(conn)
    return conn


def _payload() -> dict:
    value = request.get_json(silent=True)
    if value is None:
        value = request.form.to_dict(flat=True)
    if not isinstance(value, dict):
        raise TypeError("request body must be an object")
    return value


def _identity(conn) -> tuple[int, int]:
    return int(current_org_id(conn)), int(session["user_id"])


def _execute(operation):
    conn = _db()
    try:
        result = operation(conn)
        conn.commit()
        return jsonify({"ok": True, **result})
    except PermissionError as exc:
        conn.rollback()
        return jsonify({"error": str(exc)}), 403
    except (TypeError, ValueError, KeyError) as exc:
        conn.rollback()
        return jsonify({"error": str(exc)}), 400
    finally:
        conn.close()


@detection_lifecycle_bp.get("/detection-lifecycle")
@permission_required("detection.view")
def lifecycle_page():
    conn = _db()
    try:
        org_id, _user_id = _identity(conn)
        return render_template("detection_lifecycle.html", lifecycle=lifecycle_summary(conn, org_id))
    finally:
        conn.close()


@detection_lifecycle_bp.get("/api/detection-lifecycle")
@permission_required("detection.view")
def lifecycle_api():
    conn = _db()
    try:
        org_id, _user_id = _identity(conn)
        return jsonify({"ok": True, **lifecycle_summary(conn, org_id)})
    finally:
        conn.close()


@detection_lifecycle_bp.post("/api/detection-lifecycle/corpora")
@permission_required("detection.manage")
def create_corpus_api():
    data = _payload()
    return _execute(lambda conn: create_corpus(conn, org_id=_identity(conn)[0], name=str(data.get("name", "")), samples=data.get("samples", []), created_by=_identity(conn)[1]))


@detection_lifecycle_bp.post("/api/detection-lifecycle/corpora/<int:corpus_id>/seal")
@permission_required("detection.manage")
def seal_corpus_api(corpus_id: int):
    return _execute(lambda conn: seal_corpus(conn, corpus_id, org_id=_identity(conn)[0], sealed_by=_identity(conn)[1]))


@detection_lifecycle_bp.post("/api/detection-lifecycle/artifacts")
@permission_required("detection.manage")
def create_artifact_api():
    data = _payload()
    return _execute(
        lambda conn: create_rule_artifact(
            conn,
            org_id=_identity(conn)[0],
            platform=str(data.get("platform", "")),
            rule_key=str(data.get("rule_key", "")),
            content=data.get("content", {}),
            created_by=_identity(conn)[1],
            parent_artifact_id=data.get("parent_artifact_id"),
        )
    )


@detection_lifecycle_bp.post("/api/detection-lifecycle/replays")
@permission_required("detection.manage")
def replay_api():
    data = _payload()
    return _execute(
        lambda conn: run_replay(
            conn,
            org_id=_identity(conn)[0],
            corpus_id=int(data["corpus_id"]),
            baseline_artifact_id=int(data["baseline_artifact_id"]),
            candidate_artifact_id=int(data["candidate_artifact_id"]),
            requested_by=_identity(conn)[1],
        )
    )


@detection_lifecycle_bp.post("/api/detection-lifecycle/deployments")
@permission_required("detection.manage")
def deployment_api():
    data = _payload()
    return _execute(
        lambda conn: create_deployment(
            conn,
            org_id=_identity(conn)[0],
            mode=str(data.get("mode", "")),
            replay_id=int(data["replay_id"]),
            target=data.get("target", {}),
            requested_by=_identity(conn)[1],
        )
    )


@detection_lifecycle_bp.post("/api/detection-lifecycle/deployments/<int:deployment_id>/complete")
@permission_required("detection.manage")
def complete_deployment_api(deployment_id: int):
    data = _payload()
    return _execute(lambda conn: complete_deployment(conn, deployment_id, org_id=_identity(conn)[0], observations=data.get("observations", {}), completed_by=_identity(conn)[1]))


@detection_lifecycle_bp.post("/api/detection-lifecycle/deployments/<int:deployment_id>/approve")
@permission_required("detection.approve")
def approve_deployment_api(deployment_id: int):
    data = _payload()
    return _execute(lambda conn: approve_canary(conn, deployment_id, org_id=_identity(conn)[0], approved_by=_identity(conn)[1], ttl_minutes=int(data.get("ttl_minutes", 60))))


@detection_lifecycle_bp.post("/api/detection-lifecycle/deployments/<int:deployment_id>/production-preview")
@permission_required("detection.manage")
def production_preview_api(deployment_id: int):
    return _execute(lambda conn: prepare_production_dry_run(conn, deployment_id, org_id=_identity(conn)[0], requested_by=_identity(conn)[1]))


@detection_lifecycle_bp.post("/api/detection-lifecycle/deployments/<int:deployment_id>/drift")
@permission_required("detection.manage")
def drift_api(deployment_id: int):
    data = _payload()
    return _execute(lambda conn: record_drift_window(conn, org_id=_identity(conn)[0], deployment_id=deployment_id, baseline=data.get("baseline", {}), observed=data.get("observed", {}), created_by=_identity(conn)[1]))


@detection_lifecycle_bp.post("/api/detection-lifecycle/rollbacks")
@permission_required("detection.manage")
def rollback_api():
    data = _payload()
    return _execute(lambda conn: prepare_rollback(conn, org_id=_identity(conn)[0], deployment_id=int(data["deployment_id"]), restore_artifact_id=int(data["restore_artifact_id"]), reason=str(data.get("reason", "")), requested_by=_identity(conn)[1]))


@detection_lifecycle_bp.post("/api/detection-lifecycle/rollbacks/<int:rollback_id>/verify")
@permission_required("detection.approve")
def verify_rollback_api(rollback_id: int):
    return _execute(lambda conn: verify_rollback(conn, rollback_id, org_id=_identity(conn)[0], verified_by=_identity(conn)[1]))
