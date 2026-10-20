"""Human-reviewed document ingestion and analysis workflow."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from flask import (
    Blueprint,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from scripts.common import ROOT, audit
from scripts.playbook_parser import parse_with_llm, validate_playbook
from web.security import (
    current_org_id,
    login_required,
    permission_required,
    permissions_for_user,
)
from web.services.ai_provider import load_ai_client, provider_config
from web.services.database import connect_database
from web.services.detection_assurance import create_architecture_draft
from web.services.document_ingestion import (
    load_document_preview,
    mark_document_analyzed,
)
from web.services.organization_policy import create_policy_draft

documents_bp = Blueprint("documents", __name__)
DB_PATH = ROOT / "data" / "soc_operator.db"
PURPOSE_PERMISSION = {
    "playbook": "playbook.manage",
    "organization_policy": "policy.manage",
    "architecture": "architecture.manage",
}


def _db():
    return connect_database(DB_PATH)


def _authorize(conn, document: dict) -> int:
    org_id = int(current_org_id(conn))
    if int(document["org_id"]) != org_id:
        raise PermissionError("document preview is outside the active organization")
    required = PURPOSE_PERMISSION[document["purpose"]]
    if required not in permissions_for_user(conn, int(session["user_id"]), org_id):
        raise PermissionError(f"missing permission: {required}")
    return org_id


@documents_bp.get("/documents/<int:ingestion_id>/preview")
@login_required
def preview_document(ingestion_id: int):
    conn = _db()
    try:
        document = load_document_preview(conn, ingestion_id, org_id=int(current_org_id(conn)))
        _authorize(conn, document)
    except (ValueError, PermissionError) as exc:
        conn.close()
        return jsonify({"error": str(exc)}), 404 if isinstance(exc, ValueError) else 403
    conn.close()
    return render_template("document_preview.html", document=document)


def _create_playbook_draft(conn, document: dict, *, org_id: int, user_id: int) -> dict:
    suffix = document["suffix"]
    if suffix in {".yaml", ".yml", ".json"}:
        if suffix == ".json":
            parsed = json.loads(document["extraction_text"])
        else:
            import yaml
            try:
                parsed = yaml.safe_load(document["extraction_text"])
            except yaml.YAMLError as exc:
                raise ValueError(f"invalid playbook YAML: {exc}") from exc
    else:
        client = load_ai_client(conn, org_id)
        if not client:
            raise ValueError("an organization AI provider is required to analyze this playbook")
        parsed = parse_with_llm(
            document["extraction_text"],
            lambda system, prompt: client.chat(prompt, system=system),
        )
        if "error" in parsed:
            raise ValueError(parsed["error"])
    errors = validate_playbook(parsed)
    if errors:
        raise ValueError("; ".join(errors))
    playbook_id = str(parsed["id"]).strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,78}[a-z0-9]", playbook_id):
        raise ValueError("playbook id must be a 3-80 character lowercase slug")
    canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    draft_id = int(
        conn.execute(
            """
            INSERT INTO playbook_drafts
                (org_id, ingestion_id, source_name, playbook_id, playbook_json,
                 playbook_digest, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (org_id, document["id"], document["source_name"], playbook_id, canonical, digest, user_id),
        ).lastrowid
    )
    return {"id": draft_id, "status": "draft", "playbook_id": playbook_id, "digest": digest}


@documents_bp.post("/api/documents/<int:ingestion_id>/analyze")
@login_required
def analyze_document(ingestion_id: int):
    conn = _db()
    try:
        document = load_document_preview(conn, ingestion_id, org_id=int(current_org_id(conn)))
        org_id = _authorize(conn, document)
        if document["status"] != "preview":
            raise ValueError("document must be in preview state before analysis")
        user_id = int(session["user_id"])
        source_path = Path(document["evidence_path"])
        client = load_ai_client(conn, org_id)
        callback = (lambda system, prompt: client.chat(prompt, system=system)) if client else None
        model = provider_config(conn, org_id)["model"] if client else None
        if document["purpose"] == "playbook":
            result = _create_playbook_draft(conn, document, org_id=org_id, user_id=user_id)
            result_type = "playbook_draft"
        elif document["purpose"] == "organization_policy":
            result = create_policy_draft(
                conn, org_id=org_id, source_path=source_path, source_name=document["source_name"],
                created_by=user_id, llm_callback=callback,
                known_playbooks=sorted(path.name for path in (ROOT / "playbooks").glob("*.yaml")),
                extraction_model=model, extracted_text=document["extraction_text"],
            )
            result_type = "policy_draft"
        else:
            result = create_architecture_draft(
                conn, org_id=org_id, source_path=source_path, source_name=document["source_name"],
                created_by=user_id, llm_callback=callback, extraction_model=model,
                extracted_text=document["extraction_text"], extraction_provenance=document["provenance"],
            )
            result_type = "architecture_draft"
        mark_document_analyzed(conn, ingestion_id, org_id=org_id, result_type=result_type, result_id=result["id"])
        conn.commit()
        audit("document_analyzed_to_draft", org_id=org_id, ingestion_id=ingestion_id, result_type=result_type, result_id=result["id"])
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError, PermissionError) as exc:
        conn.rollback()
        conn.close()
        return jsonify({"error": str(exc)[:500]}), 403 if isinstance(exc, PermissionError) else 400
    conn.close()
    if request.accept_mimetypes.best == "application/json":
        return jsonify({"ok": True, "result_type": result_type, "result": result}), 201
    flash("Document analyzed into a reviewable draft. It is not active until approved.", "success")
    destination = {
        "playbook": "playbooks",
        "organization_policy": "admin.policy_page",
        "architecture": "assurance.workspace",
    }[document["purpose"]]
    return redirect(url_for(destination))


@documents_bp.post("/api/documents/<int:ingestion_id>/reject")
@login_required
def reject_document(ingestion_id: int):
    conn = _db()
    try:
        document = load_document_preview(conn, ingestion_id, org_id=int(current_org_id(conn)))
        org_id = _authorize(conn, document)
        updated = conn.execute(
            "UPDATE document_ingestions SET status = 'rejected', rejected_at = CURRENT_TIMESTAMP WHERE id = ? AND org_id = ? AND status = 'preview'",
            (ingestion_id, org_id),
        ).rowcount
        if not updated:
            raise ValueError("document preview is no longer awaiting review")
        conn.commit()
        audit("document_preview_rejected", org_id=org_id, ingestion_id=ingestion_id)
    except (ValueError, PermissionError) as exc:
        conn.rollback()
        conn.close()
        return jsonify({"error": str(exc)}), 409
    conn.close()
    return jsonify({"ok": True, "status": "rejected"})


@documents_bp.post("/api/playbook-drafts/<int:draft_id>/approve")
@permission_required("playbook.manage")
def approve_playbook_draft(draft_id: int):
    conn = _db()
    org_id = int(current_org_id(conn))
    row = conn.execute("SELECT * FROM playbook_drafts WHERE id = ? AND org_id = ?", (draft_id, org_id)).fetchone()
    if not row or row["status"] != "draft":
        conn.close()
        return jsonify({"error": "playbook draft is not awaiting approval"}), 409
    parsed = json.loads(row["playbook_json"])
    canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    if hashlib.sha256(canonical.encode("utf-8")).hexdigest() != row["playbook_digest"]:
        conn.close()
        return jsonify({"error": "playbook draft changed after analysis"}), 409
    destination = ROOT / "playbooks" / f"{row['playbook_id']}.yaml"
    if destination.exists():
        conn.close()
        return jsonify({"error": "a playbook with this id already exists"}), 409
    import yaml
    created = False
    try:
        # Exclusive creation prevents two concurrent approvals from replacing an
        # existing operational playbook. Remove the file if the DB commit fails.
        with destination.open("x", encoding="utf-8") as handle:
            handle.write(yaml.safe_dump(parsed, sort_keys=False))
        created = True
        updated = conn.execute(
            "UPDATE playbook_drafts SET status = 'approved', approved_by = ?, approved_at = CURRENT_TIMESTAMP WHERE id = ? AND org_id = ? AND status = 'draft'",
            (int(session["user_id"]), draft_id, org_id),
        ).rowcount
        if updated != 1:
            raise RuntimeError("playbook approval state changed concurrently")
        conn.commit()
    except (OSError, RuntimeError) as exc:
        conn.rollback()
        if created:
            destination.unlink(missing_ok=True)
        conn.close()
        return jsonify({"error": str(exc)[:500]}), 409
    conn.close()
    audit("playbook_draft_approved", org_id=org_id, draft_id=draft_id, path=str(destination))
    return jsonify({"ok": True, "status": "approved", "playbook": destination.name})


@documents_bp.post("/api/playbook-drafts/<int:draft_id>/reject")
@permission_required("playbook.manage")
def reject_playbook_draft(draft_id: int):
    reason = str((request.get_json(silent=True) or request.form).get("reason", "")).strip()
    if not reason:
        return jsonify({"error": "rejection reason is required"}), 400
    conn = _db()
    org_id = int(current_org_id(conn))
    updated = conn.execute(
        """
        UPDATE playbook_drafts SET status = 'rejected', rejected_by = ?,
            rejected_at = CURRENT_TIMESTAMP, rejection_reason = ?
        WHERE id = ? AND org_id = ? AND status = 'draft'
        """,
        (int(session["user_id"]), reason[:1000], draft_id, org_id),
    ).rowcount
    conn.commit()
    conn.close()
    if not updated:
        return jsonify({"error": "playbook draft is not awaiting approval"}), 409
    return jsonify({"ok": True, "status": "rejected"})
