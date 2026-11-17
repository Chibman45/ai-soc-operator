"""Evidence and authorization tests for the detection-rule lifecycle."""

from __future__ import annotations

import json
import sqlite3

import pytest

from web.services.detection_lifecycle import (
    approve_canary,
    complete_deployment,
    create_corpus,
    create_deployment,
    create_rule_artifact,
    init_detection_lifecycle_db,
    prepare_production_dry_run,
    prepare_rollback,
    record_drift_window,
    run_replay,
    sanitize_event,
    seal_corpus,
    verify_corpus,
    verify_rollback,
)


def connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_detection_lifecycle_db(conn)
    return conn


def build_replay(conn: sqlite3.Connection, org_id: int = 1) -> tuple[dict, dict, dict]:
    corpus = create_corpus(
        conn,
        org_id=org_id,
        name="validated-auth-events",
        created_by=1,
        samples=[
            {"sample_key": "attack", "ground_truth": "malicious", "event": {"risk": "high", "source_ip": "203.0.113.10", "token": "never-store"}},
            {"sample_key": "normal", "ground_truth": "benign", "event": {"risk": "low", "source_ip": "192.0.2.10"}},
        ],
    )
    seal_corpus(conn, corpus["id"], org_id=org_id, sealed_by=1)
    baseline = create_rule_artifact(conn, org_id=org_id, platform="wazuh", rule_key="auth-risk", content={"condition": {"field": "risk", "operator": "equals", "value": "critical"}}, created_by=1)
    candidate = create_rule_artifact(conn, org_id=org_id, platform="wazuh", rule_key="auth-risk", content={"condition": {"field": "risk", "operator": "equals", "value": "high"}}, created_by=1, parent_artifact_id=baseline["id"])
    replay = run_replay(conn, org_id=org_id, corpus_id=corpus["id"], baseline_artifact_id=baseline["id"], candidate_artifact_id=candidate["id"], requested_by=1)
    return baseline, candidate, replay


def test_sanitization_redacts_secrets_and_pseudonymizes_identity_per_org():
    conn = connection()
    source = {"username": "alice", "password": "secret", "nested": {"api_key": "key"}}
    first = sanitize_event(conn, 1, source)
    repeated = sanitize_event(conn, 1, source)
    other_org = sanitize_event(conn, 2, source)
    assert first["password"] == "[REDACTED]"
    assert first["nested"]["api_key"] == "[REDACTED]"
    assert first["username"] == repeated["username"]
    assert first["username"] != other_org["username"]


def test_sealed_corpus_rejects_tampering_and_cross_tenant_access():
    conn = connection()
    corpus = create_corpus(conn, org_id=1, name="truth", samples=[{"ground_truth": "benign", "event": {"kind": "known-good"}}], created_by=1)
    sealed = seal_corpus(conn, corpus["id"], org_id=1, sealed_by=1)
    assert verify_corpus(conn, corpus["id"], org_id=1) == sealed["digest"]
    with pytest.raises(ValueError, match="not found"):
        verify_corpus(conn, corpus["id"], org_id=2)
    conn.execute("UPDATE dl_corpus_samples SET event_json = ? WHERE corpus_id = ?", (json.dumps({"kind": "changed"}), corpus["id"]))
    with pytest.raises(ValueError, match="integrity"):
        verify_corpus(conn, corpus["id"], org_id=1)


def test_replay_shadow_canary_approval_and_production_preview_flow():
    conn = connection()
    _baseline, _candidate, replay = build_replay(conn)
    assert replay["metrics"]["candidate"]["tp"] == 1
    assert replay["metrics"]["candidate"]["tn"] == 1

    shadow = create_deployment(conn, org_id=1, mode="shadow", replay_id=replay["id"], target={"cluster": "staging"}, requested_by=1)
    assert complete_deployment(conn, shadow["id"], org_id=1, observations={"events": 25, "errors": 0}, completed_by=1)["status"] == "completed"
    canary = create_deployment(conn, org_id=1, mode="canary", replay_id=replay["id"], target={"cluster": "staging"}, requested_by=1)
    assert complete_deployment(conn, canary["id"], org_id=1, observations={"events": 10, "errors": 0}, completed_by=1)["status"] == "approval_required"
    with pytest.raises(PermissionError):
        approve_canary(conn, canary["id"], org_id=1, approved_by=1)
    approval = approve_canary(conn, canary["id"], org_id=1, approved_by=2)
    assert approval["status"] == "approved"
    production = prepare_production_dry_run(conn, canary["id"], org_id=1, requested_by=1)
    assert production == {"id": production["id"], "mode": "production", "status": "dry_run_ready", "external_write": False}


def test_drift_and_rollback_require_independent_verification():
    conn = connection()
    baseline, _candidate, replay = build_replay(conn)
    shadow = create_deployment(conn, org_id=1, mode="shadow", replay_id=replay["id"], target={"cluster": "staging"}, requested_by=1)
    complete_deployment(conn, shadow["id"], org_id=1, observations={"events": 5, "errors": 0}, completed_by=1)
    canary = create_deployment(conn, org_id=1, mode="canary", replay_id=replay["id"], target={"cluster": "staging"}, requested_by=1)
    complete_deployment(conn, canary["id"], org_id=1, observations={"events": 5, "errors": 0}, completed_by=1)
    approve_canary(conn, canary["id"], org_id=1, approved_by=2)
    production = prepare_production_dry_run(conn, canary["id"], org_id=1, requested_by=1)
    drift = record_drift_window(conn, org_id=1, deployment_id=production["id"], baseline={"precision": 0.95}, observed={"precision": 0.50}, created_by=1)
    assert drift["status"] == "breach"
    rollback = prepare_rollback(conn, org_id=1, deployment_id=production["id"], restore_artifact_id=baseline["id"], reason="Precision regression", requested_by=1)
    assert rollback["preview"]["platform_write"] is False
    with pytest.raises(PermissionError):
        verify_rollback(conn, rollback["id"], org_id=1, verified_by=1)
    assert verify_rollback(conn, rollback["id"], org_id=1, verified_by=2)["status"] == "verified"
