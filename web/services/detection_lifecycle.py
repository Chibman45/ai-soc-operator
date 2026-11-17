"""Evidence-gated detection-rule lifecycle with dry-run adapters only.

This module deliberately owns its schema so it can be introduced without a
startup migration. It never invokes a shell or writes to a detection platform.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar, Protocol

from scripts.common import ROOT, audit
from web.services.database import connect_database

DB_PATH = ROOT / "data" / "soc_operator.db"
SECRET_FIELDS = {
    "api_key", "apikey", "authorization", "cookie", "credential", "password",
    "secret", "session", "token",
}
IDENTITY_FIELDS = {"email", "hostname", "host", "ip", "ip_address", "source_ip", "destination_ip", "user", "username"}
LIFECYCLE_SCHEMA = """
CREATE TABLE IF NOT EXISTS dl_org_keys (
    org_id INTEGER PRIMARY KEY,
    pseudonym_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS dl_corpora (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    version INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','sealed')),
    digest TEXT,
    created_by INTEGER NOT NULL,
    sealed_by INTEGER,
    sealed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, name, version)
);
CREATE TABLE IF NOT EXISTS dl_corpus_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    corpus_id INTEGER NOT NULL,
    sample_key TEXT NOT NULL,
    ground_truth TEXT NOT NULL CHECK(ground_truth IN ('malicious','benign')),
    event_json TEXT NOT NULL,
    sample_digest TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, corpus_id, sample_key)
);
CREATE TABLE IF NOT EXISTS dl_rule_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    platform TEXT NOT NULL,
    rule_key TEXT NOT NULL,
    version INTEGER NOT NULL,
    content_json TEXT NOT NULL,
    digest TEXT NOT NULL,
    parent_artifact_id INTEGER,
    created_by INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, rule_key, version),
    UNIQUE(org_id, digest)
);
CREATE TABLE IF NOT EXISTS dl_replay_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    corpus_id INTEGER NOT NULL,
    corpus_digest TEXT NOT NULL,
    baseline_artifact_id INTEGER NOT NULL,
    baseline_digest TEXT NOT NULL,
    candidate_artifact_id INTEGER NOT NULL,
    candidate_digest TEXT NOT NULL,
    adapter_name TEXT NOT NULL,
    adapter_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('completed','failed')),
    metrics_json TEXT NOT NULL,
    results_digest TEXT NOT NULL,
    requested_by INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS dl_replay_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    replay_id INTEGER NOT NULL,
    sample_key TEXT NOT NULL,
    ground_truth TEXT NOT NULL,
    baseline_detected INTEGER NOT NULL,
    candidate_detected INTEGER NOT NULL,
    latency_ms REAL NOT NULL,
    result_digest TEXT NOT NULL,
    UNIQUE(org_id, replay_id, sample_key)
);
CREATE TABLE IF NOT EXISTS dl_deployments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN ('shadow','canary','production')),
    status TEXT NOT NULL CHECK(status IN ('dry_run_ready','observing','completed','approval_required','approved','rolled_back','failed')),
    artifact_id INTEGER NOT NULL,
    artifact_digest TEXT NOT NULL,
    corpus_digest TEXT NOT NULL,
    replay_id INTEGER NOT NULL,
    target_json TEXT NOT NULL,
    target_digest TEXT NOT NULL,
    observation_json TEXT NOT NULL DEFAULT '{}',
    observation_digest TEXT,
    requested_by INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS dl_approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    deployment_id INTEGER NOT NULL,
    binding_digest TEXT NOT NULL,
    requested_by INTEGER NOT NULL,
    approved_by INTEGER NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('approved','expired','revoked','consumed')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS dl_drift_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    deployment_id INTEGER NOT NULL,
    window_start TIMESTAMP NOT NULL,
    window_end TIMESTAMP NOT NULL,
    baseline_json TEXT NOT NULL,
    observed_json TEXT NOT NULL,
    drift_score REAL NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('ok','warning','breach')),
    digest TEXT NOT NULL,
    created_by INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS dl_rollback_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    deployment_id INTEGER NOT NULL,
    from_artifact_id INTEGER NOT NULL,
    from_digest TEXT NOT NULL,
    restore_artifact_id INTEGER NOT NULL,
    restore_digest TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('dry_run_ready','verified','failed')),
    preview_json TEXT NOT NULL,
    preview_digest TEXT NOT NULL,
    requested_by INTEGER NOT NULL,
    verified_by INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP
);
"""


class ReplayAdapter(Protocol):
    """Pure adapter contract: evaluate sanitized data without external effects."""

    name: str
    version: str

    def evaluate(self, artifact: dict[str, Any], event: dict[str, Any]) -> bool: ...


class DeterministicSandboxAdapter:
    """Evaluate a bounded declarative condition; no code or shell is accepted."""

    name = "declarative-sandbox"
    version = "1"
    _OPERATORS: ClassVar[set[str]] = {"equals", "contains", "exists", "in"}

    @staticmethod
    def _value(event: dict[str, Any], field: str) -> Any:
        value: Any = event
        for part in field.split("."):
            if not isinstance(value, dict) or part not in value:
                return None
            value = value[part]
        return value

    def evaluate(self, artifact: dict[str, Any], event: dict[str, Any]) -> bool:
        condition = artifact.get("condition")
        if not isinstance(condition, dict):
            raise TypeError("rule artifact requires a condition object")
        field = str(condition.get("field", ""))[:200]
        operator = str(condition.get("operator", ""))
        if not field or operator not in self._OPERATORS:
            raise ValueError("unsupported declarative rule condition")
        actual = self._value(event, field)
        expected = condition.get("value")
        if operator == "equals":
            return actual == expected
        if operator == "contains":
            return str(expected).lower() in str(actual or "").lower()
        if operator == "exists":
            return actual is not None
        return isinstance(expected, list) and actual in expected[:1000]


def get_db(path: Path | str | None = None):
    """Return a configured connection and ensure the isolated schema exists."""
    conn = connect_database(path or DB_PATH)
    init_detection_lifecycle_db(conn)
    return conn


def init_detection_lifecycle_db(conn) -> None:
    conn.executescript(LIFECYCLE_SCHEMA)
    conn.commit()


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: Any) -> str:
    raw = value if isinstance(value, str) else _canonical(value)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _row_dict(row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}  # noqa: SIM118 - sqlite3.Row iterates values.


def _org_key(conn, org_id: int) -> bytes:
    row = conn.execute("SELECT pseudonym_key FROM dl_org_keys WHERE org_id = ?", (org_id,)).fetchone()
    if not row:
        key = secrets.token_hex(32)
        conn.execute("INSERT INTO dl_org_keys (org_id, pseudonym_key) VALUES (?, ?)", (org_id, key))
        return bytes.fromhex(key)
    return bytes.fromhex(str(row["pseudonym_key"]))


def _pseudonym(key: bytes, kind: str, value: Any) -> str:
    token = hmac.new(key, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()[:16]
    return f"{kind}-{token}"


def sanitize_event(conn, org_id: int, event: dict[str, Any]) -> dict[str, Any]:
    """Remove secrets and replace identities with stable org-scoped pseudonyms."""
    if not isinstance(event, dict):
        raise TypeError("event must be an object")
    key = _org_key(conn, org_id)

    def clean(value: Any, field: str = "") -> Any:
        field_lower = field.lower()
        if field_lower in SECRET_FIELDS or any(part in field_lower for part in ("password", "secret", "token")):
            return "[REDACTED]"
        if isinstance(value, dict):
            if len(value) > 500:
                raise ValueError("event object is too large")
            return {str(k)[:120]: clean(v, str(k)) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
        if isinstance(value, list):
            if len(value) > 1000:
                raise ValueError("event list is too large")
            return [clean(item, field) for item in value]
        if field_lower in IDENTITY_FIELDS and value not in (None, ""):
            return _pseudonym(key, re.sub(r"[^a-z0-9]+", "_", field_lower)[:30], value)
        if isinstance(value, str):
            return value[:4000]
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return str(value)[:4000]

    return clean(event)


def create_corpus(conn, *, org_id: int, name: str, samples: list[dict[str, Any]], created_by: int) -> dict[str, Any]:
    if not name.strip() or not samples or len(samples) > 10000:
        raise ValueError("corpus requires a name and 1-10000 samples")
    version_row = conn.execute("SELECT COALESCE(MAX(version), 0) + 1 AS value FROM dl_corpora WHERE org_id = ? AND name = ?", (org_id, name.strip())).fetchone()
    version = int(version_row["value"])
    cursor = conn.execute("INSERT INTO dl_corpora (org_id, name, version, created_by) VALUES (?, ?, ?, ?)", (org_id, name.strip()[:200], version, created_by))
    corpus_id = int(cursor.lastrowid)
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict) or sample.get("ground_truth") not in {"malicious", "benign"}:
            raise ValueError("each sample requires malicious or benign ground_truth")
        sanitized = sanitize_event(conn, org_id, sample.get("event", {}))
        sample_key = str(sample.get("sample_key") or f"sample-{index + 1}")[:200]
        sample_digest = _digest({"sample_key": sample_key, "ground_truth": sample["ground_truth"], "event": sanitized})
        conn.execute(
            "INSERT INTO dl_corpus_samples (org_id, corpus_id, sample_key, ground_truth, event_json, sample_digest) VALUES (?, ?, ?, ?, ?, ?)",
            (org_id, corpus_id, sample_key, sample["ground_truth"], _canonical(sanitized), sample_digest),
        )
    audit("detection_corpus_created", org_id=org_id, corpus_id=corpus_id, version=version, sample_count=len(samples))
    return {"id": corpus_id, "version": version, "status": "draft"}


def _corpus_payload(conn, corpus_id: int, org_id: int) -> tuple[Any, list[Any], dict[str, Any]]:
    corpus = conn.execute("SELECT * FROM dl_corpora WHERE id = ? AND org_id = ?", (corpus_id, org_id)).fetchone()
    if not corpus:
        raise ValueError("corpus not found")
    samples = conn.execute("SELECT * FROM dl_corpus_samples WHERE corpus_id = ? AND org_id = ? ORDER BY sample_key", (corpus_id, org_id)).fetchall()
    payload = {
        "name": corpus["name"], "version": corpus["version"],
        "samples": [{"sample_key": row["sample_key"], "ground_truth": row["ground_truth"], "event": json.loads(row["event_json"]), "sample_digest": row["sample_digest"]} for row in samples],
    }
    return corpus, samples, payload


def seal_corpus(conn, corpus_id: int, *, org_id: int, sealed_by: int) -> dict[str, Any]:
    corpus, _samples, payload = _corpus_payload(conn, corpus_id, org_id)
    if corpus["status"] != "draft":
        raise ValueError("only a draft corpus can be sealed")
    digest = _digest(payload)
    conn.execute("UPDATE dl_corpora SET status = 'sealed', digest = ?, sealed_by = ?, sealed_at = CURRENT_TIMESTAMP WHERE id = ? AND org_id = ?", (digest, sealed_by, corpus_id, org_id))
    audit("detection_corpus_sealed", org_id=org_id, corpus_id=corpus_id, digest=digest)
    return {"id": corpus_id, "status": "sealed", "digest": digest}


def verify_corpus(conn, corpus_id: int, *, org_id: int) -> str:
    corpus, samples, payload = _corpus_payload(conn, corpus_id, org_id)
    if corpus["status"] != "sealed" or not corpus["digest"]:
        raise ValueError("corpus is not sealed")
    for row in samples:
        expected = _digest({"sample_key": row["sample_key"], "ground_truth": row["ground_truth"], "event": json.loads(row["event_json"])})
        if not hmac.compare_digest(expected, str(row["sample_digest"])):
            raise ValueError("corpus sample integrity check failed")
    computed = _digest(payload)
    if not hmac.compare_digest(computed, str(corpus["digest"])):
        raise ValueError("corpus integrity check failed")
    return computed


def create_rule_artifact(conn, *, org_id: int, platform: str, rule_key: str, content: dict[str, Any], created_by: int, parent_artifact_id: int | None = None) -> dict[str, Any]:
    if not isinstance(content, dict) or not rule_key.strip():
        raise ValueError("rule key and object content are required")
    # Validate the declarative form now so malformed rules never enter replay.
    DeterministicSandboxAdapter().evaluate(content, {})
    if parent_artifact_id is not None and not conn.execute("SELECT id FROM dl_rule_artifacts WHERE id = ? AND org_id = ?", (parent_artifact_id, org_id)).fetchone():
        raise ValueError("parent rule artifact not found")
    version = int(conn.execute("SELECT COALESCE(MAX(version), 0) + 1 AS value FROM dl_rule_artifacts WHERE org_id = ? AND rule_key = ?", (org_id, rule_key)).fetchone()["value"])
    normalized = json.loads(_canonical(content))
    digest = _digest({"platform": platform, "rule_key": rule_key, "version": version, "content": normalized, "parent_artifact_id": parent_artifact_id})
    cursor = conn.execute(
        "INSERT INTO dl_rule_artifacts (org_id, platform, rule_key, version, content_json, digest, parent_artifact_id, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (org_id, platform[:60], rule_key[:200], version, _canonical(normalized), digest, parent_artifact_id, created_by),
    )
    return {"id": int(cursor.lastrowid), "version": version, "digest": digest}


def _artifact(conn, artifact_id: int, org_id: int) -> tuple[Any, dict[str, Any]]:
    row = conn.execute("SELECT * FROM dl_rule_artifacts WHERE id = ? AND org_id = ?", (artifact_id, org_id)).fetchone()
    if not row:
        raise ValueError("rule artifact not found")
    content = json.loads(row["content_json"])
    expected = _digest({"platform": row["platform"], "rule_key": row["rule_key"], "version": row["version"], "content": content, "parent_artifact_id": row["parent_artifact_id"]})
    if not hmac.compare_digest(expected, str(row["digest"])):
        raise ValueError("rule artifact integrity check failed")
    return row, content


def _confusion(results: list[tuple[str, bool]]) -> dict[str, Any]:
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for truth, detected in results:
        counts[("t" if detected == (truth == "malicious") else "f") + ("p" if detected else "n")] += 1
    tp, fp, tn, fn = (counts[key] for key in ("tp", "fp", "tn", "fn"))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    specificity = tn / (tn + fp) if tn + fp else None
    accuracy = (tp + tn) / len(results) if results else None
    return {**counts, "precision": precision, "recall": recall, "specificity": specificity, "accuracy": accuracy, "sample_count": len(results)}


def run_replay(conn, *, org_id: int, corpus_id: int, baseline_artifact_id: int, candidate_artifact_id: int, requested_by: int, adapter: ReplayAdapter | None = None) -> dict[str, Any]:
    adapter = adapter or DeterministicSandboxAdapter()
    corpus_digest = verify_corpus(conn, corpus_id, org_id=org_id)
    baseline_row, baseline = _artifact(conn, baseline_artifact_id, org_id)
    candidate_row, candidate = _artifact(conn, candidate_artifact_id, org_id)
    samples = conn.execute("SELECT * FROM dl_corpus_samples WHERE corpus_id = ? AND org_id = ? ORDER BY sample_key", (corpus_id, org_id)).fetchall()
    per_sample: list[dict[str, Any]] = []
    baseline_pairs: list[tuple[str, bool]] = []
    candidate_pairs: list[tuple[str, bool]] = []
    for sample in samples:
        event = json.loads(sample["event_json"])
        baseline_detected = bool(adapter.evaluate(baseline, event))
        candidate_detected = bool(adapter.evaluate(candidate, event))
        baseline_pairs.append((sample["ground_truth"], baseline_detected))
        candidate_pairs.append((sample["ground_truth"], candidate_detected))
        per_sample.append({"sample_key": sample["sample_key"], "ground_truth": sample["ground_truth"], "baseline_detected": baseline_detected, "candidate_detected": candidate_detected, "latency_ms": 0.0})
    baseline_metrics = _confusion(baseline_pairs)
    candidate_metrics = _confusion(candidate_pairs)
    metrics = {"baseline": baseline_metrics, "candidate": candidate_metrics, "delta": {key: (candidate_metrics[key] - baseline_metrics[key]) if candidate_metrics[key] is not None and baseline_metrics[key] is not None else None for key in ("precision", "recall", "specificity", "accuracy")}}
    results_digest = _digest(per_sample)
    cursor = conn.execute(
        "INSERT INTO dl_replay_runs (org_id, corpus_id, corpus_digest, baseline_artifact_id, baseline_digest, candidate_artifact_id, candidate_digest, adapter_name, adapter_version, status, metrics_json, results_digest, requested_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?, ?, ?)",
        (org_id, corpus_id, corpus_digest, baseline_artifact_id, baseline_row["digest"], candidate_artifact_id, candidate_row["digest"], adapter.name, adapter.version, _canonical(metrics), results_digest, requested_by),
    )
    replay_id = int(cursor.lastrowid)
    for item in per_sample:
        result_digest = _digest(item)
        conn.execute("INSERT INTO dl_replay_results (org_id, replay_id, sample_key, ground_truth, baseline_detected, candidate_detected, latency_ms, result_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (org_id, replay_id, item["sample_key"], item["ground_truth"], int(item["baseline_detected"]), int(item["candidate_detected"]), item["latency_ms"], result_digest))
    audit("detection_replay_completed", org_id=org_id, replay_id=replay_id, candidate_digest=candidate_row["digest"])
    return {"id": replay_id, "status": "completed", "metrics": metrics, "results_digest": results_digest}


def _replay(conn, replay_id: int, org_id: int):
    row = conn.execute("SELECT * FROM dl_replay_runs WHERE id = ? AND org_id = ?", (replay_id, org_id)).fetchone()
    if not row:
        raise ValueError("replay not found")
    verify_corpus(conn, int(row["corpus_id"]), org_id=org_id)
    candidate, _ = _artifact(conn, int(row["candidate_artifact_id"]), org_id)
    if candidate["digest"] != row["candidate_digest"]:
        raise ValueError("replay candidate digest no longer matches")
    return row


def create_deployment(conn, *, org_id: int, mode: str, replay_id: int, target: dict[str, Any], requested_by: int) -> dict[str, Any]:
    if mode not in {"shadow", "canary"} or not isinstance(target, dict):
        raise ValueError("mode must be shadow or canary and target must be an object")
    replay = _replay(conn, replay_id, org_id)
    metrics = json.loads(replay["metrics_json"])["candidate"]
    if metrics["sample_count"] < 2 or metrics["recall"] is None:
        raise ValueError("replay evidence is insufficient for deployment")
    if mode == "canary":
        shadow = conn.execute("SELECT id FROM dl_deployments WHERE org_id = ? AND artifact_digest = ? AND corpus_digest = ? AND mode = 'shadow' AND status = 'completed'", (org_id, replay["candidate_digest"], replay["corpus_digest"])).fetchone()
        if not shadow:
            raise ValueError("a completed shadow deployment is required before canary")
    target_json = _canonical(target)
    target_digest = _digest(target)
    cursor = conn.execute("INSERT INTO dl_deployments (org_id, mode, status, artifact_id, artifact_digest, corpus_digest, replay_id, target_json, target_digest, requested_by) VALUES (?, ?, 'dry_run_ready', ?, ?, ?, ?, ?, ?, ?)", (org_id, mode, replay["candidate_artifact_id"], replay["candidate_digest"], replay["corpus_digest"], replay_id, target_json, target_digest, requested_by))
    return {"id": int(cursor.lastrowid), "mode": mode, "status": "dry_run_ready", "target_digest": target_digest}


def complete_deployment(conn, deployment_id: int, *, org_id: int, observations: dict[str, Any], completed_by: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM dl_deployments WHERE id = ? AND org_id = ?", (deployment_id, org_id)).fetchone()
    if not row or row["status"] not in {"dry_run_ready", "observing"}:
        raise ValueError("deployment is not ready for observation completion")
    if not isinstance(observations, dict) or int(observations.get("events", 0)) < 1 or int(observations.get("errors", 0)) > 0:
        raise ValueError("successful bounded observations are required")
    observation_json = _canonical(observations)
    observation_digest = _digest(observations)
    status = "approval_required" if row["mode"] == "canary" else "completed"
    conn.execute("UPDATE dl_deployments SET status = ?, observation_json = ?, observation_digest = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ? AND org_id = ?", (status, observation_json, observation_digest, deployment_id, org_id))
    audit("detection_deployment_observed", org_id=org_id, deployment_id=deployment_id, mode=row["mode"], completed_by=completed_by)
    return {"id": deployment_id, "status": status, "observation_digest": observation_digest}


def _approval_binding(deployment) -> str:
    return _digest({"deployment_id": deployment["id"], "artifact_digest": deployment["artifact_digest"], "corpus_digest": deployment["corpus_digest"], "target_digest": deployment["target_digest"], "observation_digest": deployment["observation_digest"]})


def approve_canary(conn, deployment_id: int, *, org_id: int, approved_by: int, ttl_minutes: int = 60) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM dl_deployments WHERE id = ? AND org_id = ?", (deployment_id, org_id)).fetchone()
    if not row or row["mode"] != "canary" or row["status"] != "approval_required":
        raise ValueError("completed canary evidence is required")
    if int(row["requested_by"]) == int(approved_by):
        raise PermissionError("requester cannot approve their own deployment")
    ttl_minutes = max(1, min(int(ttl_minutes), 1440))
    expires_at = (_utcnow() + timedelta(minutes=ttl_minutes)).isoformat()
    binding = _approval_binding(row)
    cursor = conn.execute("INSERT INTO dl_approvals (org_id, deployment_id, binding_digest, requested_by, approved_by, expires_at, status) VALUES (?, ?, ?, ?, ?, ?, 'approved')", (org_id, deployment_id, binding, row["requested_by"], approved_by, expires_at))
    conn.execute("UPDATE dl_deployments SET status = 'approved' WHERE id = ? AND org_id = ?", (deployment_id, org_id))
    return {"id": int(cursor.lastrowid), "status": "approved", "binding_digest": binding, "expires_at": expires_at}


def prepare_production_dry_run(conn, deployment_id: int, *, org_id: int, requested_by: int) -> dict[str, Any]:
    deployment = conn.execute("SELECT * FROM dl_deployments WHERE id = ? AND org_id = ?", (deployment_id, org_id)).fetchone()
    if not deployment or deployment["mode"] != "canary" or deployment["status"] != "approved":
        raise ValueError("approved canary is required")
    approval = conn.execute("SELECT * FROM dl_approvals WHERE deployment_id = ? AND org_id = ? AND status = 'approved' ORDER BY id DESC LIMIT 1", (deployment_id, org_id)).fetchone()
    if not approval:
        raise ValueError("approval not found")
    # Python 3.10 does not accept the ISO 8601 Z suffix directly.
    expires = datetime.fromisoformat(str(approval["expires_at"]).replace("Z", "+00:00"))  # noqa: FURB162
    if expires <= _utcnow():
        conn.execute("UPDATE dl_approvals SET status = 'expired' WHERE id = ?", (approval["id"],))
        raise ValueError("approval has expired")
    if not hmac.compare_digest(str(approval["binding_digest"]), _approval_binding(deployment)):
        raise ValueError("approval binding integrity check failed")
    cursor = conn.execute("INSERT INTO dl_deployments (org_id, mode, status, artifact_id, artifact_digest, corpus_digest, replay_id, target_json, target_digest, observation_json, requested_by) VALUES (?, 'production', 'dry_run_ready', ?, ?, ?, ?, ?, ?, ?, ?)", (org_id, deployment["artifact_id"], deployment["artifact_digest"], deployment["corpus_digest"], deployment["replay_id"], deployment["target_json"], deployment["target_digest"], _canonical({"source_canary_id": deployment_id, "action": "preview_only"}), requested_by))
    conn.execute("UPDATE dl_approvals SET status = 'consumed' WHERE id = ?", (approval["id"],))
    return {"id": int(cursor.lastrowid), "mode": "production", "status": "dry_run_ready", "external_write": False}


def record_drift_window(conn, *, org_id: int, deployment_id: int, baseline: dict[str, float], observed: dict[str, float], created_by: int, warning_threshold: float = 0.15, breach_threshold: float = 0.30) -> dict[str, Any]:
    deployment = conn.execute("SELECT id FROM dl_deployments WHERE id = ? AND org_id = ?", (deployment_id, org_id)).fetchone()
    if not deployment or not baseline:
        raise ValueError("deployment and baseline metrics are required")
    shared = sorted(set(baseline) & set(observed))
    if not shared:
        raise ValueError("observed metrics do not match baseline")
    score = math.sqrt(sum((float(observed[key]) - float(baseline[key])) ** 2 for key in shared) / len(shared))
    status = "breach" if score >= breach_threshold else "warning" if score >= warning_threshold else "ok"
    now = _utcnow()
    payload = {"deployment_id": deployment_id, "baseline": baseline, "observed": observed, "score": score, "status": status}
    digest = _digest(payload)
    cursor = conn.execute("INSERT INTO dl_drift_windows (org_id, deployment_id, window_start, window_end, baseline_json, observed_json, drift_score, status, digest, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (org_id, deployment_id, (now - timedelta(minutes=5)).isoformat(), now.isoformat(), _canonical(baseline), _canonical(observed), score, status, digest, created_by))
    return {"id": int(cursor.lastrowid), "drift_score": score, "status": status, "digest": digest}


def prepare_rollback(conn, *, org_id: int, deployment_id: int, restore_artifact_id: int, reason: str, requested_by: int) -> dict[str, Any]:
    deployment = conn.execute("SELECT * FROM dl_deployments WHERE id = ? AND org_id = ?", (deployment_id, org_id)).fetchone()
    restore, _ = _artifact(conn, restore_artifact_id, org_id)
    if not deployment or deployment["mode"] != "production":
        raise ValueError("production deployment not found")
    if not reason.strip() or restore["digest"] == deployment["artifact_digest"]:
        raise ValueError("rollback requires a prior artifact and reason")
    preview = {"action": "restore_rule_artifact", "platform_write": False, "from_digest": deployment["artifact_digest"], "restore_digest": restore["digest"], "rollback_note": reason.strip()[:1000]}
    preview_digest = _digest(preview)
    cursor = conn.execute("INSERT INTO dl_rollback_events (org_id, deployment_id, from_artifact_id, from_digest, restore_artifact_id, restore_digest, reason, status, preview_json, preview_digest, requested_by) VALUES (?, ?, ?, ?, ?, ?, ?, 'dry_run_ready', ?, ?, ?)", (org_id, deployment_id, deployment["artifact_id"], deployment["artifact_digest"], restore_artifact_id, restore["digest"], reason.strip()[:1000], _canonical(preview), preview_digest, requested_by))
    return {"id": int(cursor.lastrowid), "status": "dry_run_ready", "preview": preview, "preview_digest": preview_digest}


def verify_rollback(conn, rollback_id: int, *, org_id: int, verified_by: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM dl_rollback_events WHERE id = ? AND org_id = ?", (rollback_id, org_id)).fetchone()
    if not row or row["status"] != "dry_run_ready":
        raise ValueError("rollback preview not found")
    if int(row["requested_by"]) == int(verified_by):
        raise PermissionError("requester cannot verify their own rollback")
    preview = json.loads(row["preview_json"])
    if not hmac.compare_digest(_digest(preview), str(row["preview_digest"])):
        raise ValueError("rollback preview integrity check failed")
    restore, _ = _artifact(conn, int(row["restore_artifact_id"]), org_id)
    if restore["digest"] != row["restore_digest"]:
        raise ValueError("rollback artifact integrity check failed")
    conn.execute("UPDATE dl_rollback_events SET status = 'verified', verified_by = ?, verified_at = CURRENT_TIMESTAMP WHERE id = ? AND org_id = ?", (verified_by, rollback_id, org_id))
    conn.execute("UPDATE dl_deployments SET status = 'rolled_back' WHERE id = ? AND org_id = ?", (row["deployment_id"], org_id))
    audit("detection_rollback_verified", org_id=org_id, rollback_id=rollback_id, external_write=False)
    return {"id": rollback_id, "status": "verified", "external_write": False}


def lifecycle_summary(conn, org_id: int) -> dict[str, list[dict[str, Any]]]:
    """Return a tenant-scoped UI projection without exposing pseudonym keys."""
    tables = {
        "corpora": "dl_corpora", "artifacts": "dl_rule_artifacts", "replays": "dl_replay_runs",
        "deployments": "dl_deployments", "drift_windows": "dl_drift_windows", "rollbacks": "dl_rollback_events",
    }
    summary = {}
    for name, table in tables.items():
        # Table names come only from the closed mapping above; tenant data stays parameterized.
        query = f"SELECT * FROM {table} WHERE org_id = ? ORDER BY id DESC LIMIT 50"  # nosec B608
        summary[name] = [_row_dict(row) for row in conn.execute(query, (org_id,)).fetchall()]
    return summary
