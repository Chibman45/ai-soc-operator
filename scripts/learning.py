"""Local learning store for playbook, case, and alert outcomes.

The learning layer records operational patterns and creates reviewable Codex
skill drafts. Publication is delegated to the approval-gated capability ledger.
"""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from .common import ROOT, audit, safe_name, utc_now
except ImportError:
    from scripts.common import ROOT, audit, safe_name, utc_now


DB_PATH = ROOT / "data" / "soc_operator.db"
SKILL_DRAFT_DIR = ROOT / "data" / "learning" / "skill_drafts"


class LearningStore:
    """Persist and summarize operational learning signals."""

    def __init__(self, db_path: Path = DB_PATH, draft_dir: Path = SKILL_DRAFT_DIR):
        self.db_path = db_path
        self.draft_dir = draft_dir
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        from web.services.database import connect_database

        return connect_database(self.db_path)

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS learning_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    category TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    severity TEXT DEFAULT 'info',
                    summary TEXT NOT NULL,
                    evidence_json TEXT DEFAULT '{}',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS skill_suggestions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    slug TEXT UNIQUE NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    draft_path TEXT NOT NULL,
                    event_count INTEGER DEFAULT 1,
                    status TEXT DEFAULT 'draft',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS skill_evaluations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    suggestion_id INTEGER NOT NULL,
                    org_id INTEGER,
                    corpus_version TEXT NOT NULL,
                    passed INTEGER NOT NULL,
                    score REAL NOT NULL,
                    details_json TEXT DEFAULT '{}',
                    evaluated_by INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (suggestion_id) REFERENCES skill_suggestions(id)
                );

                CREATE INDEX IF NOT EXISTS idx_learning_category_subject
                    ON learning_events(category, subject);
                CREATE INDEX IF NOT EXISTS idx_skill_suggestions_category
                    ON skill_suggestions(category);
                """
            )
            for table, columns in {
                "learning_events": {"org_id": "INTEGER"},
                "skill_suggestions": {
                    "org_id": "INTEGER",
                    "reviewed_by": "INTEGER",
                    "reviewed_at": "TIMESTAMP",
                    "published_at": "TIMESTAMP",
                },
            }.items():
                existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
                for name, definition in columns.items():
                    if name not in existing:
                        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
            conn.commit()
        finally:
            conn.close()

    def record_event(
        self,
        *,
        source: str,
        category: str,
        subject: str,
        summary: str,
        severity: str = "info",
        evidence: dict[str, Any] | None = None,
        org_id: int | None = None,
    ) -> int:
        """Record one learning event and refresh matching skill suggestions."""
        conn = self._connect()
        try:
            cursor = conn.execute(
                """
                INSERT INTO learning_events
                    (source, category, subject, severity, summary, evidence_json, org_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source,
                    category,
                    subject,
                    severity,
                    summary,
                    json.dumps(_redact_sensitive(evidence or {}), sort_keys=True),
                    org_id,
                ),
            )
            event_id = int(cursor.lastrowid)
            conn.commit()
        finally:
            conn.close()

        audit(
            "learning_event_recorded",
            source=source,
            category=category,
            subject=subject,
            severity=severity,
        )
        self.refresh_skill_suggestions(category=category, subject=subject, org_id=org_id)
        return event_id

    def learn_from_alert(
        self,
        alert: dict[str, Any],
        *,
        source: str = "alert",
        playbook: str | None = None,
        org_id: int | None = None,
    ) -> None:
        """Learn from a Wazuh or generic alert before execution."""
        rule = (alert.get("rule") or {}).get("name") or alert.get("title") or "unknown-alert"
        tags = alert.get("tags") or []
        evidence = {
            "rule": alert.get("rule", {}),
            "tags": tags,
            "severity": alert.get("severity"),
            "playbook": playbook,
        }
        self.record_event(
            source=source,
            category="alert_pattern",
            subject=str(rule),
            severity=str(alert.get("severity") or "info"),
            summary=f"Observed alert pattern: {rule}",
            evidence=evidence,
            org_id=org_id,
        )

    def learn_from_playbook_result(
        self,
        playbook_name: str,
        result: dict[str, Any],
        alert: dict[str, Any] | None = None,
        org_id: int | None = None,
    ) -> None:
        """Learn from completed playbook execution and failed/pending steps."""
        steps = result.get("steps", {})
        for step_id, step_result in steps.items():
            if not isinstance(step_result, dict):
                continue
            if "error" in step_result:
                self.record_event(
                    source="playbook",
                    category="playbook_step_error",
                    subject=f"{playbook_name}:{step_id}",
                    severity="high",
                    summary=f"Step {step_id} failed in {playbook_name}: {step_result['error']}",
                    evidence={"step_result": step_result, "alert_rule": _alert_rule(alert)},
                    org_id=org_id,
                )
            elif str(step_result.get("status", "")).startswith("pending"):
                self.record_event(
                    source="playbook",
                    category="pending_capability",
                    subject=f"{playbook_name}:{step_id}",
                    severity="medium",
                    summary=f"Step {step_id} in {playbook_name} requires follow-up execution support.",
                    evidence={"step_result": step_result, "alert_rule": _alert_rule(alert)},
                    org_id=org_id,
                )

    def learn_from_case(self, case: dict[str, Any], org_id: int | None = None) -> None:
        """Learn from a local case record."""
        title = str(case.get("title") or "untitled-case")
        self.record_event(
            source="case",
            category="case_pattern",
            subject=title,
            severity=str(case.get("severity") or "info"),
            summary=f"Case created or updated: {title}",
            evidence={
                "case_id": case.get("id") or case.get("case_id"),
                "status": case.get("status"),
                "summary": str(case.get("summary") or "")[:500],
            },
            org_id=org_id,
        )

    def refresh_skill_suggestions(
        self,
        *,
        category: str | None = None,
        subject: str | None = None,
        minimum_events: int = 1,
        org_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """Create or update reviewable skill drafts from repeated signals."""
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT category, subject, COUNT(*) AS count,
                       MAX(severity) AS severity,
                       MAX(summary) AS latest_summary
                FROM learning_events
                WHERE (? IS NULL OR category = ?)
                  AND (? IS NULL OR subject = ?)
                  AND (? IS NULL OR org_id = ?)
                GROUP BY category, subject
                HAVING COUNT(*) >= ?
                ORDER BY count DESC, subject
                """,
                (category, category, subject, subject, org_id, org_id, minimum_events),
            ).fetchall()
        finally:
            conn.close()

        suggestions = []
        for row in rows:
            suggestions.append(self._upsert_skill_suggestion({**dict(row), "org_id": org_id}))
        return suggestions

    def list_skill_suggestions(self, limit: int = 20, org_id: int | None = None) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            if org_id is None:
                rows = conn.execute("SELECT * FROM skill_suggestions ORDER BY event_count DESC, updated_at DESC LIMIT ?", (limit,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM skill_suggestions WHERE org_id = ? ORDER BY event_count DESC, updated_at DESC LIMIT ?", (org_id, limit)).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def _upsert_skill_suggestion(self, signal: dict[str, Any]) -> dict[str, Any]:
        category = signal["category"]
        subject = signal["subject"]
        event_count = int(signal["count"])
        org_id = signal.get("org_id")
        slug = safe_name(f"{org_id or 'global'}-{category}-{subject}").lower()
        title = _title_for(category, subject)
        reason = (
            f"{event_count} learning event(s) for {subject}. "
            f"Latest signal: {signal.get('latest_summary', '')}"
        )
        draft_path = self._write_skill_draft(slug, title, category, subject, reason)

        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO skill_suggestions
                    (slug, title, category, reason, draft_path, event_count, org_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(slug) DO UPDATE SET
                    reason = excluded.reason,
                    draft_path = excluded.draft_path,
                    event_count = excluded.event_count,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (slug, title, category, reason, str(draft_path), event_count, org_id),
            )
            conn.commit()
        finally:
            conn.close()

        audit("skill_suggestion_updated", slug=slug, category=category, subject=subject)
        return {
            "slug": slug,
            "title": title,
            "category": category,
            "reason": reason,
            "draft_path": str(draft_path),
            "event_count": event_count,
        }

    def record_evaluation(
        self,
        suggestion_id: int,
        *,
        org_id: int,
        corpus_version: str,
        score: float,
        passed: bool,
        evaluated_by: int,
        details: dict[str, Any] | None = None,
    ) -> int:
        conn = self._connect()
        try:
            exists = conn.execute(
                "SELECT 1 FROM skill_suggestions WHERE id = ? AND org_id = ?",
                (suggestion_id, org_id),
            ).fetchone()
            if not exists:
                raise ValueError("Skill suggestion not found")
            cursor = conn.execute(
                "INSERT INTO skill_evaluations (suggestion_id, org_id, corpus_version, passed, score, details_json, evaluated_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (suggestion_id, org_id, corpus_version, 1 if passed else 0, score, json.dumps(_redact_sensitive(details or {}), sort_keys=True), evaluated_by),
            )
            conn.commit()
            return int(cursor.lastrowid)
        finally:
            conn.close()

    def transition_suggestion(self, suggestion_id: int, *, org_id: int, status: str, reviewed_by: int) -> dict[str, Any]:
        transitions = {
            "draft": {"under_review", "rejected"},
            "under_review": {"approved", "rejected"},
            "approved": {"shadow", "rejected"},
            "shadow": {"canary", "rolled_back"},
            # Publication has a dedicated method because it must atomically
            # create an immutable capability proposal for independent review.
            "canary": {"rolled_back"},
            "publication_requested": {"rolled_back"},
            "published": {"rolled_back"},
            "rejected": set(),
            "rolled_back": set(),
        }
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT status, slug FROM skill_suggestions WHERE id = ? AND org_id = ?",
                (suggestion_id, org_id),
            ).fetchone()
            if not row:
                raise ValueError("Skill suggestion not found")
            current = str(row["status"])
            if status not in transitions.get(current, set()):
                raise ValueError(f"Invalid learning transition: {current} -> {status}")
            if status in {"approved", "shadow", "canary", "publication_requested"}:
                evaluation = conn.execute(
                    "SELECT passed FROM skill_evaluations WHERE suggestion_id = ? AND org_id = ? ORDER BY id DESC LIMIT 1",
                    (suggestion_id, org_id),
                ).fetchone()
                if not evaluation or not evaluation["passed"]:
                    raise PermissionError("A passing evaluation is required before promotion")
            if current == "published" and status == "rolled_back":
                self._archive_published_skill(str(row["slug"]), suggestion_id)
            conn.execute(
                "UPDATE skill_suggestions SET status = ?, reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND org_id = ?",
                (status, reviewed_by, suggestion_id, org_id),
            )
            conn.commit()
        finally:
            conn.close()
        audit("skill_suggestion_transitioned", suggestion_id=suggestion_id, org_id=org_id, status=status, reviewed_by=reviewed_by)
        return {"id": suggestion_id, "status": status}

    def _archive_published_skill(self, slug: str, suggestion_id: int) -> None:
        published_root = (ROOT / "skills" / "generated").resolve()
        source = (published_root / slug).resolve()
        if not source.is_relative_to(published_root):
            raise PermissionError("published skill path escaped its controlled root")
        if not source.exists():
            return
        archive_root = (ROOT / "data" / "learning" / "rolled_back").resolve()
        archive_root.mkdir(parents=True, exist_ok=True)
        destination = archive_root / f"{slug}-{suggestion_id}-{utc_now().replace(':', '')}"
        # Moving the directory out of generated skills makes rollback effective
        # immediately while retaining the exact artifact for audit and recovery.
        shutil.move(str(source), str(destination))

    def request_publication(
        self,
        suggestion_id: int,
        *,
        org_id: int,
        requested_by: int | None = None,
        source: str = "learning",
    ) -> dict[str, Any]:
        """Create a human-approved publication request for a canary skill."""
        from web.services.capabilities import create_capability_proposal

        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM skill_suggestions WHERE id = ? AND org_id = ?",
                (suggestion_id, org_id),
            ).fetchone()
            if not row:
                raise ValueError("Skill suggestion not found")
            if row["status"] != "canary":
                raise ValueError("Only a canary skill can request publication")
            evaluation = conn.execute(
                "SELECT passed FROM skill_evaluations WHERE suggestion_id = ? AND org_id = ? ORDER BY id DESC LIMIT 1",
                (suggestion_id, org_id),
            ).fetchone()
            if not evaluation or not evaluation["passed"]:
                raise PermissionError("A passing evaluation is required before publication request")
            conn.execute(
                "UPDATE skill_suggestions SET status = 'publication_requested', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND org_id = ? AND status = 'canary'",
                (suggestion_id, org_id),
            )
            proposal = create_capability_proposal(
                conn,
                org_id=org_id,
                kind="skill_publish",
                target=str(row["slug"]),
                reason=f"Publish evaluated canary skill: {row['title']}. {row['reason']}",
                manifest={"suggestion_id": suggestion_id, "slug": row["slug"]},
                requested_by=requested_by,
                source=source,
            )
            conn.commit()
        finally:
            conn.close()
        audit("skill_publication_requested", suggestion_id=suggestion_id, org_id=org_id, proposal_id=proposal["id"])
        return proposal

    def _write_skill_draft(
        self,
        slug: str,
        title: str,
        category: str,
        subject: str,
        reason: str,
    ) -> Path:
        self.draft_dir.mkdir(parents=True, exist_ok=True)
        draft_dir = self.draft_dir / slug
        draft_dir.mkdir(parents=True, exist_ok=True)
        skill_path = draft_dir / "SKILL.md"
        skill_path.write_text(
            _draft_skill_markdown(title, category, subject, reason),
            encoding="utf-8",
        )
        return skill_path


def _alert_rule(alert: dict[str, Any] | None) -> str | None:
    if not alert:
        return None
    return (alert.get("rule") or {}).get("name") or alert.get("title")


def _redact_sensitive(value: Any, key: str = "") -> Any:
    sensitive = {"password", "passwd", "secret", "token", "api_key", "apikey", "authorization", "credential"}
    if any(marker in key.lower() for marker in sensitive):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact_sensitive(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_sensitive(item, key) for item in value]
    if isinstance(value, str) and len(value) > 10000:
        return value[:10000] + "[TRUNCATED]"
    return value


def _title_for(category: str, subject: str) -> str:
    compact = re.sub(r"[^a-zA-Z0-9_.:-]+", " ", subject).strip()
    compact = compact.replace("-", " ").replace("_", " ")
    return f"{category.replace('_', ' ').title()}: {compact[:80].title()}"


def _draft_skill_markdown(title: str, category: str, subject: str, reason: str) -> str:
    skill_name = safe_name(title).lower()
    return f"""---
name: {skill_name}
description: >
  Draft skill suggested by AI SOC Operator learning events for {category}: {subject}.
  Evaluate in shadow and canary modes before requesting approval to publish.
---

# {title}

## Why This Draft Exists

{reason}

## When To Use

Use this draft when investigating repeated `{category}` signals related to `{subject}`.

## Workflow

1. Confirm the alert, case, or playbook evidence that triggered this pattern.
2. Identify affected users, hosts, IP addresses, domains, files, and timestamps.
3. Separate confirmed facts from hypotheses.
4. Check existing playbooks for a matching response path.
5. Recommend a concrete fix, new playbook step, or platform integration improvement.
6. Record the outcome in the case timeline and audit log.

## Guardrails

- Do not run active tests outside configured scope.
- Do not expose credentials or sensitive evidence.
- Require approval before platform writes or containment actions.
- Never treat generated instructions as executable until evaluation and independent approval succeed.
"""


def learn_playbook_result(
    playbook_name: str,
    result: dict[str, Any],
    alert: dict[str, Any] | None = None,
    org_id: int | None = None,
) -> None:
    LearningStore().learn_from_playbook_result(playbook_name, result, alert, org_id=org_id)


def learn_alert(alert: dict[str, Any], source: str, playbook: str | None = None, org_id: int | None = None) -> None:
    LearningStore().learn_from_alert(alert, source=source, playbook=playbook, org_id=org_id)


def learn_case(case: dict[str, Any], org_id: int | None = None) -> None:
    LearningStore().learn_from_case(case, org_id=org_id)
