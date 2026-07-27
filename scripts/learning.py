"""Local learning store for playbook, case, and alert outcomes.

The learning layer records operational patterns and creates reviewable Codex
skill drafts. It does not auto-install skills or mutate playbooks.
"""

from __future__ import annotations

import json
import re
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
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

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

                CREATE INDEX IF NOT EXISTS idx_learning_category_subject
                    ON learning_events(category, subject);
                CREATE INDEX IF NOT EXISTS idx_skill_suggestions_category
                    ON skill_suggestions(category);
                """
            )
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
    ) -> int:
        """Record one learning event and refresh matching skill suggestions."""
        conn = self._connect()
        try:
            cursor = conn.execute(
                """
                INSERT INTO learning_events
                    (source, category, subject, severity, summary, evidence_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    source,
                    category,
                    subject,
                    severity,
                    summary,
                    json.dumps(evidence or {}, sort_keys=True),
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
        self.refresh_skill_suggestions(category=category, subject=subject)
        return event_id

    def learn_from_alert(
        self,
        alert: dict[str, Any],
        *,
        source: str = "alert",
        playbook: str | None = None,
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
        )

    def learn_from_playbook_result(
        self,
        playbook_name: str,
        result: dict[str, Any],
        alert: dict[str, Any] | None = None,
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
                )
            elif str(step_result.get("status", "")).startswith("pending"):
                self.record_event(
                    source="playbook",
                    category="pending_capability",
                    subject=f"{playbook_name}:{step_id}",
                    severity="medium",
                    summary=f"Step {step_id} in {playbook_name} requires follow-up execution support.",
                    evidence={"step_result": step_result, "alert_rule": _alert_rule(alert)},
                )

    def learn_from_case(self, case: dict[str, Any]) -> None:
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
        )

    def refresh_skill_suggestions(
        self,
        *,
        category: str | None = None,
        subject: str | None = None,
        minimum_events: int = 1,
    ) -> list[dict[str, Any]]:
        """Create or update reviewable skill drafts from repeated signals."""
        conn = self._connect()
        try:
            where = []
            params: list[Any] = []
            if category:
                where.append("category = ?")
                params.append(category)
            if subject:
                where.append("subject = ?")
                params.append(subject)
            clause = "WHERE " + " AND ".join(where) if where else ""
            rows = conn.execute(
                f"""
                SELECT category, subject, COUNT(*) AS count,
                       MAX(severity) AS severity,
                       MAX(summary) AS latest_summary
                FROM learning_events
                {clause}
                GROUP BY category, subject
                HAVING COUNT(*) >= ?
                ORDER BY count DESC, subject
                """,
                (*params, minimum_events),
            ).fetchall()
        finally:
            conn.close()

        suggestions = []
        for row in rows:
            suggestions.append(self._upsert_skill_suggestion(dict(row)))
        return suggestions

    def list_skill_suggestions(self, limit: int = 20) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT * FROM skill_suggestions
                ORDER BY event_count DESC, updated_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def _upsert_skill_suggestion(self, signal: dict[str, Any]) -> dict[str, Any]:
        category = signal["category"]
        subject = signal["subject"]
        event_count = int(signal["count"])
        slug = safe_name(f"{category}-{subject}").lower()
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
                    (slug, title, category, reason, draft_path, event_count)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(slug) DO UPDATE SET
                    reason = excluded.reason,
                    draft_path = excluded.draft_path,
                    event_count = excluded.event_count,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (slug, title, category, reason, str(draft_path), event_count),
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
  Review, edit, and install manually before use.
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
- Save generated artifacts as reviewable drafts before installation.
"""


def learn_playbook_result(
    playbook_name: str,
    result: dict[str, Any],
    alert: dict[str, Any] | None = None,
) -> None:
    LearningStore().learn_from_playbook_result(playbook_name, result, alert)


def learn_alert(alert: dict[str, Any], source: str, playbook: str | None = None) -> None:
    LearningStore().learn_from_alert(alert, source=source, playbook=playbook)


def learn_case(case: dict[str, Any]) -> None:
    LearningStore().learn_from_case(case)
