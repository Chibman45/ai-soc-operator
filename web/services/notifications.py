"""Notification abstraction for SOC workflow events."""

from __future__ import annotations

import json
import os
import sqlite3
import smtplib
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any

from scripts.common import audit


def enqueue_notification(
    conn,
    *,
    event_type: str,
    message: str,
    severity: str = "info",
    channel: str = "console",
    metadata: dict[str, Any] | None = None,
    org_id: int | None = None,
    dedup_key: str | None = None,
) -> int:
    if org_id is None:
        raise ValueError("organization context is required for notifications")
    if dedup_key:
        existing = conn.execute(
            "SELECT id FROM notifications WHERE org_id = ? AND dedup_key = ? LIMIT 1",
            (org_id, dedup_key),
        ).fetchone()
        if existing:
            return int(existing["id"])
    try:
        cursor = conn.execute(
            """
            INSERT INTO notifications
                (org_id, event_type, severity, channel, status, message, metadata_json, dedup_key)
            VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)
            """,
            (org_id, event_type, severity, channel, message, json.dumps(metadata or {}, sort_keys=True), dedup_key),
        )
    except sqlite3.IntegrityError:
        # The unique index closes the race between concurrent worker scans.
        if not dedup_key:
            raise
        existing = conn.execute(
            "SELECT id FROM notifications WHERE org_id = ? AND dedup_key = ?",
            (org_id, dedup_key),
        ).fetchone()
        if not existing:
            raise
        return int(existing["id"])
    notification_id = int(cursor.lastrowid)
    audit("notification_queued", notification_id=notification_id, event_type=event_type, severity=severity)
    return notification_id


def notify_case_event(
    conn,
    *,
    event_type: str,
    severity: str,
    message: str,
    org_id: int,
    metadata: dict[str, Any] | None = None,
    dedup_key: str | None = None,
) -> None:
    channels = ["console"]
    if os.environ.get("AI_SOC_SLACK_WEBHOOK_URL"):
        channels.append("slack")
    if os.environ.get("AI_SOC_SMTP_HOST") and os.environ.get("AI_SOC_NOTIFY_EMAIL_TO"):
        channels.append("email")
    for channel in channels:
        enqueue_notification(
            conn,
            event_type=event_type,
            severity=severity,
            channel=channel,
            message=message,
            metadata=metadata,
            org_id=org_id,
            dedup_key=f"{dedup_key}:{channel}" if dedup_key else None,
        )


def dispatch_pending(conn, limit: int = 20, org_id: int | None = None) -> list[dict[str, Any]]:
    where = "status IN ('pending', 'retrying', 'sending') AND (next_attempt_at IS NULL OR next_attempt_at <= CURRENT_TIMESTAMP)"
    params: list[Any] = []
    if org_id is not None:
        where += " AND org_id = ?"
        params.append(org_id)
    rows = conn.execute(
        f"SELECT * FROM notifications WHERE {where} ORDER BY created_at LIMIT ?",
        (*params, limit),
    ).fetchall()
    results = []
    for row in rows:
        claimed = conn.execute(
            """
            UPDATE notifications
            SET status = 'sending', next_attempt_at = datetime('now', '+5 minutes')
            WHERE id = ? AND org_id = ?
              AND status IN ('pending', 'retrying', 'sending')
              AND (next_attempt_at IS NULL OR next_attempt_at <= CURRENT_TIMESTAMP)
            """,
            (row["id"], row["org_id"]),
        ).rowcount
        conn.commit()
        if not claimed:
            continue
        try:
            _dispatch(dict(row))
            status = "sent"
            error = None
            next_attempt = None
            dead_lettered = None
        except Exception as exc:
            error = str(exc)[:300]
            attempts = int(row["attempt_count"] or 0) + 1
            if attempts >= int(row["max_attempts"] or 5):
                status = "dead_letter"
                next_attempt = None
                dead_lettered = datetime.now(timezone.utc).isoformat()
            else:
                status = "retrying"
                # Exponential backoff is bounded so a recovered provider is
                # retried promptly without creating a tight failure loop.
                delay_minutes = min(2 ** (attempts - 1), 60)
                next_attempt = f"+{delay_minutes} minutes"
                dead_lettered = None
        conn.execute(
            """
            UPDATE notifications
            SET status = ?, attempt_count = attempt_count + 1,
                sent_at = CASE WHEN ? = 'sent' THEN CURRENT_TIMESTAMP ELSE sent_at END,
                next_attempt_at = CASE WHEN ? IS NULL THEN NULL ELSE datetime('now', ?) END,
                last_error = ?, dead_lettered_at = ?
            WHERE id = ? AND org_id = ?
            """,
            (status, status, next_attempt, next_attempt, error, dead_lettered, row["id"], row["org_id"]),
        )
        results.append({"id": row["id"], "status": status, "error": error})
    conn.commit()
    return results


def _dispatch(row: dict[str, Any]) -> None:
    if row["channel"] == "console":
        print(f"[AI_SOC_NOTIFICATION] {row['severity']} {row['event_type']}: {row['message']}")
        return
    if row["channel"] == "slack":
        webhook = os.environ.get("AI_SOC_SLACK_WEBHOOK_URL", "")
        if not webhook.startswith("https://"):
            raise RuntimeError("Slack webhook is not configured")
        body = json.dumps({"text": f"*{row['severity']}* {row['event_type']}: {row['message']}"}).encode("utf-8")
        req = urllib.request.Request(webhook, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10):
            pass
        return
    if row["channel"] == "email":
        host = os.environ.get("AI_SOC_SMTP_HOST", "")
        sender = os.environ.get("AI_SOC_NOTIFY_EMAIL_FROM", "ai-soc-operator@localhost")
        recipient = os.environ.get("AI_SOC_NOTIFY_EMAIL_TO", "")
        if not host or not recipient:
            raise RuntimeError("SMTP host or recipient is not configured")
        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = recipient
        msg["Subject"] = f"AI SOC Operator: {row['event_type']}"
        msg.set_content(row["message"])
        with smtplib.SMTP(host, int(os.environ.get("AI_SOC_SMTP_PORT", "587")), timeout=10) as smtp:
            if os.environ.get("AI_SOC_SMTP_STARTTLS", "1").lower() in {"1", "true", "yes"}:
                smtp.starttls()
            username = os.environ.get("AI_SOC_SMTP_USERNAME", "")
            password = os.environ.get("AI_SOC_SMTP_PASSWORD", "")
            if username and password:
                smtp.login(username, password)
            smtp.send_message(msg)
        return
    raise RuntimeError(f"Unsupported notification channel: {row['channel']}")
