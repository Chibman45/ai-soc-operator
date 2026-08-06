"""Notification abstraction for SOC workflow events."""

from __future__ import annotations

import json
import os
import smtplib
import urllib.request
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
) -> int:
    cursor = conn.execute(
        """
        INSERT INTO notifications
            (org_id, event_type, severity, channel, status, message, metadata_json)
        VALUES (?, ?, ?, ?, 'pending', ?, ?)
        """,
        (org_id, event_type, severity, channel, message, json.dumps(metadata or {}, sort_keys=True)),
    )
    notification_id = int(cursor.lastrowid)
    audit("notification_queued", notification_id=notification_id, event_type=event_type, severity=severity)
    return notification_id


def notify_case_event(conn, *, event_type: str, severity: str, message: str, metadata: dict[str, Any] | None = None) -> None:
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
        )


def dispatch_pending(conn, limit: int = 20) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM notifications WHERE status = 'pending' ORDER BY created_at LIMIT ?",
        (limit,),
    ).fetchall()
    results = []
    for row in rows:
        try:
            _dispatch(dict(row))
            status = "sent"
            error = None
        except Exception as exc:
            status = "failed"
            error = str(exc)[:300]
        conn.execute(
            "UPDATE notifications SET status = ?, sent_at = CURRENT_TIMESTAMP WHERE id = ?",
            (status, row["id"]),
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
        if not webhook:
            raise RuntimeError("Slack webhook is not configured")
        body = json.dumps({"text": f"*{row['severity']}* {row['event_type']}: {row['message']}"}).encode("utf-8")
        req = urllib.request.Request(webhook, data=body, headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=10)
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
        with smtplib.SMTP(host, int(os.environ.get("AI_SOC_SMTP_PORT", "25")), timeout=10) as smtp:
            smtp.send_message(msg)
        return
    raise RuntimeError(f"Unsupported notification channel: {row['channel']}")
