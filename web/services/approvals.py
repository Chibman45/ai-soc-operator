"""Human-in-the-loop approval bridge for playbook execution.

When a playbook hits an ``approval`` step that needs sign-off, the ``PlaybookRunner``
blocks on a handler produced here. The handler posts the request into the dashboard
copilot thread (``case_id = 0``) as an assistant message plus a ``chat_actions`` row,
then polls until a human approves/rejects it in the UI (or it times out).

This reuses the exact same chat_actions machinery the copilot already renders, so a
pending playbook approval shows up as an Approve / Reject card in the floating copilot
on any page — "the AI uses the chat feature to get approval", as requested.
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable

from scripts.common import audit

GLOBAL_CASE_ID = 0
POLL_INTERVAL_SECONDS = 1.0
DEFAULT_TIMEOUT_SECONDS = 1800  # 30 minutes — long enough for a human to respond

# Statuses that mean "the human said yes" (approve endpoint may leave the row in
# any of these once the action resolves).
_APPROVED_STATES = {"approved", "done", "executed"}


def _get_global_thread(conn, created_by: int | None = None) -> int:
    """Return the id of the open dashboard-copilot thread, creating it if needed."""
    thread = conn.execute(
        "SELECT id FROM chat_threads WHERE case_id = ? AND closed = 0 "
        "ORDER BY updated_at DESC LIMIT 1",
        (GLOBAL_CASE_ID,),
    ).fetchone()
    if thread:
        return int(thread["id"])
    cursor = conn.execute(
        "INSERT INTO chat_threads (case_id, title, created_by) "
        "VALUES (?, 'Dashboard Copilot', ?)",
        (GLOBAL_CASE_ID, created_by),
    )
    conn.commit()
    return int(cursor.lastrowid)


def _describe_actions(actions: list[dict[str, Any]]) -> str:
    labels = []
    for a in actions or []:
        labels.append(
            a.get("label")
            or a.get("action")
            or a.get("tool")
            or a.get("type")
            or "action"
        )
    return ", ".join(labels) if labels else "the proposed action(s)"


def make_approval_handler(
    run_id: int,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> Callable[[dict[str, Any], list[dict[str, Any]], dict[str, Any]], dict[str, Any]]:
    """Build an ``approval_handler(step, actions, context)`` for ``PlaybookRunner``.

    The returned callable runs in the job-worker thread. It opens its own sqlite
    connection (sqlite connections are thread-bound), records the approval request
    where the copilot can render it, then blocks — polling for the human decision —
    and returns ``{"decision": "approved" | "rejected" | "timeout", ...}``.
    """

    def handler(
        step: dict[str, Any],
        actions: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        from web.app import get_db
        from web.services.chat import init_chat_db

        conn = get_db()
        try:
            init_chat_db(conn)
            thread_id = _get_global_thread(conn)

            step_id = step.get("id", "approval")
            prompt = (
                step.get("prompt")
                or step.get("description")
                or "The playbook requires your approval to continue."
            )
            action_desc = _describe_actions(actions)
            alert_title = ""
            try:
                alert_title = (context.get("alert") or {}).get("title", "") or (
                    context.get("rule") or {}
                ).get("name", "")
            except Exception:
                pass

            reasoning = [
                f"Playbook run #{run_id} reached approval gate '{step_id}'"
                + (f" for alert '{alert_title}'." if alert_title else "."),
                f"Proposed action(s): {action_desc}.",
                "Pausing execution — waiting for a human decision in the copilot.",
            ]
            message = (
                f"🔐 Approval needed for playbook run #{run_id}"
                + (f" ({alert_title})" if alert_title else "")
                + f":\n{prompt}\n\nProposed action(s): {action_desc}"
            )

            conn.execute(
                "INSERT INTO chat_messages (thread_id, sender_type, content, reasoning_json) "
                "VALUES (?, 'assistant', ?, ?)",
                (thread_id, message, json.dumps(reasoning)),
            )
            cursor = conn.execute(
                "INSERT INTO chat_actions "
                "(thread_id, case_id, action_type, label, description, tool_name, "
                " tool_args_json, requires_approval, status, requested_by) "
                "VALUES (?, ?, 'playbook_approval', ?, ?, NULL, ?, 1, 'proposed', NULL)",
                (
                    thread_id,
                    GLOBAL_CASE_ID,
                    f"Playbook approval: {step_id}",
                    f"{prompt} — {action_desc}",
                    json.dumps(
                        {"run_id": run_id, "step_id": step_id, "actions": actions}
                    ),
                ),
            )
            action_id = int(cursor.lastrowid)
            conn.execute(
                "UPDATE chat_threads SET updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (thread_id,),
            )
            conn.commit()

            audit(
                "playbook_approval_requested",
                run_id=run_id,
                step=step_id,
                action_id=action_id,
            )

            deadline = time.time() + timeout_seconds
            while time.time() < deadline:
                # End any implicit read transaction so the next SELECT sees rows
                # committed by the request thread that handled the Approve click.
                conn.rollback()
                row = conn.execute(
                    "SELECT status, approved_by, approved_at, result_json "
                    "FROM chat_actions WHERE id = ?",
                    (action_id,),
                ).fetchone()
                status = (row["status"] if row else "rejected") or "proposed"

                if status in _APPROVED_STATES:
                    audit(
                        "playbook_approval_granted",
                        run_id=run_id,
                        step=step_id,
                        action_id=action_id,
                    )
                    return {
                        "decision": "approved",
                        "decided_by": row["approved_by"],
                        "decided_at": row["approved_at"],
                        "action_id": action_id,
                    }
                if status in ("rejected", "failed"):
                    reason = ""
                    try:
                        reason = json.loads(row["result_json"] or "{}").get("reason", "")
                    except Exception:
                        pass
                    audit(
                        "playbook_approval_rejected",
                        run_id=run_id,
                        step=step_id,
                        action_id=action_id,
                    )
                    return {
                        "decision": "rejected",
                        "decided_by": row["approved_by"],
                        "decided_at": row["approved_at"],
                        "reason": reason,
                        "action_id": action_id,
                    }
                time.sleep(POLL_INTERVAL_SECONDS)

            # Timed out — mark the pending row so the stale card disappears.
            conn.execute(
                "UPDATE chat_actions SET status = 'timeout' "
                "WHERE id = ? AND status = 'proposed'",
                (action_id,),
            )
            conn.commit()
            audit(
                "playbook_approval_timeout",
                run_id=run_id,
                step=step_id,
                action_id=action_id,
            )
            return {"decision": "timeout", "action_id": action_id}
        finally:
            conn.close()

    return handler
