"""Chat routes — case-scoped SOC copilot with tool execution."""

from __future__ import annotations

import json
from pathlib import Path
from flask import Blueprint, jsonify, request, session

ROOT = Path(__file__).resolve().parents[2]

chat_bp = Blueprint("chat", __name__, url_prefix="/api/chat")


def _get_db():
    import sqlite3
    db_path = ROOT / "data" / "soc_operator.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def _init_chat(conn):
    from web.services.chat import init_chat_db
    init_chat_db(conn)


def _login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


@chat_bp.post("/<int:case_id>")
@_login_required
def chat_post(case_id: int):
    from web.services.chat import build_chat_context, chat_completion

    payload = request.get_json(force=True)
    user_message = (payload.get("message") or "").strip()
    if not user_message:
        return jsonify({"ok": False, "error": "message is required"}), 400

    conn = _get_db()
    _init_chat(conn)

    # Get or create thread
    thread = conn.execute(
        "SELECT * FROM chat_threads WHERE case_id = ? AND closed = 0 ORDER BY updated_at DESC LIMIT 1",
        (case_id,),
    ).fetchone()
    if not thread:
        cursor = conn.execute(
            "INSERT INTO chat_threads (case_id, title, created_by) VALUES (?, 'SOC Copilot', ?)",
            (case_id, session["user_id"]),
        )
        conn.commit()
        thread = conn.execute("SELECT * FROM chat_threads WHERE id = ?", (cursor.lastrowid,)).fetchone()

    # Save user message
    conn.execute(
        "INSERT INTO chat_messages (thread_id, sender_type, sender_id, content) VALUES (?, 'user', ?, ?)",
        (thread["id"], session["user_id"], user_message),
    )
    conn.commit()

    # Build context and get LLM response
    context = build_chat_context(conn, case_id, user_message)
    history_rows = conn.execute(
        "SELECT * FROM chat_messages WHERE thread_id = ? ORDER BY created_at ASC",
        (thread["id"],),
    ).fetchall()
    history = [{"sender_type": r["sender_type"], "content": r["content"]} for r in history_rows]

    response = chat_completion(context, history, user_message)

    # Save assistant message
    answer = response.get("answer", "")
    citations = json.dumps(response.get("citations", []))
    conn.execute(
        "INSERT INTO chat_messages (thread_id, sender_type, content, citations_json) VALUES (?, 'assistant', ?, ?)",
        (thread["id"], answer, citations),
    )

    # Save suggested actions
    suggested = response.get("suggested_actions", [])
    for action in suggested:
        conn.execute(
            "INSERT INTO chat_actions (thread_id, case_id, action_type, label, description, tool_name, tool_args_json, requires_approval, status, requested_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'proposed', ?)",
            (
                thread["id"], case_id,
                action.get("action_type", "tool_execution"),
                action.get("label", ""),
                action.get("description", ""),
                action.get("tool_name"),
                json.dumps(action.get("tool_args", {})),
                1 if action.get("requires_approval", True) else 0,
                session["user_id"],
            ),
        )

    conn.execute("UPDATE chat_threads SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", (thread["id"],))
    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "thread_id": thread["id"],
        "answer": answer,
        "citations": response.get("citations", []),
        "suggested_actions": suggested,
        "approval_required": any(a.get("requires_approval") for a in suggested),
    })


@chat_bp.get("/<int:case_id>/history")
@_login_required
def chat_history(case_id: int):
    conn = _get_db()
    _init_chat(conn)

    thread = conn.execute(
        "SELECT * FROM chat_threads WHERE case_id = ? ORDER BY updated_at DESC LIMIT 1",
        (case_id,),
    ).fetchone()

    if not thread:
        conn.close()
        return jsonify({"ok": True, "thread": None, "messages": [], "actions": []})

    messages = conn.execute(
        "SELECT * FROM chat_messages WHERE thread_id = ? ORDER BY created_at ASC",
        (thread["id"],),
    ).fetchall()

    actions = conn.execute(
        "SELECT * FROM chat_actions WHERE thread_id = ? ORDER BY created_at ASC",
        (thread["id"],),
    ).fetchall()

    conn.close()
    return jsonify({
        "ok": True,
        "thread": {"id": thread["id"], "case_id": thread["case_id"], "title": thread["title"]},
        "messages": [
            {"id": m["id"], "sender_type": m["sender_type"], "content": m["content"],
             "citations": json.loads(m["citations_json"] or "[]"), "created_at": m["created_at"]}
            for m in messages
        ],
        "actions": [
            {"id": a["id"], "action_type": a["action_type"], "label": a["label"],
             "description": a["description"], "tool_name": a["tool_name"],
             "requires_approval": bool(a["requires_approval"]), "status": a["status"],
             "result_json": a["result_json"], "created_at": a["created_at"]}
            for a in actions
        ],
    })


@chat_bp.post("/<int:case_id>/action/<int:action_id>/approve")
@_login_required
def chat_action_approve(case_id: int, action_id: int):
    from web.services.chat import execute_tool

    conn = _get_db()
    _init_chat(conn)

    action = conn.execute(
        "SELECT * FROM chat_actions WHERE id = ? AND case_id = ?", (action_id, case_id)
    ).fetchone()
    if not action:
        conn.close()
        return jsonify({"error": "not found"}), 404

    conn.execute(
        "UPDATE chat_actions SET status = 'approved', approved_by = ?, approved_at = CURRENT_TIMESTAMP WHERE id = ?",
        (session["user_id"], action_id),
    )
    conn.commit()

    # Execute tool if applicable
    result = None
    if action["action_type"] == "tool_execution" and action["tool_name"]:
        tool_args = json.loads(action["tool_args_json"] or "{}")
        args = tool_args.get("args", [])
        timeout = tool_args.get("timeout_seconds", 30)
        result = execute_tool(action["tool_name"], args, timeout=timeout)

        conn.execute(
            "INSERT INTO tool_executions (action_id, tool_name, command_preview, argv_json, status, exit_code, stdout, stderr, started_at, finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            (action_id, action["tool_name"], result["command_preview"],
             json.dumps([action["tool_name"]] + args),
             result["status"], result["exit_code"], result["stdout"], result["stderr"]),
        )
        conn.execute(
            "UPDATE chat_actions SET status = ?, result_json = ?, executed_at = CURRENT_TIMESTAMP WHERE id = ?",
            (result["status"], json.dumps(result), action_id),
        )
        conn.commit()

    conn.close()
    return jsonify({"ok": True, "status": action["status"], "result": result})


@chat_bp.post("/<int:case_id>/action/<int:action_id>/reject")
@_login_required
def chat_action_reject(case_id: int, action_id: int):
    reason = request.json.get("reason", "") if request.is_json else ""
    conn = _get_db()
    _init_chat(conn)

    conn.execute(
        "UPDATE chat_actions SET status = 'rejected', approved_by = ?, approved_at = CURRENT_TIMESTAMP, result_json = ? WHERE id = ? AND case_id = ?",
        (session["user_id"], json.dumps({"reason": reason}), action_id, case_id),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "status": "rejected"})


@chat_bp.post("/<int:case_id>/execute")
@_login_required
def chat_execute_direct(case_id: int):
    from web.services.chat import validate_command, execute_tool

    payload = request.get_json(force=True)
    tool_name = payload.get("tool_name", "")
    args = payload.get("args", [])
    timeout = payload.get("timeout_seconds", 30)

    allowed, reason = validate_command(tool_name, args)
    if not allowed:
        return jsonify({"ok": False, "error": reason}), 400

    result = execute_tool(tool_name, args, timeout=timeout)

    conn = _get_db()
    _init_chat(conn)
    conn.execute(
        "INSERT INTO tool_executions (action_id, tool_name, command_preview, argv_json, status, exit_code, stdout, stderr, started_at, finished_at) VALUES (0, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        (tool_name, result["command_preview"], json.dumps([tool_name] + args),
         result["status"], result["exit_code"], result["stdout"], result["stderr"]),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "result": result})
