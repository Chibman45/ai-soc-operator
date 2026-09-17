"""Chat routes — case-scoped SOC copilot with tool execution."""

from __future__ import annotations

import json
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse
from flask import Blueprint, jsonify, request, session
from web.security import claim_case_for_mutation, current_org_id, permission_required
from web.services.database import connect_database

ROOT = Path(__file__).resolve().parents[2]

chat_bp = Blueprint("chat", __name__, url_prefix="/api/chat")


def _get_db():
    db_path = ROOT / "data" / "soc_operator.db"
    return connect_database(db_path)


def _init_chat(conn):
    from web.services.chat import init_chat_db
    init_chat_db(conn)


_login_required = permission_required("chat.read")


def _case_in_org(conn, case_id: int, org_id: int) -> bool:
    return case_id == 0 or conn.execute(
        "SELECT 1 FROM cases WHERE id = ? AND org_id = ?", (case_id, org_id)
    ).fetchone() is not None


def _action_requires_approval(action: dict) -> bool:
    """Derive approval policy server-side; clients and model output are untrusted."""
    if action.get("action_type", "tool_execution") == "tool_execution":
        from web.services.chat import ALLOWED_TOOLS

        tool = ALLOWED_TOOLS.get(action.get("tool_name"))
        return True if tool is None else bool(tool["approval"])
    return bool(action.get("requires_approval", True))


_NETWORK_TOOLS = {"whois", "dig", "nslookup", "host", "curl", "nmap", "whatweb"}
_FILE_TOOLS = {"grep", "rg", "awk", "sed", "jq", "cat", "head", "tail", "strings", "file", "sha256sum", "md5sum", "sqlite3", "yara", "exiftool", "binwalk"}
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)


def _tool_scope_target(
    conn,
    case_id: int,
    org_id: int,
    tool_name: str,
    args: list[str],
    user_id: int | None = None,
) -> str:
    """Return an audited target label after enforcing case and filesystem scope."""
    if tool_name in _NETWORK_TOOLS:
        if case_id == GLOBAL_CASE_ID:
            rows = conn.execute("SELECT DISTINCT value FROM observables WHERE org_id = ?", (org_id,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT DISTINCT value FROM observables WHERE org_id = ? AND case_id = ?",
                (org_id, case_id),
            ).fetchall()
        allowed = {str(row["value"]).strip().lower() for row in rows}
        targets: list[str] = []
        for raw in args:
            value = str(raw).strip()
            if not value or value.startswith("-"):
                continue
            parsed = urlparse(value if "://" in value else f"//{value}")
            candidate = (parsed.hostname or value).strip("[]").lower()
            base_candidate = candidate.split("/", 1)[0]
            try:
                ipaddress.ip_network(candidate, strict=False)
                targets.append(candidate)
            except ValueError:
                if _DOMAIN_RE.fullmatch(base_candidate):
                    targets.append(base_candidate)
        if not targets or any(target not in allowed for target in targets):
            raise PermissionError("tool target is not an observable in the authorized case scope")
        if user_id is not None:
            from web.services.organization_policy import policy_allows_target

            if any(
                not policy_allows_target(conn, org_id=org_id, user_id=user_id, target=target)
                for target in targets
            ):
                raise PermissionError("tool target is outside your approved organization policy scope")
        return ",".join(sorted(set(targets)))

    if tool_name in _FILE_TOOLS:
        allowed_roots = [(ROOT / name).resolve() for name in ("evidence", "reports", "outputs", "scans")]
        paths = []
        for raw in args:
            value = str(raw).strip()
            if not value or value.startswith("-") or value in {".", ".."}:
                continue
            candidate = Path(value)
            if not candidate.is_absolute() and not any(separator in value for separator in ("/", "\\")):
                continue
            resolved = (candidate if candidate.is_absolute() else ROOT / candidate).resolve()
            if not any(resolved == root or resolved.is_relative_to(root) for root in allowed_roots):
                raise PermissionError("tool file path is outside approved evidence and report roots")
            paths.append(str(resolved))
        return ",".join(paths) or "local-approved-data"

    return "local-host"


def _execute_audited_tool(executor, tool_name: str, args: list[str], timeout: int, target: str) -> dict:
    from scripts.common import Session, safe_name

    operation = Session(mode="chat-tool", target=target, purpose=f"Approved {tool_name} investigation")
    try:
        result = executor(tool_name, args, timeout=timeout)
        artifact = operation.path("evidence") / f"{safe_name(tool_name)}-result.json"
        artifact.write_text(json.dumps(result, indent=2), encoding="utf-8")
        operation.note("Tool Result", {"Tool": tool_name, "Status": result.get("status"), "Artifact": str(artifact)})
        return {**result, "session_id": operation.session_id}
    finally:
        operation.finish()


@chat_bp.post("/<int:case_id>")
@permission_required("chat.act")
def chat_post(case_id: int):
    from web.services.chat import build_chat_context, chat_completion

    payload = request.get_json(force=True)
    user_message = (payload.get("message") or "").strip()
    if not user_message:
        return jsonify({"ok": False, "error": "message is required"}), 400

    conn = _get_db()
    _init_chat(conn)
    org_id = int(current_org_id(conn))
    if not _case_in_org(conn, case_id, org_id):
        conn.close()
        return jsonify({"error": "not found"}), 404

    # Get or create thread
    thread = conn.execute(
        "SELECT * FROM chat_threads WHERE case_id = ? AND org_id = ? AND closed = 0 ORDER BY updated_at DESC LIMIT 1",
        (case_id, org_id),
    ).fetchone()
    if not thread:
        cursor = conn.execute(
            "INSERT INTO chat_threads (case_id, title, created_by, org_id) VALUES (?, 'SOC Copilot', ?, ?)",
            (case_id, session["user_id"], org_id),
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

    from web.services.ai_provider import load_ai_client

    response = chat_completion(
        context,
        history,
        user_message,
        ai_client=load_ai_client(conn, int(org_id)),
    )

    # Save assistant message
    answer = response.get("answer", "")
    citations = json.dumps(response.get("citations", []))
    reasoning = json.dumps(response.get("reasoning", []))
    conn.execute(
        "INSERT INTO chat_messages (thread_id, sender_type, content, citations_json, reasoning_json) VALUES (?, 'assistant', ?, ?, ?)",
        (thread["id"], answer, citations, reasoning),
    )

    # Save suggested actions
    suggested = response.get("suggested_actions", [])
    for action in suggested:
        requires_approval = _action_requires_approval(action)
        action["requires_approval"] = requires_approval
        conn.execute(
            "INSERT INTO chat_actions (thread_id, case_id, action_type, label, description, tool_name, tool_args_json, requires_approval, status, requested_by, org_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'proposed', ?, ?)",
            (
                thread["id"], case_id,
                action.get("action_type", "tool_execution"),
                action.get("label", ""),
                action.get("description", ""),
                action.get("tool_name"),
                json.dumps(action.get("tool_args", {})),
                1 if requires_approval else 0,
                session["user_id"],
                org_id,
            ),
        )

    conn.execute("UPDATE chat_threads SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", (thread["id"],))
    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "thread_id": thread["id"],
        "answer": answer,
        "reasoning": response.get("reasoning", []),
        "citations": response.get("citations", []),
        "suggested_actions": suggested,
        "approval_required": any(a.get("requires_approval") for a in suggested),
    })


@chat_bp.get("/<int:case_id>/history")
@_login_required
def chat_history(case_id: int):
    conn = _get_db()
    _init_chat(conn)
    org_id = int(current_org_id(conn))
    if not _case_in_org(conn, case_id, org_id):
        conn.close()
        return jsonify({"error": "not found"}), 404

    thread = conn.execute(
        "SELECT * FROM chat_threads WHERE case_id = ? AND org_id = ? ORDER BY updated_at DESC LIMIT 1",
        (case_id, org_id),
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
             "citations": json.loads(m["citations_json"] or "[]"),
             "reasoning": json.loads((m["reasoning_json"] if "reasoning_json" in m.keys() else "[]") or "[]"),
             "created_at": m["created_at"]}
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
@permission_required("responder.approve")
def chat_action_approve(case_id: int, action_id: int):
    from web.services.chat import execute_tool, execute_enrichment

    conn = _get_db()
    _init_chat(conn)
    org_id = int(current_org_id(conn))

    action = conn.execute(
        "SELECT * FROM chat_actions WHERE id = ? AND case_id = ? AND org_id = ?", (action_id, case_id, org_id)
    ).fetchone()
    if not action:
        conn.close()
        return jsonify({"error": "not found"}), 404

    if action["requires_approval"] and action["requested_by"] == session["user_id"]:
        conn.close()
        return jsonify({"error": "requester cannot approve their own action"}), 403

    tool_args = json.loads(action["tool_args_json"] or "{}")
    scoped_target = None
    if action["action_type"] == "tool_execution" and action["tool_name"]:
        try:
            scoped_target = _tool_scope_target(
                conn,
                case_id,
                org_id,
                action["tool_name"],
                tool_args.get("args", []),
                int(session["user_id"]),
            )
        except PermissionError as exc:
            conn.close()
            return jsonify({"error": str(exc)}), 403

    # The status predicate is the replay guard: only one request can claim and
    # execute a proposed action, including under concurrent approvals.
    claimed = conn.execute(
        """
        UPDATE chat_actions
        SET status = 'approved', approved_by = ?, approved_at = CURRENT_TIMESTAMP
        WHERE id = ? AND org_id = ? AND status = 'proposed'
        """,
        (session["user_id"], action_id, org_id),
    ).rowcount
    if not claimed:
        conn.close()
        return jsonify({"error": "action is no longer awaiting approval"}), 409
    conn.commit()

    # Execute tool if applicable
    result = None
    final_status = "approved"
    if action["action_type"] == "tool_execution" and action["tool_name"]:
        args = tool_args.get("args", [])
        timeout = tool_args.get("timeout_seconds", 30)
        result = _execute_audited_tool(execute_tool, action["tool_name"], args, timeout, scoped_target or "local-host")
        final_status = result["status"]

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
    elif action["action_type"] == "enrichment":
        tool_args = json.loads(action["tool_args_json"] or "{}")
        ioc_type = (tool_args.get("ioc_type") or tool_args.get("type") or "").lower()
        value = tool_args.get("value") or tool_args.get("ioc") or ""
        result = execute_enrichment(ioc_type, value)
        final_status = result["status"]
        conn.execute(
            "UPDATE chat_actions SET status = ?, result_json = ?, executed_at = CURRENT_TIMESTAMP WHERE id = ?",
            (result["status"], json.dumps(result), action_id),
        )
        conn.commit()

    conn.close()
    return jsonify({"ok": True, "status": final_status, "result": result})


@chat_bp.post("/<int:case_id>/action/<int:action_id>/reject")
@permission_required("responder.approve")
def chat_action_reject(case_id: int, action_id: int):
    reason = request.json.get("reason", "") if request.is_json else ""
    conn = _get_db()
    _init_chat(conn)
    org_id = int(current_org_id(conn))

    rejected = conn.execute(
        "UPDATE chat_actions SET status = 'rejected', approved_by = ?, approved_at = CURRENT_TIMESTAMP, result_json = ? WHERE id = ? AND case_id = ? AND org_id = ? AND status = 'proposed'",
        (session["user_id"], json.dumps({"reason": reason}), action_id, case_id, org_id),
    ).rowcount
    if not rejected:
        conn.close()
        return jsonify({"error": "action is no longer awaiting approval"}), 409
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "status": "rejected"})


@chat_bp.post("/<int:case_id>/execute")
@permission_required("tool.execute")
def chat_execute_direct(case_id: int):
    from web.services.chat import validate_command, execute_tool

    payload = request.get_json(force=True)
    tool_name = payload.get("tool_name", "")
    args = payload.get("args", [])
    timeout = payload.get("timeout_seconds", 30)

    conn = _get_db()
    _init_chat(conn)
    org_id = int(current_org_id(conn))
    if not _case_in_org(conn, case_id, org_id):
        conn.close()
        return jsonify({"error": "not found"}), 404
    if case_id != GLOBAL_CASE_ID and not claim_case_for_mutation(
        conn, case_id, int(session["user_id"]), org_id
    ):
        conn.close()
        return jsonify({"error": "case is assigned to another analyst"}), 409

    try:
        scoped_target = _tool_scope_target(conn, case_id, org_id, tool_name, args, int(session["user_id"]))
    except PermissionError as exc:
        conn.close()
        return jsonify({"ok": False, "error": str(exc)}), 403
    # Persist an automatic claim before the tool runs outside this transaction.
    conn.commit()
    conn.close()

    allowed, reason = validate_command(tool_name, args)
    if not allowed:
        return jsonify({"ok": False, "error": reason}), 400
    from web.services.chat import ALLOWED_TOOLS
    if ALLOWED_TOOLS[tool_name]["approval"]:
        return jsonify({"ok": False, "error": "This tool requires a proposed action and independent approval"}), 409

    result = _execute_audited_tool(execute_tool, tool_name, args, timeout, scoped_target)

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


@chat_bp.post("/<int:case_id>/action")
@permission_required("chat.act")
def chat_action_create(case_id: int):
    """Create a proposed action from the chat UI (previously missing route).

    The chat panel's suggested-action buttons POST here to persist the action
    before approving it. Returns the created action row so the client can call
    the approve endpoint with a real action id.
    """
    payload = request.get_json(force=True) or {}
    conn = _get_db()
    _init_chat(conn)
    org_id = int(current_org_id(conn))
    if not _case_in_org(conn, case_id, org_id):
        conn.close()
        return jsonify({"error": "not found"}), 404

    thread = conn.execute(
        "SELECT * FROM chat_threads WHERE case_id = ? AND org_id = ? AND closed = 0 ORDER BY updated_at DESC LIMIT 1",
        (case_id, org_id),
    ).fetchone()
    if not thread:
        cursor = conn.execute(
            "INSERT INTO chat_threads (case_id, title, created_by, org_id) VALUES (?, 'SOC Copilot', ?, ?)",
            (case_id, session["user_id"], org_id),
        )
        conn.commit()
        thread = conn.execute("SELECT * FROM chat_threads WHERE id = ?", (cursor.lastrowid,)).fetchone()

    cursor = conn.execute(
        "INSERT INTO chat_actions (thread_id, case_id, action_type, label, description, tool_name, tool_args_json, requires_approval, status, requested_by, org_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'proposed', ?, ?)",
        (
            thread["id"], case_id,
            payload.get("action_type", "tool_execution"),
            payload.get("label", ""),
            payload.get("description", ""),
            payload.get("tool_name"),
            json.dumps(payload.get("tool_args", {})),
            1 if _action_requires_approval(payload) else 0,
            session["user_id"],
            org_id,
        ),
    )
    conn.commit()
    action_id = cursor.lastrowid
    conn.close()
    return jsonify({"ok": True, "action": {"id": action_id, "status": "proposed"}})


# ═══════════════════════════════════════════
# Global (dashboard-wide) copilot
# ═══════════════════════════════════════════
# Uses case_id = 0 as a sentinel for the SOC-wide thread, so it reuses the
# same chat_threads/chat_messages/chat_actions machinery as case chat.

GLOBAL_CASE_ID = 0


@chat_bp.post("/global")
@permission_required("chat.act")
def chat_global_post():
    from web.services.chat import build_global_context, chat_completion

    payload = request.get_json(force=True)
    user_message = (payload.get("message") or "").strip()
    if not user_message:
        return jsonify({"ok": False, "error": "message is required"}), 400

    conn = _get_db()
    _init_chat(conn)
    org_id = int(current_org_id(conn))

    thread = conn.execute(
        "SELECT * FROM chat_threads WHERE case_id = ? AND org_id = ? AND closed = 0 ORDER BY updated_at DESC LIMIT 1",
        (GLOBAL_CASE_ID, org_id),
    ).fetchone()
    if not thread:
        cursor = conn.execute(
            "INSERT INTO chat_threads (case_id, title, created_by, org_id) VALUES (?, 'Dashboard Copilot', ?, ?)",
            (GLOBAL_CASE_ID, session["user_id"], org_id),
        )
        conn.commit()
        thread = conn.execute("SELECT * FROM chat_threads WHERE id = ?", (cursor.lastrowid,)).fetchone()

    conn.execute(
        "INSERT INTO chat_messages (thread_id, sender_type, sender_id, content) VALUES (?, 'user', ?, ?)",
        (thread["id"], session["user_id"], user_message),
    )
    conn.commit()

    context = build_global_context(conn, user_message, org_id=org_id)
    history_rows = conn.execute(
        "SELECT * FROM chat_messages WHERE thread_id = ? ORDER BY created_at ASC",
        (thread["id"],),
    ).fetchall()
    history = [{"sender_type": r["sender_type"], "content": r["content"]} for r in history_rows]

    from web.services.ai_provider import load_ai_client

    response = chat_completion(
        context,
        history,
        user_message,
        global_mode=True,
        ai_client=load_ai_client(conn, int(org_id)),
    )

    answer = response.get("answer", "")
    citations = json.dumps(response.get("citations", []))
    reasoning = json.dumps(response.get("reasoning", []))
    conn.execute(
        "INSERT INTO chat_messages (thread_id, sender_type, content, citations_json, reasoning_json) VALUES (?, 'assistant', ?, ?, ?)",
        (thread["id"], answer, citations, reasoning),
    )

    suggested = response.get("suggested_actions", [])
    for action in suggested:
        requires_approval = _action_requires_approval(action)
        action["requires_approval"] = requires_approval
        conn.execute(
            "INSERT INTO chat_actions (thread_id, case_id, action_type, label, description, tool_name, tool_args_json, requires_approval, status, requested_by, org_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'proposed', ?, ?)",
            (
                thread["id"], GLOBAL_CASE_ID,
                action.get("action_type", "tool_execution"),
                action.get("label", ""),
                action.get("description", ""),
                action.get("tool_name"),
                json.dumps(action.get("tool_args", {})),
                1 if requires_approval else 0,
                session["user_id"],
                org_id,
            ),
        )

    conn.execute("UPDATE chat_threads SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", (thread["id"],))
    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "thread_id": thread["id"],
        "answer": answer,
        "reasoning": response.get("reasoning", []),
        "citations": response.get("citations", []),
        "suggested_actions": suggested,
        "approval_required": any(a.get("requires_approval") for a in suggested),
    })


@chat_bp.get("/global/history")
@_login_required
def chat_global_history():
    conn = _get_db()
    _init_chat(conn)
    org_id = int(current_org_id(conn))

    thread = conn.execute(
        "SELECT * FROM chat_threads WHERE case_id = ? AND org_id = ? ORDER BY updated_at DESC LIMIT 1",
        (GLOBAL_CASE_ID, org_id),
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
             "citations": json.loads(m["citations_json"] or "[]"),
             "reasoning": json.loads((m["reasoning_json"] if "reasoning_json" in m.keys() else "[]") or "[]"),
             "created_at": m["created_at"]}
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
