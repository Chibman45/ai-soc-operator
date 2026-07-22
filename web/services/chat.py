"""Chat service — routes, tool executor, context retrieval.

Uses raw sqlite3 (matching existing app.py pattern) instead of SQLAlchemy.
Schema tables: chat_threads, chat_messages, chat_actions, chat_approvals, tool_executions.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]

# ── Schema (run once) ──

CHAT_SCHEMA = """
CREATE TABLE IF NOT EXISTS chat_threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    title TEXT DEFAULT 'SOC Copilot',
    created_by INTEGER,
    closed INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER NOT NULL,
    sender_type TEXT NOT NULL,
    sender_id INTEGER,
    content TEXT NOT NULL,
    citations_json TEXT DEFAULT '[]',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (thread_id) REFERENCES chat_threads(id)
);

CREATE TABLE IF NOT EXISTS chat_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER NOT NULL,
    case_id INTEGER NOT NULL,
    action_type TEXT NOT NULL,
    label TEXT NOT NULL,
    description TEXT NOT NULL,
    tool_name TEXT,
    tool_args_json TEXT DEFAULT '{}',
    requires_approval INTEGER DEFAULT 1,
    status TEXT DEFAULT 'proposed',
    result_json TEXT,
    requested_by INTEGER,
    approved_by INTEGER,
    approved_at TIMESTAMP,
    executed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (thread_id) REFERENCES chat_threads(id)
);

CREATE TABLE IF NOT EXISTS tool_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id INTEGER NOT NULL,
    tool_name TEXT NOT NULL,
    command_preview TEXT NOT NULL,
    argv_json TEXT NOT NULL,
    cwd TEXT,
    status TEXT DEFAULT 'pending',
    exit_code INTEGER,
    stdout TEXT,
    stderr TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    FOREIGN KEY (action_id) REFERENCES chat_actions(id)
);
"""


def init_chat_db(conn) -> None:
    conn.executescript(CHAT_SCHEMA)


# ── Tool Allowlist ──

ALLOWED_TOOLS = {
    # Tier 0 — passive, no approval
    "whois": {"tier": 0, "approval": False},
    "dig": {"tier": 0, "approval": False},
    "nslookup": {"tier": 0, "approval": False},
    "host": {"tier": 0, "approval": False},
    "ip": {"tier": 0, "approval": False},
    "curl": {"tier": 0, "approval": False},
    "grep": {"tier": 0, "approval": False},
    "rg": {"tier": 0, "approval": False},
    "awk": {"tier": 0, "approval": False},
    "sed": {"tier": 0, "approval": False},
    "jq": {"tier": 0, "approval": False},
    "ps": {"tier": 0, "approval": False},
    "ss": {"tier": 0, "approval": False},
    "lsof": {"tier": 0, "approval": False},
    "cat": {"tier": 0, "approval": False},
    "head": {"tier": 0, "approval": False},
    "tail": {"tier": 0, "approval": False},
    "strings": {"tier": 0, "approval": False},
    "file": {"tier": 0, "approval": False},
    "sha256sum": {"tier": 0, "approval": False},
    "md5sum": {"tier": 0, "approval": False},
    "sqlite3": {"tier": 0, "approval": False},
    # Tier 1 — local analysis
    "nmap": {"tier": 1, "approval": True},
    "whatweb": {"tier": 1, "approval": True},
    "yara": {"tier": 1, "approval": True},
    "exiftool": {"tier": 1, "approval": True},
    "binwalk": {"tier": 1, "approval": True},
    # Tier 2 — active discovery, approval required
    "tshark": {"tier": 2, "approval": True},
    "tcpdump": {"tier": 2, "approval": True},
}

# Commands that are always blocked regardless of allowlist
BLOCKED_ARGUMENTS = [
    "rm -rf",
    "rm -r /",
    "dd if=",
    "mkfs",
    "shred",
    "wget",
    "bash -c",
    "sh -c",
    "python -c",
    "python3 -c",
    "nc -l",
    "ncat -l",
]


def validate_command(tool_name: str, args: list[str]) -> tuple[bool, str]:
    """Validate a command against the allowlist. Returns (allowed, reason)."""
    if tool_name not in ALLOWED_TOOLS:
        return False, f"Tool '{tool_name}' is not in the allowlist"

    full_command = f"{tool_name} {' '.join(args)}".lower()

    for blocked in BLOCKED_ARGUMENTS:
        if blocked.lower() in full_command:
            return False, f"Blocked argument pattern: {blocked}"

    if any(arg.startswith("-") and "script" in arg.lower() for arg in args):
        return False, "Script-like arguments are not allowed"

    return True, "ok"


def execute_tool(
    tool_name: str,
    args: list[str],
    timeout: int = 30,
    cwd: str | None = None,
) -> dict[str, Any]:
    """Execute an allowlisted tool and return the result.

    Returns: {exit_code, stdout, stderr, status, command_preview}
    """
    allowed, reason = validate_command(tool_name, args)
    if not allowed:
        return {"exit_code": -1, "stdout": "", "stderr": reason, "status": "rejected", "command_preview": f"{tool_name} {' '.join(args)}"}

    argv = [tool_name] + args
    command_preview = subprocess.list2cmdline(argv)

    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        return {
            "exit_code": result.returncode,
            "stdout": result.stdout[:50000],  # Cap output
            "stderr": result.stderr[:10000],
            "status": "done" if result.returncode == 0 else "failed",
            "command_preview": command_preview,
        }
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout": "", "stderr": f"Timed out after {timeout}s", "status": "timeout", "command_preview": command_preview}
    except FileNotFoundError:
        return {"exit_code": -1, "stdout": "", "stderr": f"Tool not installed: {tool_name}", "status": "not_installed", "command_preview": command_preview}
    except Exception as e:
        return {"exit_code": -1, "stdout": "", "stderr": str(e)[:500], "status": "error", "command_preview": command_preview}


# ── Context Builder ──

def build_chat_context(conn, case_id: int, user_message: str) -> dict[str, Any]:
    """Build context for the LLM from case data and playbook."""
    case = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if not case:
        return {"error": "Case not found"}

    # Get recent activity
    activity = conn.execute(
        "SELECT * FROM activity_log WHERE run_id IN (SELECT run_id FROM cases WHERE id = ?) ORDER BY timestamp DESC LIMIT 20",
        (case_id,),
    ).fetchall()

    # Get observables from the case
    iocs = []
    if case["summary"]:
        # Extract IPs from summary
        import re
        ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", case["summary"])
        iocs.extend([{"type": "ip", "value": ip} for ip in ips])

    return {
        "case": {
            "id": case["id"],
            "title": case["title"],
            "severity": case["severity"],
            "status": case["status"],
            "summary": case["summary"] or "",
        },
        "activity": [
            {"step": row["step"], "status": row["status"], "detail": row["detail"]}
            for row in activity
        ],
        "observables": iocs,
        "allowed_tools": list(ALLOWED_TOOLS.keys()),
    }


# ── LLM Chat ──

SOC_SYSTEM_PROMPT = """You are an AI SOC analyst assistant. You help analysts investigate security incidents.

You can:
- Analyze alerts and explain what happened
- Suggest investigation steps
- Recommend tool commands (whois, dig, nmap, etc.) for the analyst to run
- Enrich IOCs through threat intelligence platforms
- Update TheHive cases with findings

Rules:
- Always ground your analysis in the case context and activity log
- When suggesting a tool command, include the tool_name and args as a suggested action
- For risky tools (nmap, tshark, tcpdump), mark requires_approval: true
- Be concise and factual — no speculation without evidence
- Structure your response as JSON with: answer, citations, suggested_actions

Response format:
{
  "answer": "Your analysis text",
  "citations": [{"type": "case", "ref": "case_id", "label": "..."}],
  "suggested_actions": [
    {
      "action_type": "tool_execution",
      "label": "DNS lookup on suspicious domain",
      "description": "Use dig to resolve the domain",
      "tool_name": "dig",
      "tool_args": {"args": ["example.com", "ANY"], "timeout_seconds": 15},
      "requires_approval": false
    }
  ]
}"""


def chat_completion(context: dict[str, Any], history: list[dict], user_message: str) -> dict[str, Any]:
    """Call GPT-5.6 for chat response."""
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    if not openai_key:
        return {
            "answer": "I need an OpenAI API key configured to analyze this case. Please set OPENAI_API_KEY.",
            "citations": [],
            "suggested_actions": [],
        }

    try:
        import urllib.request
        import ssl

        messages = [{"role": "system", "content": SOC_SYSTEM_PROMPT}]

        # Add context
        context_str = json.dumps(context, indent=2)
        messages.append({
            "role": "user",
            "content": f"Case context:\n{context_str}\n\n"
        })

        # Add history
        for msg in history[-10:]:
            role = "assistant" if msg["sender_type"] == "assistant" else "user"
            messages.append({"role": role, "content": msg["content"]})

        messages.append({"role": "user", "content": user_message})

        body = json.dumps({
            "model": "gpt-5.6",
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": 2048,
        }).encode("utf-8")

        request = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {openai_key}",
            },
            method="POST",
        )

        ctx = ssl.create_default_context()
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

        with opener.open(request, timeout=60) as response:
            result = json.loads(response.read().decode("utf-8"))

        content = result["choices"][0]["message"]["content"]

        # Try to parse as JSON
        if content.startswith("```"):
            import re
            content = re.sub(r"^```(?:json)?\s*\n?", "", content)
            content = re.sub(r"\n?```\s*$", "", content)

        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {
                "answer": content,
                "citations": [],
                "suggested_actions": [],
            }

    except Exception as e:
        return {
            "answer": f"Error calling LLM: {str(e)[:200]}",
            "citations": [],
            "suggested_actions": [],
        }
