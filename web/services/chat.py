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
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    org_id INTEGER
);

CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER NOT NULL,
    sender_type TEXT NOT NULL,
    sender_id INTEGER,
    content TEXT NOT NULL,
    citations_json TEXT DEFAULT '[]',
    reasoning_json TEXT DEFAULT '[]',
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
    org_id INTEGER,
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
    # Migration: add reasoning_json to chat_messages if missing (older DBs).
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(chat_messages)").fetchall()}
        if "reasoning_json" not in cols:
            conn.execute("ALTER TABLE chat_messages ADD COLUMN reasoning_json TEXT DEFAULT '[]'")
        for table in ("chat_threads", "chat_actions"):
            table_cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            if "org_id" not in table_cols:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN org_id INTEGER")
        default_org = conn.execute("SELECT id FROM organizations ORDER BY id LIMIT 1").fetchone()
        if default_org:
            conn.execute("UPDATE chat_threads SET org_id = ? WHERE org_id IS NULL", (default_org["id"],))
            conn.execute("UPDATE chat_actions SET org_id = ? WHERE org_id IS NULL", (default_org["id"],))
        conn.commit()
    except Exception:
        pass


# ── Tool Allowlist ──

ALLOWED_TOOLS = {
    # Tier 0 — passive, no approval
    "whois": {"tier": 0, "approval": False},
    "dig": {"tier": 0, "approval": False},
    "nslookup": {"tier": 0, "approval": False},
    "host": {"tier": 0, "approval": False},
    "ip": {"tier": 2, "approval": True},
    "curl": {"tier": 2, "approval": True},
    "grep": {"tier": 0, "approval": False},
    "rg": {"tier": 0, "approval": False},
    "awk": {"tier": 1, "approval": True},
    "sed": {"tier": 1, "approval": True},
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
    "sqlite3": {"tier": 1, "approval": True},
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
    "system(",
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
    if tool_name == "sed" and any(arg == "-i" or arg.startswith("-i") for arg in args):
        return False, "In-place file changes are not allowed"

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


def execute_enrichment(ioc_type: str, value: str) -> dict[str, Any]:
    """Execute enrichment lookup via EnrichmentClient (VT/AbuseIPDB/Shodan/urlscan/HybridAnalysis/MISP).

    Returns: {status, platforms, results} where results is {platform: data} for each.
    """
    try:
        from web.app import load_config_for_web
        from scripts.orchestrator import build_clients
        from web.security import current_org_id, get_security_db
        from web.services.credential_vault import open_secret

        conn = get_security_db()
        try:
            org_id = current_org_id(conn)
            credentials = {
                row["key_name"]: open_secret(row["key_value"])
                for row in conn.execute("SELECT key_name, key_value FROM credentials WHERE org_id = ?", (org_id,)).fetchall()
            }
        finally:
            conn.close()
        config = load_config_for_web(org_id)
        clients = build_clients(config, credentials=credentials)
        enrichment_client = clients.get("enrichment")
        if not enrichment_client:
            return {
                "status": "no_enrichment_configured",
                "platforms": [],
                "results": {},
                "error": "No enrichment platforms configured (VirusTotal/AbuseIPDB/Shodan/urlscan/HybridAnalysis/MISP).",
            }

        results = enrichment_client.enrich(ioc_type, value)
        platforms = list(results.keys())
        has_data = any(
            isinstance(v, dict) and "error" not in v for v in results.values()
        )
        return {
            "status": "done" if has_data else "no_data",
            "platforms": platforms,
            "results": results,
        }
    except Exception as e:
        return {
            "status": "error",
            "platforms": [],
            "results": {},
            "error": str(e)[:500],
        }


# ── Context Builder ──

def build_chat_context(conn, case_id: int, user_message: str) -> dict[str, Any]:
    """Build context for the LLM from case data, playbook, and observables."""
    case = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if not case:
        return {"error": "Case not found"}
    org_id = case["org_id"] if "org_id" in case.keys() else None

    # Get recent activity
    activity = conn.execute(
        "SELECT * FROM activity_log WHERE run_id IN (SELECT run_id FROM cases WHERE id = ?) ORDER BY timestamp DESC LIMIT 20",
        (case_id,),
    ).fetchall()

    # Get observables from the observables table (real data)
    observables = []
    try:
        if org_id is None:
            obs_rows = conn.execute("SELECT * FROM observables WHERE case_id = ? ORDER BY created_at DESC", (case_id,)).fetchall()
        else:
            obs_rows = conn.execute(
                "SELECT * FROM observables WHERE case_id = ? AND org_id = ? ORDER BY created_at DESC",
                (case_id, org_id),
            ).fetchall()
        observables = [{"type": r["type"], "value": r["value"], "source": r["source"]} for r in obs_rows]
    except Exception:
        pass  # Table may not exist yet

    # Get related cases sharing observables (IOC correlation)
    related_cases = []
    if observables:
        for obs in observables[:5]:
            try:
                if org_id is None:
                    related = conn.execute(
                        "SELECT DISTINCT c.id, c.title, c.severity FROM observables o JOIN cases c ON o.case_id = c.id WHERE o.value = ? AND o.case_id != ? LIMIT 3",
                        (obs["value"], case_id),
                    ).fetchall()
                else:
                    related = conn.execute(
                        "SELECT DISTINCT c.id, c.title, c.severity FROM observables o JOIN cases c ON o.case_id = c.id WHERE o.org_id = ? AND c.org_id = ? AND o.value = ? AND o.case_id != ? LIMIT 3",
                        (org_id, org_id, obs["value"], case_id),
                    ).fetchall()
                for r in related:
                    if r["id"] not in [rc["id"] for rc in related_cases]:
                        related_cases.append({"id": r["id"], "title": r["title"], "severity": r["severity"]})
            except Exception:
                pass

    # Get triage result from the run if available
    triage_result = None
    if case["run_id"]:
        try:
            run = conn.execute("SELECT result_json FROM runs WHERE id = ?", (case["run_id"],)).fetchone()
            if run and run["result_json"]:
                import json as _json
                run_data = _json.loads(run["result_json"])
                triage_result = run_data.get("triage_result")
        except Exception:
            pass

    # Get playbook results
    playbook_results = {}
    if case["run_id"]:
        try:
            run = conn.execute("SELECT result_json FROM runs WHERE id = ?", (case["run_id"],)).fetchone()
            if run and run["result_json"]:
                import json as _json
                run_data = _json.loads(run["result_json"])
                playbook_results = run_data.get("steps", {})
        except Exception:
            pass

    # Extract additional IOCs from summary
    iocs_from_summary = []
    if case["summary"]:
        import re
        ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", case["summary"])
        iocs_from_summary.extend([{"type": "ip", "value": ip} for ip in ips])
        domains = re.findall(r"\b([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b", case["summary"])
        iocs_from_summary.extend([{"type": "domain", "value": d[0]} for d in domains[:5]])

    return {
        "case": {
            "id": case["id"],
            "title": case["title"],
            "severity": case["severity"],
            "status": case["status"],
            "summary": case["summary"] or "",
        },
        "triage": triage_result,
        "activity": [
            {"step": row["step"], "status": row["status"], "detail": row["detail"]}
            for row in activity
        ],
        "observables": observables or iocs_from_summary,
        "related_cases": related_cases,
        "playbook_results": {k: v for k, v in list(playbook_results.items())[:5]},
        "allowed_tools": list(ALLOWED_TOOLS.keys()),
    }


# ── Global (dashboard) context builder ──

def build_global_context(conn, user_message: str = "", org_id: int | None = None) -> dict[str, Any]:
    """Build context spanning ALL alerts and cases for the dashboard copilot.

    Unlike build_chat_context (single case), this gives the AI a SOC-wide view:
    recent cases, the live alert queue, org-wide activity, and IOC hot-spots.
    """
    cases = conn.execute(
        "SELECT id, title, severity, status, summary, created_at FROM cases WHERE org_id = ? ORDER BY created_at DESC LIMIT 25",
        (org_id,),
    ).fetchall()

    # Alert queue (feature table may not exist on very old DBs)
    alerts = []
    try:
        alerts = conn.execute(
            "SELECT id, source, title, severity, status, case_id, created_at FROM alerts WHERE org_id = ? ORDER BY created_at DESC LIMIT 25",
            (org_id,),
        ).fetchall()
    except Exception:
        pass

    activity = conn.execute(
        "SELECT step, status, detail, timestamp FROM activity_log WHERE org_id = ? ORDER BY timestamp DESC LIMIT 30",
        (org_id,),
    ).fetchall()

    # IOCs seen across more than one case — correlation hot-spots
    hot_iocs = []
    try:
        hot_iocs = conn.execute(
            "SELECT value, type, COUNT(DISTINCT case_id) AS cases FROM observables "
            "WHERE org_id = ? AND case_id IS NOT NULL GROUP BY value, type HAVING cases > 1 ORDER BY cases DESC LIMIT 10",
            (org_id,),
        ).fetchall()
    except Exception:
        pass

    def _sev_count(rows, sev):
        return sum(1 for r in rows if (r["severity"] or "").lower() == sev)

    return {
        "scope": "global",
        "summary": {
            "open_cases": sum(1 for c in cases if (c["status"] or "") == "open"),
            "total_cases": len(cases),
            "queued_alerts": sum(1 for a in alerts if (a["status"] or "") in ("new", "queued")),
            "critical_cases": _sev_count(cases, "critical"),
            "high_cases": _sev_count(cases, "high"),
        },
        "cases": [
            {"id": c["id"], "title": c["title"], "severity": c["severity"],
             "status": c["status"], "summary": (c["summary"] or "")[:300], "created_at": c["created_at"]}
            for c in cases
        ],
        "alerts": [
            {"id": a["id"], "source": a["source"], "title": a["title"], "severity": a["severity"],
             "status": a["status"], "case_id": a["case_id"], "created_at": a["created_at"]}
            for a in alerts
        ],
        "activity": [
            {"step": r["step"], "status": r["status"], "detail": r["detail"], "timestamp": r["timestamp"]}
            for r in activity
        ],
        "correlated_iocs": [
            {"value": r["value"], "type": r["type"], "case_count": r["cases"]}
            for r in hot_iocs
        ],
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
- To look up an IOC's reputation across threat-intel platforms (VirusTotal, AbuseIPDB, Shodan, urlscan, Hybrid Analysis, MISP), propose an "enrichment" action with tool_args {"ioc_type": "ip|domain|hash|url", "value": "<the ioc>"}
- For risky tools (nmap, tshark, tcpdump), mark requires_approval: true
- Be concise and factual — no speculation without evidence
- Show your reasoning: put your step-by-step thinking in the "reasoning" field so the analyst can follow how you reached the answer
- Anything with a side effect (running a tool, closing a case, contacting a platform that changes state) MUST be a suggested_action with requires_approval: true — never claim you already did it
- Structure your response as JSON with: reasoning, answer, citations, suggested_actions

Response format:
{
  "reasoning": ["Step 1: what I looked at", "Step 2: what it implies", "Step 3: what I conclude"],
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
    },
    {
      "action_type": "enrichment",
      "label": "Enrich IP 203.0.113.5",
      "description": "Reputation lookup via VirusTotal / AbuseIPDB / Shodan / MISP",
      "tool_args": {"ioc_type": "ip", "value": "203.0.113.5"},
      "requires_approval": true
    }
  ]
}"""

GLOBAL_SYSTEM_PROMPT = SOC_SYSTEM_PROMPT + """

You are operating in DASHBOARD mode with a SOC-wide view: you can see every case,
the alert queue, org-wide activity, and IOCs that correlate across cases. When the
analyst asks about "an alert" or "a case", identify which one(s) they mean from the
context and cite them by id. If the question is ambiguous across many cases, ask a
brief clarifying question rather than guessing."""


def chat_completion(context: dict[str, Any], history: list[dict], user_message: str, global_mode: bool = False) -> dict[str, Any]:
    """Call GPT-5.6 for chat response.

    Args:
        context: Case-specific or global SOC context
        history: Conversation history
        user_message: Current user question
        global_mode: If True, use GLOBAL_SYSTEM_PROMPT (dashboard copilot)
    """
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    if not openai_key:
        return {
            "reasoning": ["No OpenAI API key configured"],
            "answer": "I need an OpenAI API key configured to analyze cases. Please set OPENAI_API_KEY.",
            "citations": [],
            "suggested_actions": [],
        }

    try:
        import urllib.request
        import ssl

        system_prompt = GLOBAL_SYSTEM_PROMPT if global_mode else SOC_SYSTEM_PROMPT
        messages = [{"role": "system", "content": system_prompt}]

        # Add context
        context_str = json.dumps(context, indent=2)
        label = "SOC-wide context" if global_mode else "Case context"
        messages.append({
            "role": "user",
            "content": f"{label}:\n{context_str}\n\n"
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
            parsed = json.loads(content)
            # Ensure reasoning exists (fallback to empty list if not in response)
            if "reasoning" not in parsed:
                parsed["reasoning"] = []
            return parsed
        except json.JSONDecodeError:
            return {
                "reasoning": [],
                "answer": content,
                "citations": [],
                "suggested_actions": [],
            }

    except Exception as e:
        return {
            "reasoning": [f"LLM call failed: {str(e)[:200]}"],
            "answer": f"Error calling LLM: {str(e)[:200]}",
            "citations": [],
            "suggested_actions": [],
        }
