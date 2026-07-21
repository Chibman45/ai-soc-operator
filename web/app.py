"""AI SOC Operator — Web Interface.

Flask-based web UI for the playbook-driven SOC automation platform.
Provides setup wizard, dashboard, cases view, and report viewer.

Usage:
    python3 web/app.py
    # Then open http://localhost:5000
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
from functools import wraps
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "data" / "soc_operator.db"

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)


# ── Database ──

def get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            platform TEXT NOT NULL,
            key_name TEXT NOT NULL,
            key_value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS platform_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            platform TEXT UNIQUE,
            base_url TEXT,
            enabled INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            playbook TEXT,
            alert_file TEXT,
            status TEXT DEFAULT 'pending',
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            finished_at TIMESTAMP,
            result_json TEXT,
            report_path TEXT
        );
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER,
            case_id TEXT,
            title TEXT,
            severity TEXT,
            status TEXT DEFAULT 'open',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            summary TEXT,
            report_path TEXT,
            FOREIGN KEY (run_id) REFERENCES runs(id)
        );
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            step TEXT,
            status TEXT,
            detail TEXT,
            FOREIGN KEY (run_id) REFERENCES runs(id)
        );
    """)
    conn.commit()
    conn.close()


# ── Auth ──

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest() + f":{salt}"


def verify_password(password: str, stored: str) -> bool:
    salt = stored.split(":")[-1]
    return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest() == stored.split(":")[0]


PLATFORM_DEFAULTS = {
    "thehive": "https://thehive.example.com",
    "cortex": "https://cortex.example.com",
    "wazuh_manager": "https://wazuh-manager.example.com:55000",
    "wazuh_indexer": "https://wazuh-indexer.example.com:9200",
    "virustotal": "https://www.virustotal.com",
    "abuseipdb": "https://api.abuseipdb.com",
    "shodan": "https://api.shodan.io",
    "urlscan": "https://urlscan.io",
    "hybrid_analysis": "https://www.hybrid-analysis.com",
    "misp": "https://misp.example.com",
}

PLATFORM_CREDENTIAL_KEYS = [
    ("OPENAI_API_KEY", None),
    ("THEHIVE_API_KEY", "thehive"),
    ("CORTEX_API_KEY", "cortex"),
    ("WAZUH_API_TOKEN", "wazuh_manager"),
    ("VIRUSTOTAL_API_KEY", "virustotal"),
    ("ABUSEIPDB_API_KEY", "abuseipdb"),
    ("SHODAN_API_KEY", "shodan"),
    ("URLSCAN_API_KEY", "urlscan"),
    ("HYBRID_ANALYSIS_API_KEY", "hybrid_analysis"),
    ("MISP_API_KEY", "misp"),
]


def _platform_rows() -> list[dict[str, Any]]:
    return [
        {"platform": platform, "base_url": base_url, "enabled": 0}
        for platform, base_url in PLATFORM_DEFAULTS.items()
    ]


def save_platform_settings(conn: sqlite3.Connection, form: Any) -> None:
    for key_name, platform in PLATFORM_CREDENTIAL_KEYS:
        value = form.get(key_name, "").strip()
        if value:
            conn.execute("DELETE FROM credentials WHERE key_name = ?", (key_name,))
            conn.execute(
                "INSERT INTO credentials (platform, key_name, key_value) VALUES (?, ?, ?)",
                ((platform or key_name.split("_")[0].lower()), key_name, value),
            )
    for platform, default_url in PLATFORM_DEFAULTS.items():
        form_key = {
            "thehive": "THEHIVE_URL",
            "cortex": "CORTEX_URL",
            "wazuh_manager": "WAZUH_URL",
            "wazuh_indexer": "WAZUH_INDEXER_URL",
            "misp": "MISP_URL",
            "virustotal": "VIRUSTOTAL_URL",
            "abuseipdb": "ABUSEIPDB_URL",
            "shodan": "SHODAN_URL",
            "urlscan": "URLSCAN_URL",
            "hybrid_analysis": "HYBRID_ANALYSIS_URL",
        }.get(platform)
        if form_key:
            base_url = form.get(form_key, "").strip() or default_url
            enabled = 1 if base_url else 0
            conn.execute(
                "INSERT INTO platform_config (platform, base_url, enabled, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)"
                " ON CONFLICT(platform) DO UPDATE SET base_url = excluded.base_url, enabled = excluded.enabled, updated_at = CURRENT_TIMESTAMP",
                (platform, base_url, enabled),
            )


def build_platforms_toml() -> str:
    conn = get_db()
    creds = {row["key_name"]: row["key_value"] for row in conn.execute("SELECT key_name, key_value FROM credentials").fetchall()}
    rows = conn.execute("SELECT platform, base_url, enabled FROM platform_config ORDER BY platform").fetchall()
    conn.close()
    lines = [
        "# AI SOC Operator — Platform Configuration",
        "# Auto-generated from the web portal",
        "",
    ]
    for row in rows:
        platform = row["platform"]
        enabled = int(row["enabled"] or 0)
        key_name = {
            "thehive": "THEHIVE_API_KEY",
            "cortex": "CORTEX_API_KEY",
            "wazuh_manager": "WAZUH_API_TOKEN",
            "virustotal": "VIRUSTOTAL_API_KEY",
            "abuseipdb": "ABUSEIPDB_API_KEY",
            "shodan": "SHODAN_API_KEY",
            "urlscan": "URLSCAN_API_KEY",
            "hybrid_analysis": "HYBRID_ANALYSIS_API_KEY",
            "misp": "MISP_API_KEY",
        }.get(platform)
        if not key_name:
            continue
        lines.extend([
            f"[platforms.{platform}]",
            f"enabled = {str(bool(enabled and creds.get(key_name))).lower()}",
            f'base_url = "{row["base_url"] or PLATFORM_DEFAULTS.get(platform, "")}"',
            f'credential_env = "{key_name}"',
            "",
        ])
    return "\n".join(lines)


def write_platforms_toml() -> None:
    output = ROOT / "config" / "platforms.toml"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(build_platforms_toml(), encoding="utf-8")


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ── Routes: Auth ──

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()
        if user and verify_password(password, user["password_hash"]):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "error")
    return render_template("login.html")


@app.route("/setup", methods=["GET", "POST"])
def setup():
    conn = get_db()
    user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    conn.close()
    if user_count > 0:
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password required", "error")
        else:
            conn = get_db()
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hash_password(password)),
            )
            conn.commit()
            conn.close()
            session["user_id"] = 1
            session["username"] = username
            return redirect(url_for("credentials"))
    return render_template("setup.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── Routes: Credentials ──

@app.route("/credentials", methods=["GET", "POST"])
@login_required
def credentials():
    conn = get_db()
    if request.method == "POST":
        save_platform_settings(conn, request.form)
        conn.commit()
        flash("Credentials and platform connections saved", "success")
        return redirect(url_for("dashboard"))

    existing = {
        row["key_name"]: row["key_value"][:8] + "****"
        for row in conn.execute("SELECT key_name, key_value FROM credentials").fetchall()
    }
    platform_existing = {
        row["platform"]: {"base_url": row["base_url"], "enabled": bool(row["enabled"])}
        for row in conn.execute("SELECT platform, base_url, enabled FROM platform_config").fetchall()
    }
    conn.close()
    return render_template("credentials.html", existing=existing, platform_existing=platform_existing)


# ── Routes: Dashboard ──

@app.route("/")
@login_required
def dashboard():
    conn = get_db()
    runs = conn.execute(
        "SELECT * FROM runs ORDER BY started_at DESC LIMIT 20"
    ).fetchall()
    cases = conn.execute(
        "SELECT * FROM cases ORDER BY created_at DESC LIMIT 10"
    ).fetchall()
    recent_log = conn.execute(
        "SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return render_template(
        "dashboard.html", runs=runs, cases=cases, activity=recent_log
    )


# ── Routes: Agent Run ──

@app.route("/run", methods=["POST"])
@login_required
def run_agent():
    write_platforms_toml()
    playbook = request.form.get("playbook", "identity-compromise.yaml")
    alert_file = request.form.get("alert_file", "")

    conn = get_db()
    cursor = conn.execute(
        "INSERT INTO runs (playbook, alert_file, status) VALUES (?, ?, 'running')",
        (playbook, alert_file),
    )
    run_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # Run agent in background thread
    thread = threading.Thread(
        target=_execute_run, args=(run_id, playbook, alert_file), daemon=True
    )
    thread.start()

    return jsonify({"run_id": run_id, "status": "running"})


def _execute_run(run_id: int, playbook: str, alert_file: str) -> None:
    """Execute the agent in a background thread."""
    write_platforms_toml()
    conn = get_db()
    try:
        # Load credentials from DB into environment
        creds = conn.execute("SELECT key_name, key_value FROM credentials").fetchall()
        for cred in creds:
            os.environ[cred["key_name"]] = cred["key_value"]

        # Log start
        conn.execute(
            "INSERT INTO activity_log (run_id, step, status, detail) VALUES (?, 'start', 'running', ?)",
            (run_id, f"Starting playbook: {playbook}"),
        )
        conn.commit()

        # Build command
        cmd = [
            sys.executable, "-m", "scripts.orchestrator",
            "--playbook", str(ROOT / "playbooks" / playbook),
        ]
        if alert_file:
            cmd.extend(["--alert", alert_file])

        # Execute
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=300,
        )

        # Parse output and create case
        if result.returncode == 0:
            conn.execute(
                "UPDATE runs SET status = 'completed', finished_at = CURRENT_TIMESTAMP, result_json = ? WHERE id = ?",
                (result.stdout, run_id),
            )
            # Create a case entry
            conn.execute(
                "INSERT INTO cases (run_id, title, severity, status, summary) VALUES (?, ?, 'medium', 'open', ?)",
                (run_id, f"Auto-created from {playbook}", result.stdout[:500]),
            )
            conn.execute(
                "INSERT INTO activity_log (run_id, step, status, detail) VALUES (?, 'complete', 'done', 'Playbook execution completed')",
                (run_id,),
            )
        else:
            conn.execute(
                "UPDATE runs SET status = 'failed', finished_at = CURRENT_TIMESTAMP, result_json = ? WHERE id = ?",
                (result.stderr[:2000], run_id),
            )
            conn.execute(
                "INSERT INTO activity_log (run_id, step, status, detail) VALUES (?, 'error', 'failed', ?)",
                (run_id, result.stderr[:500]),
            )
        conn.commit()

    except Exception as e:
        conn.execute(
            "UPDATE runs SET status = 'failed', finished_at = CURRENT_TIMESTAMP WHERE id = ?",
            (run_id,),
        )
        conn.execute(
            "INSERT INTO activity_log (run_id, step, status, detail) VALUES (?, 'error', 'failed', ?)",
            (run_id, str(e)[:500]),
        )
        conn.commit()
    finally:
        conn.close()


# ── Routes: Cases ──

@app.route("/cases")
@login_required
def cases():
    conn = get_db()
    cases = conn.execute(
        "SELECT * FROM cases ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return render_template("cases.html", cases=cases)


@app.route("/cases/<int:case_id>")
@login_required
def case_detail(case_id: int):
    conn = get_db()
    case = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    run = None
    activity = []
    if case and case["run_id"]:
        run = conn.execute("SELECT * FROM runs WHERE id = ?", (case["run_id"],)).fetchone()
        activity = conn.execute(
            "SELECT * FROM activity_log WHERE run_id = ? ORDER BY timestamp",
            (case["run_id"],),
        ).fetchall()
    conn.close()
    if not case:
        flash("Case not found", "error")
        return redirect(url_for("cases"))
    return render_template("case_detail.html", case=case, run=run, activity=activity)


# ── Routes: Reports ──

@app.route("/reports")
@login_required
def reports():
    conn = get_db()
    cases_with_reports = conn.execute(
        "SELECT * FROM cases WHERE report_path IS NOT NULL ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return render_template("reports.html", cases=cases_with_reports)


# ── Routes: API (for AJAX) ──

@app.route("/api/run/<int:run_id>/status")
@login_required
def api_run_status(run_id: int):
    conn = get_db()
    run = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    log = conn.execute(
        "SELECT * FROM activity_log WHERE run_id = ? ORDER BY timestamp",
        (run_id,),
    ).fetchall()
    conn.close()
    if not run:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "status": run["status"],
        "log": [dict(row) for row in log],
    })


@app.route("/api/activity")
@login_required
def api_activity():
    conn = get_db()
    log = conn.execute(
        "SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return jsonify([dict(row) for row in log])


@app.route("/playbooks")
@login_required
def playbooks():
    pb_dir = ROOT / "playbooks"
    playbooks = []
    if pb_dir.is_dir():
        for f in sorted(pb_dir.glob("*.yaml")):
            playbooks.append({"name": f.name, "path": str(f)})
    return render_template("playbooks.html", playbooks=playbooks)


# ── Routes: Playbook Upload ──

@app.route("/playbooks/upload", methods=["POST"])
@login_required
def upload_playbook():
    if "playbook" not in request.files:
        flash("No file selected", "error")
        return redirect(url_for("playbooks"))

    file = request.files["playbook"]
    if not file.filename:
        flash("No file selected", "error")
        return redirect(url_for("playbooks"))

    allowed = {".yaml", ".yml", ".pdf", ".docx", ".md", ".txt"}
    suffix = Path(file.filename).suffix.lower()
    if suffix not in allowed:
        flash(f"Unsupported file type. Allowed: {', '.join(sorted(allowed))}", "error")
        return redirect(url_for("playbooks"))

    # Save uploaded file temporarily
    import tempfile
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    file.save(tmp.name)
    tmp.close()

    from scripts.playbook_parser import parse_playbook_document

    # For YAML, parse directly; for PDF/DOCX/MD, use LLM parser
    openai_client = None
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    if openai_key and suffix not in (".yaml", ".yml"):
        from scripts.soc_client.openai import OpenAIClient
        openai_client = OpenAIClient(openai_key)

    if openai_client:
        def llm_callback(system_prompt, user_prompt):
            return openai_client.chat(user_prompt, system=system_prompt)
    else:
        llm_callback = None

    if suffix in (".yaml", ".yml"):
        # Direct YAML parse
        import yaml
        try:
            content = Path(tmp.name).read_text(encoding="utf-8")
            parsed = yaml.safe_load(content)
            if not isinstance(parsed, dict) or "steps" not in parsed:
                flash("Invalid playbook: must have 'steps' key", "error")
                return redirect(url_for("playbooks"))
            dest = ROOT / "playbooks" / file.filename
            dest.write_text(content, encoding="utf-8")
        except Exception as e:
            flash(f"YAML parse error: {e}", "error")
            return redirect(url_for("playbooks"))
    else:
        # Non-YAML: extract → LLM → validate → save
        if not llm_callback:
            flash("PDF/DOCX parsing requires an OpenAI API key. Set OPENAI_API_KEY.", "error")
            return redirect(url_for("playbooks"))
        result = parse_playbook_document(Path(tmp.name), llm_callback)
        if not result["valid"]:
            flash(f"Parsing errors: {'; '.join(result['errors'])}", "error")
            return redirect(url_for("playbooks"))
        # Save parsed playbook as YAML
        import yaml
        safe_name = Path(file.filename).stem.replace(" ", "-").lower()
        dest = ROOT / "playbooks" / f"{safe_name}.yaml"
        dest.write_text(yaml.dump(result["playbook"], default_flow_style=False), encoding="utf-8")
        file.filename = f"{safe_name}.yaml"

    # Cleanup temp file
    Path(tmp.name).unlink(missing_ok=True)

    # Record in DB
    conn = get_db()
    conn.execute(
        "INSERT INTO activity_log (step, status, detail) VALUES (?, 'done', ?)",
        ("upload_playbook", f"Uploaded playbook: {file.filename}"),
    )
    conn.commit()
    conn.close()

    flash(f"Playbook uploaded: {file.filename}", "success")
    return redirect(url_for("playbooks"))


# ── Routes: Run Approve/Reject ──

@app.route("/api/runs/<int:run_id>/approve", methods=["POST"])
@login_required
def api_run_approve(run_id: int):
    conn = get_db()
    run = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if not run:
        conn.close()
        return jsonify({"error": "not found"}), 404
    conn.execute(
        "UPDATE runs SET status = 'approved' WHERE id = ?",
        (run_id,),
    )
    conn.execute(
        "INSERT INTO activity_log (run_id, step, status, detail) VALUES (?, 'approval', 'done', 'Run approved by operator')",
        (run_id,),
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "approved", "run_id": run_id})


@app.route("/api/runs/<int:run_id>/reject", methods=["POST"])
@login_required
def api_run_reject(run_id: int):
    reason = request.json.get("reason", "") if request.is_json else ""
    conn = get_db()
    conn.execute(
        "UPDATE runs SET status = 'rejected' WHERE id = ?",
        (run_id,),
    )
    conn.execute(
        "INSERT INTO activity_log (run_id, step, status, detail) VALUES (?, 'approval', 'failed', ?)",
        (run_id, f"Run rejected: {reason}" if reason else "Run rejected by operator"),
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "rejected", "run_id": run_id})


# ── Routes: Secrets Status & Test ──

@app.route("/api/secrets/status")
@login_required
def api_secrets_status():
    conn = get_db()
    creds = conn.execute("SELECT key_name FROM credentials").fetchall()
    conn.close()
    configured = [c["key_name"] for c in creds]
    required = [
        "OPENAI_API_KEY", "THEHIVE_API_KEY", "CORTEX_API_KEY",
        "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY",
    ]
    optional = [
        "SHODAN_API_KEY", "URLSCAN_API_KEY", "HYBRID_ANALYSIS_API_KEY",
        "CENSYS_PAT", "WAZUH_API_TOKEN",
    ]
    return jsonify({
        "configured": configured,
        "required": {k: k in configured for k in required},
        "optional": {k: k in configured for k in optional},
        "all_required_met": all(k in configured for k in required),
    })


@app.route("/api/secrets/test", methods=["POST"])
@login_required
def api_secrets_test():
    platform = request.json.get("platform", "") if request.is_json else ""
    if not platform:
        return jsonify({"error": "platform required"}), 400

    # Simple connectivity test
    import urllib.request
    import ssl
    test_urls = {
        "VIRUSTOTAL": "https://www.virustotal.com",
        "ABUSEIPDB": "https://api.abuseipdb.com",
        "SHODAN": "https://api.shodan.io",
        "THEHIVE": None,  # Needs URL from config
        "CORTEX": None,
    }
    url = test_urls.get(platform.upper())
    if url is None:
        return jsonify({"status": "unknown", "message": "Platform requires base URL configuration"})

    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, method="HEAD")
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        opener.open(req, timeout=5)
        return jsonify({"status": "reachable", "platform": platform})
    except Exception as e:
        return jsonify({"status": "unreachable", "error": str(e)[:200]})


# ── Main ──

def get_local_ip() -> str:
    """Detect the machine's local IP address."""
    import socket as _socket
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


if __name__ == "__main__":
    init_db()
    ip = get_local_ip()
    port = 5000
    print(f"\n{'='*50}")
    print(f"  AI SOC Operator")
    print(f"  Local:   http://localhost:{port}")
    print(f"  Network: http://{ip}:{port}")
    print(f"{'='*50}\n")
    app.run(host="0.0.0.0", port=port, debug=True)
