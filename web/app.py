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
        for key in [
            "OPENAI_API_KEY", "THEHIVE_API_KEY", "CORTEX_API_KEY",
            "WAZUH_API_TOKEN", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY",
            "SHODAN_API_KEY", "URLSCAN_API_KEY", "HYBRID_ANALYSIS_API_KEY",
        ]:
            value = request.form.get(key, "").strip()
            if value:
                conn.execute(
                    "INSERT OR REPLACE INTO credentials (platform, key_name, key_value) VALUES (?, ?, ?)",
                    (key.split("_")[0].lower(), key, value),
                )
        conn.commit()
        flash("Credentials saved", "success")
        return redirect(url_for("dashboard"))

    existing = {
        row["key_name"]: row["key_value"][:8] + "****"
        for row in conn.execute("SELECT key_name, key_value FROM credentials").fetchall()
    }
    conn.close()
    return render_template("credentials.html", existing=existing)


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


# ── Main ──

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
