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
import sys
from datetime import datetime, timezone
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
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

from scripts.job_queue import JobQueue
from scripts.learning import LearningStore, learn_alert, learn_case, learn_playbook_result
from scripts.common import audit
from web.security import (
    csrf_token,
    current_org_id,
    enforce_csrf,
    login_required as secure_login_required,
    permission_required,
    permissions_for_user,
)
from web.services.credential_vault import open_secret, seal_secret
from web.services.database import connect_database

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "data" / "soc_operator.db"

app = Flask(__name__)

# Forwarded headers are trusted only when deployment explicitly enables the
# reverse-proxy boundary. The bootstrap binds Gunicorn to loopback in this mode,
# so untrusted clients cannot bypass Nginx and forge these values directly.
if os.environ.get("AI_SOC_BEHIND_PROXY", "").lower() in {"1", "true", "yes"}:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)


def _session_secret() -> str:
    configured = os.environ.get("AI_SOC_SESSION_SECRET", "").strip()
    if configured:
        return configured
    if os.environ.get("AI_SOC_ENV", "development").lower() == "production":
        raise RuntimeError("AI_SOC_SESSION_SECRET is required in production")
    path = ROOT / "data" / ".session_secret"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(secrets.token_hex(32), encoding="ascii")
        try:
            path.chmod(0o600)
        except OSError:
            pass
    return path.read_text(encoding="ascii").strip()


app.secret_key = _session_secret()
app.config.update(
    MAX_CONTENT_LENGTH=int(os.environ.get("AI_SOC_MAX_REQUEST_BYTES", str(5 * 1024 * 1024))),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("AI_SOC_ENV", "development").lower() == "production",
    PERMANENT_SESSION_LIFETIME=int(os.environ.get("AI_SOC_SESSION_TTL_SECONDS", "28800")),
)
app.before_request(enforce_csrf)
app.jinja_env.globals["csrf_token"] = csrf_token


@app.context_processor
def template_permissions():
    """Expose current permissions for navigation and action visibility only."""
    user_id = session.get("user_id")
    if user_id is None:
        return {"can": lambda _permission: False}
    conn = get_db()
    try:
        permissions = permissions_for_user(conn, int(user_id), current_org_id(conn))
    finally:
        conn.close()
    return {"can": lambda permission: permission in permissions}


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
    )
    if app.config["SESSION_COOKIE_SECURE"]:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response
job_queue = JobQueue(DB_PATH)


# ── Database ──

def get_db():
    data_dir = DB_PATH.parent
    data_dir.mkdir(parents=True, exist_ok=True)
    # Check writability — common failure when bootstrap ran as root
    import os
    if data_dir.exists() and not os.access(data_dir, os.W_OK):
        print(
            f"\n[ERROR] Cannot write to {data_dir}\n"
            f"  Fix with: sudo chown -R $USER {data_dir}\n"
            f"  Then re-run: ai-soc-operator\n",
            file=sys.stderr,
        )
        sys.exit(1)
    if DB_PATH.exists() and not os.access(DB_PATH, os.W_OK):
        print(
            f"\n[ERROR] Database file is not writable: {DB_PATH}\n"
            f"  Fix with: sudo chown $USER {DB_PATH}\n"
            f"  Then re-run: ai-soc-operator\n",
            file=sys.stderr,
        )
        sys.exit(1)
    return connect_database(DB_PATH)


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
    # Initialize feature tables (alerts, roles, observables, responders, etc.)
    try:
        from web.services.schema_features import init_feature_db
        init_feature_db(conn)
        from web.services.credential_vault import migrate_plaintext_credentials
        migrated = migrate_plaintext_credentials(conn)
        if migrated:
            audit("credentials_encrypted_at_rest", count=migrated)
    except Exception as e:
        if os.environ.get("AI_SOC_ENV", "development").lower() == "production":
            conn.close()
            raise
        print(f"[WARN] Feature schema init failed: {e}", file=sys.stderr)
    conn.close()


# ── Auth ──

def hash_password(password: str) -> str:
    return generate_password_hash(password, method="scrypt")


def verify_password(password: str, stored: str) -> bool:
    if stored.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored, password)
    # Legacy salted SHA-256 remains readable only long enough to migrate at login.
    try:
        digest, salt = stored.split(":", 1)
    except ValueError:
        return False
    candidate = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return secrets.compare_digest(candidate, digest)


PLATFORM_DEFAULTS = {
    # Self-hosted services have no safe universal address. Keeping them empty
    # prevents a placeholder domain from being saved as an enabled connection.
    "thehive": "",
    "cortex": "",
    "wazuh_manager": "",
    "wazuh_indexer": "",
    "virustotal": "https://www.virustotal.com",
    "abuseipdb": "https://api.abuseipdb.com",
    "shodan": "https://api.shodan.io",
    "urlscan": "https://urlscan.io",
    "hybrid_analysis": "https://www.hybrid-analysis.com",
    "phishtank": "https://checkurl.phishtank.com",
    "misp": "",
}

PLATFORM_URL_PLACEHOLDERS = {
    "thehive": "https://thehive.your-domain.example",
    "cortex": "https://cortex.your-domain.example",
    "wazuh_manager": "https://wazuh-manager.your-domain.example:55000",
    "wazuh_indexer": "https://wazuh-indexer.your-domain.example:9200",
    "misp": "https://misp.your-domain.example",
}

# Platforms that operate without an API key. They may still accept an optional
# key (higher rate limits), but are enabled purely on their config flag.
KEYLESS_PLATFORMS = {"phishtank"}

PLATFORM_CREDENTIAL_KEYS = [
    ("OPENAI_API_KEY", None),
    ("THEHIVE_API_KEY", "thehive"),
    ("CORTEX_API_KEY", "cortex"),
    ("WAZUH_API_TOKEN", "wazuh_manager"),
    ("WAZUH_INDEXER_USER", "wazuh_indexer"),
    ("WAZUH_INDEXER_PASSWORD", "wazuh_indexer"),
    ("VIRUSTOTAL_API_KEY", "virustotal"),
    ("ABUSEIPDB_API_KEY", "abuseipdb"),
    ("SHODAN_API_KEY", "shodan"),
    ("URLSCAN_API_KEY", "urlscan"),
    ("HYBRID_ANALYSIS_API_KEY", "hybrid_analysis"),
    ("PHISHTANK_API_KEY", "phishtank"),
    ("MISP_API_KEY", "misp"),
]


def _platform_rows() -> list[dict[str, Any]]:
    return [
        {"platform": platform, "base_url": base_url, "enabled": 0}
        for platform, base_url in PLATFORM_DEFAULTS.items()
    ]


def save_platform_settings(conn: sqlite3.Connection, form: Any, org_id: int) -> None:
    for key_name, platform in PLATFORM_CREDENTIAL_KEYS:
        value = form.get(key_name, "").strip()
        if value.endswith("****"):
            continue
        if value:
            conn.execute("DELETE FROM credentials WHERE key_name = ? AND org_id = ?", (key_name, org_id))
            conn.execute(
                "INSERT INTO credentials (platform, key_name, key_value, org_id) VALUES (?, ?, ?, ?)",
                ((platform or key_name.split("_")[0].lower()), key_name, seal_secret(value), org_id),
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
            "phishtank": "PHISHTANK_URL",
        }.get(platform)
        if form_key:
            base_url = form.get(form_key, "").strip() or default_url
            # Keyless platforms are toggled by an explicit checkbox; everything
            # else is considered enabled once it has a base URL.
            if platform in KEYLESS_PLATFORMS:
                enabled = 1 if form.get(f"{platform}_enabled") else 0
            else:
                enabled = 1 if base_url else 0
            conn.execute(
                "INSERT INTO platform_config (platform, base_url, enabled, org_id, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)"
                " ON CONFLICT(org_id, platform) DO UPDATE SET base_url = excluded.base_url, enabled = excluded.enabled, updated_at = CURRENT_TIMESTAMP",
                (platform, base_url, enabled, org_id),
            )


def build_platforms_toml(org_id: int | None = None) -> str:
    conn = get_db()
    org_id = org_id or current_org_id(conn)
    creds = {row["key_name"]: open_secret(row["key_value"]) for row in conn.execute("SELECT key_name, key_value FROM credentials WHERE org_id = ?", (org_id,)).fetchall()}
    rows = conn.execute("SELECT platform, base_url, enabled FROM platform_config WHERE org_id = ? ORDER BY platform", (org_id,)).fetchall()
    conn.close()
    lines = [
        "# AI SOC Operator — Platform Configuration",
        "# Auto-generated from the web portal",
        "",
    ]
    for row in rows:
        platform = row["platform"]
        enabled = int(row["enabled"] or 0)
        # Wazuh Indexer authenticates with basic auth (user+password), not a
        # single API key — emit a dedicated block with username/password envs.
        if platform == "wazuh_indexer":
            user = creds.get("WAZUH_INDEXER_USER")
            pw = creds.get("WAZUH_INDEXER_PASSWORD")
            idx_enabled = bool(enabled and user and pw)
            lines.extend([
                "[platforms.wazuh_indexer]",
                f"enabled = {str(idx_enabled).lower()}",
                f'base_url = "{row["base_url"] or PLATFORM_DEFAULTS.get(platform, "")}"',
                'username_env = "WAZUH_INDEXER_USER"',
                'password_env = "WAZUH_INDEXER_PASSWORD"',
                "",
            ])
            continue
        key_name = {
            "thehive": "THEHIVE_API_KEY",
            "cortex": "CORTEX_API_KEY",
            "wazuh_manager": "WAZUH_API_TOKEN",
            "virustotal": "VIRUSTOTAL_API_KEY",
            "abuseipdb": "ABUSEIPDB_API_KEY",
            "shodan": "SHODAN_API_KEY",
            "urlscan": "URLSCAN_API_KEY",
            "hybrid_analysis": "HYBRID_ANALYSIS_API_KEY",
            "phishtank": "PHISHTANK_API_KEY",
            "misp": "MISP_API_KEY",
        }.get(platform)
        if not key_name:
            continue
        # Keyless platforms (e.g. PhishTank) are enabled purely on their config
        # flag; key-gated platforms require a stored credential to switch on.
        if platform in KEYLESS_PLATFORMS:
            is_enabled = bool(enabled)
        else:
            is_enabled = bool(enabled and creds.get(key_name))
        lines.extend([
            f"[platforms.{platform}]",
            f"enabled = {str(is_enabled).lower()}",
            f'base_url = "{row["base_url"] or PLATFORM_DEFAULTS.get(platform, "")}"',
            f'credential_env = "{key_name}"',
            "",
        ])
    return "\n".join(lines)


def write_platforms_toml(org_id: int | None = None) -> None:
    output = ROOT / "config" / "platforms.toml"
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(build_platforms_toml(org_id), encoding="utf-8")
    except PermissionError:
        raise PermissionError(
            f"Cannot write to {output}. "
            f"Fix with: sudo chown -R $USER {output.parent}"
        )


def login_required(f):
    return secure_login_required(f)


# ── Routes: Auth ──

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        recent_failures = conn.execute(
            """
            SELECT COUNT(*) FROM login_attempts
            WHERE username = ? AND ip_address = ? AND succeeded = 0
              AND attempted_at >= datetime('now', '-15 minutes')
            """,
            (username, request.remote_addr or ""),
        ).fetchone()[0]
        if recent_failures >= 10:
            conn.close()
            audit("login_rate_limited", username=username, ip_address=request.remote_addr)
            return render_template("login.html"), 429
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        membership = None
        if user:
            membership = conn.execute(
                """
                SELECT org_id FROM organization_memberships
                WHERE user_id = ? AND status = 'active'
                ORDER BY CASE WHEN org_id = ? THEN 0 ELSE 1 END, id LIMIT 1
                """,
                (user["id"], user["default_org_id"]),
            ).fetchone()
        valid = bool(
            user
            and membership
            and not user["disabled_at"]
            and not user["must_change_password"]
            and verify_password(password, user["password_hash"])
        )
        conn.execute(
            "INSERT INTO login_attempts (username, ip_address, succeeded) VALUES (?, ?, ?)",
            (username, request.remote_addr or "", 1 if valid else 0),
        )
        if valid:
            if not user["password_hash"].startswith(("scrypt:", "pbkdf2:")):
                conn.execute(
                    "UPDATE users SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (hash_password(password), user["id"]),
                )
            conn.commit()
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["org_id"] = membership["org_id"]
            session["session_version"] = int(user["session_version"] or 0)
            csrf_token()
            audit("login_success", user_id=user["id"], org_id=membership["org_id"], ip_address=request.remote_addr)
            conn.close()
            return redirect(url_for("dashboard"))
        conn.commit()
        conn.close()
        audit("login_failed", username=username, ip_address=request.remote_addr)
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
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or len(password) < 12:
            flash("Username and a password of at least 12 characters are required", "error")
        else:
            conn = get_db()
            org = conn.execute("SELECT id FROM organizations ORDER BY id LIMIT 1").fetchone()
            if not org:
                org_id = int(conn.execute(
                    "INSERT INTO organizations (name, slug) VALUES ('Default Organization', 'default')"
                ).lastrowid)
            else:
                org_id = int(org["id"])
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hash_password(password)),
            )
            user_id = int(cursor.lastrowid)
            conn.execute("UPDATE users SET default_org_id = ?, password_changed_at = CURRENT_TIMESTAMP WHERE id = ?", (org_id, user_id))
            conn.execute("INSERT OR IGNORE INTO organization_memberships (org_id, user_id) VALUES (?, ?)", (org_id, user_id))
            from web.services.schema_features import ensure_admin_role
            ensure_admin_role(conn, user_id, org_id)
            conn.close()
            session.clear()
            session.permanent = True
            session["user_id"] = user_id
            session["username"] = username
            session["org_id"] = org_id
            session["session_version"] = 0
            csrf_token()
            audit("initial_admin_created", user_id=user_id, org_id=org_id)
            return redirect(url_for("credentials"))
    return render_template("setup.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── Routes: Credentials ──

@app.route("/credentials", methods=["GET", "POST"])
@permission_required("credential.manage")
def credentials():
    conn = get_db()
    org_id = current_org_id(conn)
    if request.method == "POST":
        save_platform_settings(conn, request.form, int(org_id))
        conn.commit()
        flash("Credentials and platform connections saved", "success")
        return redirect(url_for("dashboard"))

    existing = {
        row["key_name"]: row["key_value"][:8] + "****"
        for row in conn.execute("SELECT key_name, key_value FROM credentials WHERE org_id = ?", (org_id,)).fetchall()
    }
    platform_existing = {
        row["platform"]: {"base_url": row["base_url"], "enabled": bool(row["enabled"])}
        for row in conn.execute("SELECT platform, base_url, enabled FROM platform_config WHERE org_id = ?", (org_id,)).fetchall()
    }
    conn.close()
    return render_template(
        "credentials.html",
        existing=existing,
        platform_existing=platform_existing,
        platform_defaults=PLATFORM_DEFAULTS,
        platform_placeholders=PLATFORM_URL_PLACEHOLDERS,
    )


# ── Routes: Dashboard ──

@app.route("/")
@login_required
def dashboard():
    conn = get_db()
    org_id = current_org_id(conn)
    runs = conn.execute(
        "SELECT * FROM runs WHERE org_id = ? ORDER BY started_at DESC LIMIT 20", (org_id,)
    ).fetchall()
    cases = conn.execute(
        "SELECT * FROM cases WHERE org_id = ? ORDER BY created_at DESC LIMIT 10", (org_id,)
    ).fetchall()
    recent_log = conn.execute(
        "SELECT * FROM activity_log WHERE org_id = ? ORDER BY timestamp DESC LIMIT 50", (org_id,)
    ).fetchall()
    alerts = conn.execute(
        """
        SELECT a.*, j.status AS job_status
        FROM alerts a LEFT JOIN jobs j ON j.id = a.job_id AND j.org_id = a.org_id
        WHERE a.org_id = ?
        ORDER BY a.created_at DESC LIMIT 20
        """,
        (org_id,),
    ).fetchall()
    # Compute from stored UTC values in Python so SQLite and PostgreSQL produce
    # identical metrics without backend-specific date functions.
    metric_rows = conn.execute(
        "SELECT created_at, opened_at, first_response_at, closed_at FROM cases WHERE org_id = ?",
        (org_id,),
    ).fetchall()
    response_hours = [_elapsed_hours(row["opened_at"] or row["created_at"], row["first_response_at"]) for row in metric_rows]
    resolution_hours = [_elapsed_hours(row["opened_at"] or row["created_at"], row["closed_at"]) for row in metric_rows]
    response_hours = [value for value in response_hours if value is not None]
    resolution_hours = [value for value in resolution_hours if value is not None]
    sla = {
        "mtta_hours": round(sum(response_hours) / len(response_hours), 2) if response_hours else None,
        "mttr_hours": round(sum(resolution_hours) / len(resolution_hours), 2) if resolution_hours else None,
    }
    conn.close()
    return render_template(
        "dashboard.html", runs=runs, cases=cases, activity=recent_log,
        alerts=alerts, sla=sla,
    )


def _elapsed_hours(start: Any, end: Any) -> float | None:
    if not start or not end:
        return None
    def parse(value: Any) -> datetime:
        if isinstance(value, datetime):
            parsed = value
        else:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)
    try:
        return max(0.0, (parse(end) - parse(start)).total_seconds() / 3600)
    except (TypeError, ValueError):
        return None


# ── Routes: Agent Run ──

@app.route("/run", methods=["POST"])
@permission_required("tool.execute")
def run_agent():
    playbook = request.form.get("playbook", "identity-compromise.yaml")
    if Path(playbook).name != playbook:
        return jsonify({"error": "Invalid playbook name"}), 400
    alert_file = request.form.get("alert_file", "")
    playbook_path = ROOT / "playbooks" / playbook
    if not playbook_path.is_file():
        return jsonify({"error": f"Playbook not found: {playbook}"}), 400

    try:
        alert = _load_alert_payload(alert_file)
    except Exception as e:
        return jsonify({"error": f"Unable to load alert: {str(e)[:200]}"}), 400

    conn = get_db()
    org_id = current_org_id(conn)
    from web.services.alert_ingest import normalize_alert, observables_from_alert
    from web.services.organization_policy import allowed_playbooks_for_user, policy_allows_target

    available = [path.name for path in (ROOT / "playbooks").glob("*.yaml")]
    allowed = allowed_playbooks_for_user(
        conn,
        org_id=int(org_id),
        user_id=int(session["user_id"]),
        available=available,
    )
    if playbook not in allowed:
        conn.close()
        audit(
            "organization_policy_playbook_denied",
            org_id=org_id,
            user_id=session["user_id"],
            playbook=playbook,
        )
        return jsonify({"error": "playbook is outside your approved organization policy"}), 403
    normalized_alert = normalize_alert("manual", alert)
    scoped_observables = observables_from_alert(normalized_alert)
    denied_targets = [
        item["value"]
        for item in scoped_observables
        if not policy_allows_target(
            conn,
            org_id=int(org_id),
            user_id=int(session["user_id"]),
            target=item["value"],
        )
    ]
    if denied_targets:
        conn.close()
        audit(
            "organization_policy_alert_scope_denied",
            org_id=org_id,
            user_id=session["user_id"],
            target_count=len(denied_targets),
        )
        return jsonify({"error": "alert contains targets outside your approved organization policy scope"}), 403
    idempotency_key = request.headers.get("Idempotency-Key") or secrets.token_urlsafe(24)
    existing_run = conn.execute(
        "SELECT id FROM runs WHERE org_id = ? AND idempotency_key = ?",
        (org_id, idempotency_key),
    ).fetchone()
    if existing_run:
        conn.close()
        return jsonify({"run_id": existing_run["id"], "status": "already_queued"}), 200
    cursor = conn.execute(
        "INSERT INTO runs (org_id, requested_by, idempotency_key, playbook, alert_file, status) VALUES (?, ?, ?, ?, ?, 'pending')",
        (org_id, session["user_id"], idempotency_key, playbook, alert_file or "demo/brute-force-alert.json"),
    )
    run_id = cursor.lastrowid
    conn.execute(
        "INSERT INTO activity_log (org_id, actor_id, run_id, step, status, detail) VALUES (?, ?, ?, 'queue', 'running', ?)",
        (org_id, session["user_id"], run_id, f"Queued playbook: {playbook}"),
    )
    conn.commit()
    conn.close()

    config = load_config_for_web(int(org_id))
    job_id = job_queue.create_job(
        run_id=run_id,
        playbook_path=str(playbook_path),
        alert=alert,
        config=config,
        org_id=int(org_id),
        idempotency_key=idempotency_key,
    )
    learn_alert(alert, source="manual_run", playbook=playbook, org_id=int(org_id))
    from web.services.playbook_jobs import dispatch_playbook_job

    dispatch_playbook_job(job_queue, job_id)

    return jsonify({"run_id": run_id, "job_id": job_id, "status": "queued"})


def load_config_for_web(org_id: int | None = None) -> dict[str, Any]:
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore
    # Parsing the generated text in memory avoids a cross-tenant shared config file.
    return tomllib.loads(build_platforms_toml(org_id))


def _load_alert_payload(alert_file: str) -> dict[str, Any]:
    raw = (alert_file or "").strip()
    if not raw:
        raw = str(ROOT / "demo" / "brute-force-alert.json")
    path = Path(raw)
    if not path.is_absolute():
        path = ROOT / path
    resolved = path.resolve()
    allowed_roots = [(ROOT / name).resolve() for name in ("demo", "data", "evidence")]
    if not any(resolved == root or root in resolved.parents for root in allowed_roots):
        raise ValueError("alert file must be under demo/, data/, or evidence/")
    path = resolved
    if not path.is_file():
        raise FileNotFoundError(str(path))
    alert = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(alert, dict):
        raise ValueError("alert JSON must be an object")
    return alert


def _execute_run_job(
    run_id: int,
    playbook_path: Path,
    alert: dict[str, Any],
    config: dict[str, Any],
    progress_cb,
    org_id: int,
) -> dict[str, Any]:
    """Execute a web-submitted run through the persistent job queue."""
    from scripts.common import Session
    from scripts.orchestrator import build_clients, execute_playbook

    progress_cb(0.05)
    conn = get_db()
    try:
        credentials = {
            row["key_name"]: open_secret(row["key_value"])
            for row in conn.execute(
                "SELECT key_name, key_value FROM credentials WHERE org_id = ?",
                (org_id,),
            ).fetchall()
        }
        config = load_config_for_web(org_id) or config

        conn.execute(
            "INSERT INTO activity_log (org_id, run_id, step, status, detail) VALUES (?, ?, 'start', 'running', ?)",
            (org_id, run_id, f"Starting playbook: {playbook_path.name}"),
        )
        conn.execute("UPDATE runs SET status = 'running', first_response_at = COALESCE(first_response_at, CURRENT_TIMESTAMP) WHERE id = ? AND org_id = ?", (run_id, org_id))
        conn.commit()
        progress_cb(0.15)

        clients = build_clients(config, credentials=credentials)
        progress_cb(0.25)

        alert_title = alert.get("rule", {}).get("name", alert.get("title", "Unknown alert"))
        session_obj = Session(
            mode="SOC_ANALYST",
            target=alert.get("agent", {}).get("name", "manual-run"),
            purpose=f"Web run for: {alert_title}",
        )
        try:
            progress_cb(0.35)
            from web.services.approvals import make_approval_handler

            approval_handler = make_approval_handler(run_id)
            result = execute_playbook(
                playbook_path, alert, clients, session_obj,
                approval_handler=approval_handler,
            )
            progress_cb(0.9)
        finally:
            session_obj.finish()

        result_json = json.dumps(result, indent=2)
        conn.execute(
            "UPDATE runs SET status = 'completed', finished_at = CURRENT_TIMESTAMP, result_json = ?, report_path = ? WHERE id = ?",
            (result_json, result.get("report_path"), run_id),
        )
        case_title = f"Auto-created from {playbook_path.name}"
        case_summary = result_json[:500]
        severity = result.get("triage_result", {}).get("tier", "medium")
        external_thehive_id = _thehive_case_id(result)
        cursor = conn.execute(
            """
            INSERT INTO cases
                (org_id, run_id, case_id, title, severity, status, summary, report_path,
                 opened_at, source_platform)
            VALUES (?, ?, ?, ?, ?, 'open', ?, ?, CURRENT_TIMESTAMP, ?)
            """,
            (
                org_id,
                run_id,
                external_thehive_id,
                case_title,
                severity,
                case_summary,
                result.get("report_path"),
                "thehive" if external_thehive_id else "local",
            ),
        )
        case_id = cursor.lastrowid
        if external_thehive_id:
            from web.services.external_sync import record_external_object

            record_external_object(
                conn,
                org_id=org_id,
                platform="thehive",
                object_type="case",
                external_id=external_thehive_id,
                local_case_id=int(case_id),
                payload={"source": "playbook", "run_id": run_id},
            )
        conn.execute(
            "INSERT INTO activity_log (org_id, run_id, step, status, detail) VALUES (?, ?, 'complete', 'done', 'Playbook execution completed')",
            (org_id, run_id),
        )
        conn.commit()

        learn_playbook_result(playbook_path.name, result, alert, org_id=org_id)
        learn_case(
            {
                "id": case_id,
                "title": case_title,
                "severity": severity,
                "status": "open",
                "summary": case_summary,
            },
            org_id=org_id,
        )
        progress_cb(1.0)
        return result
    except Exception as e:
        conn.execute(
            "UPDATE runs SET status = 'failed', finished_at = CURRENT_TIMESTAMP, result_json = ? WHERE id = ?",
            (str(e)[:2000], run_id),
        )
        conn.execute(
            "INSERT INTO activity_log (org_id, run_id, step, status, detail) VALUES (?, ?, 'error', 'failed', ?)",
            (org_id, run_id, str(e)[:500]),
        )
        conn.commit()
        raise
    finally:
        conn.close()


def _thehive_case_id(result: dict[str, Any]) -> str | None:
    """Find the external case created by a completed TheHive playbook step."""
    for step in (result.get("steps") or {}).values():
        if (
            isinstance(step, dict)
            and step.get("type") == "thehive"
            and step.get("status") == "completed"
            and step.get("case_id")
        ):
            return str(step["case_id"])
    return None


# ── Routes: Cases ──

@app.route("/cases")
@login_required
def cases():
    conn = get_db()
    org_id = current_org_id(conn)
    assignment = request.args.get("assignment", "all")
    where = "org_id = ?"
    params: list[Any] = [org_id]
    if assignment == "mine":
        where += " AND assignee_id = ?"
        params.append(session["user_id"])
    elif assignment == "unassigned":
        where += " AND assignee_id IS NULL"
    cases = conn.execute(
        f"""
        SELECT c.*, u.username AS assignee_name
        FROM cases c LEFT JOIN users u ON u.id = c.assignee_id
        WHERE {where.replace('org_id', 'c.org_id')} ORDER BY c.created_at DESC
        """,
        params,
    ).fetchall()
    members = conn.execute(
        """
        SELECT u.id, u.username FROM organization_memberships om
        JOIN users u ON u.id = om.user_id
        WHERE om.org_id = ? AND om.status = 'active' ORDER BY lower(u.username)
        """,
        (org_id,),
    ).fetchall()
    conn.close()
    return render_template("cases.html", cases=cases, members=members, assignment=assignment)


@app.route("/cases/<int:case_id>")
@login_required
def case_detail(case_id: int):
    conn = get_db()
    org_id = current_org_id(conn)
    case = conn.execute("SELECT * FROM cases WHERE id = ? AND org_id = ?", (case_id, org_id)).fetchone()
    run = None
    activity = []
    steps = []
    if case and case["run_id"]:
        run = conn.execute("SELECT * FROM runs WHERE id = ?", (case["run_id"],)).fetchone()
        activity = conn.execute(
            "SELECT * FROM activity_log WHERE run_id = ? ORDER BY timestamp",
            (case["run_id"],),
        ).fetchall()
        steps = _extract_run_steps(run)
    conn.close()
    if not case:
        flash("Case not found", "error")
        return redirect(url_for("cases"))
    return render_template(
        "case_detail.html", case=case, run=run, activity=activity, steps=steps
    )


def _extract_run_steps(run) -> list[dict[str, Any]]:
    """Parse a run's result_json into display-friendly step records.

    Surfaces the LLM "thought process" (response/analysis), toolchain
    enrichment output, and TheHive/case actions so the UI can render them
    instead of a raw JSON blob.
    """
    if not run:
        return []
    try:
        result = json.loads(run["result_json"] or "{}")
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(result, dict):
        return []

    ordered_ids = [e.get("step_id") for e in result.get("execution_log", [])]
    step_results = result.get("steps", {})
    # Preserve execution order, then append any steps missing from the log.
    seen: set[str] = set()
    display: list[dict[str, Any]] = []
    for step_id in [*ordered_ids, *step_results.keys()]:
        if not step_id or step_id in seen or step_id not in step_results:
            continue
        seen.add(step_id)
        data = step_results[step_id]
        if not isinstance(data, dict):
            display.append({"id": step_id, "kind": "other", "raw": data})
            continue
        kind = data.get("type") or ("toolchain" if "results" in data else "other")
        record: dict[str, Any] = {
            "id": step_id,
            "kind": kind,
            "status": data.get("status", ""),
            "error": data.get("error"),
        }
        if kind == "llm":
            # The model's reasoning/output — the "thought process".
            record["thought"] = (
                data.get("response")
                or data.get("analysis")
                or data.get("instruction")
                or ""
            )
            record["model"] = data.get("model", "")
            record["prompt"] = data.get("prompt", "")
        elif kind == "toolchain" or "results" in data:
            record["kind"] = "toolchain"
            record["tool_results"] = data.get("results", [])
        elif kind == "thehive":
            record["action"] = data.get("action", "")
            record["case_ref"] = data.get("case_id")
        else:
            record["raw"] = data
        display.append(record)
    return display


# ── Routes: Reports ──

@app.route("/reports")
@login_required
def reports():
    conn = get_db()
    org_id = current_org_id(conn)
    cases_with_reports = conn.execute(
        "SELECT * FROM cases WHERE org_id = ? AND report_path IS NOT NULL ORDER BY created_at DESC",
        (org_id,),
    ).fetchall()
    conn.close()
    return render_template("reports.html", cases=cases_with_reports)


@app.route("/intel")
@login_required
def threat_intel():
    conn = get_db()
    org_id = current_org_id(conn)
    events = conn.execute(
        "SELECT * FROM intel_events WHERE org_id = ? ORDER BY updated_at DESC LIMIT 250",
        (org_id,),
    ).fetchall()
    sync_state = conn.execute(
        "SELECT * FROM integration_sync_state WHERE org_id = ? AND platform = 'misp' AND object_type = 'event'",
        (org_id,),
    ).fetchone()
    conn.close()
    return render_template("intel.html", events=events, sync_state=sync_state)


# ── Routes: API (for AJAX) ──

@app.route("/api/run/<int:run_id>/status")
@login_required
def api_run_status(run_id: int):
    conn = get_db()
    org_id = current_org_id(conn)
    run = conn.execute("SELECT * FROM runs WHERE id = ? AND org_id = ?", (run_id, org_id)).fetchone()
    log = conn.execute(
        "SELECT * FROM activity_log WHERE run_id = ? AND org_id = ? ORDER BY timestamp",
        (run_id, org_id),
    ).fetchall()
    job = conn.execute(
        "SELECT id, status, progress, error_message, finished_at FROM jobs WHERE run_id = ? AND org_id = ? ORDER BY created_at DESC LIMIT 1",
        (run_id, org_id),
    ).fetchone()
    conn.close()
    if not run:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "status": run["status"],
        "job": dict(job) if job else None,
        "log": [dict(row) for row in log],
    })


@app.route("/api/learning/suggestions")
@permission_required("learning.review")
def api_learning_suggestions():
    return jsonify(LearningStore().list_skill_suggestions(org_id=current_org_id()))


@app.route("/api/activity")
@login_required
def api_activity():
    conn = get_db()
    org_id = current_org_id(conn)
    log = conn.execute(
        "SELECT * FROM activity_log WHERE org_id = ? ORDER BY timestamp DESC LIMIT 50", (org_id,)
    ).fetchall()
    conn.close()
    return jsonify([dict(row) for row in log])


@app.route("/playbooks")
@login_required
def playbooks():
    pb_dir = ROOT / "playbooks"
    available = []
    if pb_dir.is_dir():
        for f in sorted(pb_dir.glob("*.yaml")):
            available.append(f.name)
    conn = get_db()
    org_id = int(current_org_id(conn))
    from web.services.organization_policy import allowed_playbooks_for_user

    permitted = allowed_playbooks_for_user(
        conn,
        org_id=org_id,
        user_id=int(session["user_id"]),
        available=available,
    )
    conn.close()
    playbooks = [{"name": name, "path": str(pb_dir / name)} for name in permitted]
    return render_template("playbooks.html", playbooks=playbooks)


# ── Routes: Playbook Upload ──

@app.route("/playbooks/upload", methods=["POST"])
@permission_required("playbook.manage")
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

    try:
        if suffix in (".yaml", ".yml"):
            # Direct YAML parse
            import yaml
            try:
                content = Path(tmp.name).read_text(encoding="utf-8")
                parsed = yaml.safe_load(content)
                if not isinstance(parsed, dict) or "steps" not in parsed:
                    flash("Invalid playbook: must have 'steps' key", "error")
                    return redirect(url_for("playbooks"))
                # Sanitize filename to prevent path traversal
                safe_name = Path(file.filename).name
                if ".." in safe_name or "/" in safe_name or "\\" in safe_name:
                    flash("Invalid filename", "error")
                    return redirect(url_for("playbooks"))
                dest = ROOT / "playbooks" / safe_name
                dest.write_text(content, encoding="utf-8")
                file.filename = safe_name
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
            # Sanitize to prevent path traversal
            if ".." in safe_name or "/" in safe_name or "\\" in safe_name:
                flash("Invalid filename", "error")
                return redirect(url_for("playbooks"))
            dest = ROOT / "playbooks" / f"{safe_name}.yaml"
            dest.write_text(yaml.dump(result["playbook"], default_flow_style=False), encoding="utf-8")
            file.filename = f"{safe_name}.yaml"

        # Record in DB
        conn = get_db()
        conn.execute(
            "INSERT INTO activity_log (org_id, actor_id, run_id, step, status, detail) VALUES (?, ?, ?, ?, 'done', ?)",
            (current_org_id(conn), session["user_id"], None, "upload_playbook", f"Uploaded playbook: {file.filename}"),
        )
        conn.commit()
        conn.close()

        flash(f"Playbook uploaded: {file.filename}", "success")
        return redirect(url_for("playbooks"))

    finally:
        # Cleanup temp file
        Path(tmp.name).unlink(missing_ok=True)


# ── Routes: Run Approve/Reject ──

@app.route("/api/runs/<int:run_id>/approve", methods=["POST"])
@permission_required("responder.approve")
def api_run_approve(run_id: int):
    conn = get_db()
    org_id = current_org_id(conn)
    run = conn.execute("SELECT * FROM runs WHERE id = ? AND org_id = ?", (run_id, org_id)).fetchone()
    if not run:
        conn.close()
        return jsonify({"error": "not found"}), 404
    if run["requested_by"] == session["user_id"]:
        conn.close()
        return jsonify({"error": "requester cannot approve their own run"}), 403
    updated = conn.execute(
        "UPDATE runs SET status = 'approved' WHERE id = ? AND org_id = ? AND status IN ('pending', 'awaiting_approval')",
        (run_id, org_id),
    ).rowcount
    if not updated:
        conn.close()
        return jsonify({"error": "run is not awaiting approval"}), 409
    conn.execute(
        "INSERT INTO activity_log (org_id, actor_id, run_id, step, status, detail) VALUES (?, ?, ?, 'approval', 'done', 'Run approved by operator')",
        (org_id, session["user_id"], run_id),
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "approved", "run_id": run_id})


@app.route("/api/runs/<int:run_id>/reject", methods=["POST"])
@permission_required("responder.approve")
def api_run_reject(run_id: int):
    reason = request.json.get("reason", "") if request.is_json else ""
    conn = get_db()
    org_id = current_org_id(conn)
    run = conn.execute("SELECT id, requested_by FROM runs WHERE id = ? AND org_id = ?", (run_id, org_id)).fetchone()
    if not run:
        conn.close()
        return jsonify({"error": "not found"}), 404
    if run["requested_by"] == session["user_id"]:
        conn.close()
        return jsonify({"error": "requester cannot reject their own run"}), 403
    updated = conn.execute(
        "UPDATE runs SET status = 'rejected' WHERE id = ? AND org_id = ? AND status IN ('pending', 'awaiting_approval')",
        (run_id, org_id),
    ).rowcount
    if not updated:
        conn.close()
        return jsonify({"error": "run is not awaiting approval"}), 409
    conn.execute(
        "INSERT INTO activity_log (org_id, actor_id, run_id, step, status, detail) VALUES (?, ?, ?, 'approval', 'failed', ?)",
        (org_id, session["user_id"], run_id, f"Run rejected: {reason}" if reason else "Run rejected by operator"),
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "rejected", "run_id": run_id})


# ── Routes: Secrets Status & Test ──

@app.route("/api/secrets/status")
@permission_required("credential.manage")
def api_secrets_status():
    conn = get_db()
    creds = conn.execute("SELECT key_name FROM credentials WHERE org_id = ?", (current_org_id(conn),)).fetchall()
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
@permission_required("credential.manage")
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


# ── Platform connection testing ──

PLATFORM_LABELS = {
    "openai": "OpenAI",
    "thehive": "TheHive",
    "cortex": "Cortex",
    "wazuh_manager": "Wazuh Manager",
    "wazuh_indexer": "Wazuh Indexer",
    "virustotal": "VirusTotal",
    "abuseipdb": "AbuseIPDB",
    "shodan": "Shodan",
    "urlscan": "urlscan.io",
    "hybrid_analysis": "Hybrid Analysis",
    "misp": "MISP",
}


def _platform_probe(platform: str, base_url: str, api_key: str):
    """Return (url, headers, method) for a lightweight authenticated probe, or None."""
    b = (base_url or "").rstrip("/")
    if platform == "openai":
        return ("https://api.openai.com/v1/models", {"Authorization": f"Bearer {api_key}"}, "GET")
    if platform == "virustotal":
        return ("https://www.virustotal.com/api/v3/metadata", {"x-apikey": api_key}, "GET")
    if platform == "abuseipdb":
        return ("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=30",
                {"Key": api_key, "Accept": "application/json"}, "GET")
    if platform == "shodan":
        return (f"https://api.shodan.io/api-info?key={api_key}", {}, "GET")
    if platform == "urlscan":
        return ("https://urlscan.io/user/quota/", {"API-Key": api_key}, "GET")
    if platform == "hybrid_analysis":
        return ("https://www.hybrid-analysis.com/api/v2/key/current",
                {"api-key": api_key, "User-Agent": "Falcon Sandbox", "Accept": "application/json"}, "GET")
    if platform == "misp":
        return (f"{b}/servers/getPyMISPVersion.json",
                {"Authorization": api_key, "Accept": "application/json"}, "GET")
    if platform == "thehive":
        return (f"{b}/api/v1/user/current", {"Authorization": f"Bearer {api_key}"}, "GET")
    if platform == "cortex":
        return (f"{b}/api/user/current", {"Authorization": f"Bearer {api_key}"}, "GET")
    if platform == "wazuh_manager":
        return (f"{b}/manager/info", {"Authorization": f"Bearer {api_key}"}, "GET")
    if platform == "wazuh_indexer":
        return (f"{b}/", {}, "GET")
    return None


def _test_platform_connection(platform: str, base_url: str, api_key: str) -> dict[str, Any]:
    result: dict[str, Any] = {"platform": platform, "label": PLATFORM_LABELS.get(platform, platform), "status": "unknown", "message": ""}
    probe = _platform_probe(platform, base_url, api_key)
    if probe is None:
        result.update(status="skipped", message="No connectivity test available")
        return result
    url, headers, method = probe
    if platform != "wazuh_indexer" and not api_key:
        result.update(status="no_key", message="API key not configured")
        return result
    if base_url and "example.com" in base_url:
        result.update(status="not_configured", message="Base URL still set to placeholder")
        return result

    import urllib.request
    import urllib.error
    import ssl
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, method=method, headers=headers)
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        resp = opener.open(req, timeout=8)
        result.update(status="ok", http_status=resp.getcode(), message="Connected")
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            result.update(status="auth_failed", http_status=e.code, message="Reachable, but authentication failed")
        elif e.code in (400, 404, 405, 429):
            result.update(status="reachable", http_status=e.code, message=f"Server responded ({e.code})")
        else:
            result.update(status="error", http_status=e.code, message=f"HTTP {e.code}")
    except Exception as e:
        result.update(status="unreachable", message=str(e)[:200])
    return result


@app.route("/api/secrets/test-all", methods=["POST"])
@permission_required("credential.manage")
def api_secrets_test_all():
    conn = get_db()
    org_id = current_org_id(conn)
    creds = {row["key_name"]: open_secret(row["key_value"]) for row in conn.execute("SELECT key_name, key_value FROM credentials WHERE org_id = ?", (org_id,)).fetchall()}
    platform_cfg = {row["platform"]: row["base_url"] for row in conn.execute("SELECT platform, base_url FROM platform_config WHERE org_id = ?", (org_id,)).fetchall()}
    conn.close()

    key_for_platform = {plat: kn for kn, plat in PLATFORM_CREDENTIAL_KEYS if plat}
    results = [_test_platform_connection("openai", "", creds.get("OPENAI_API_KEY", ""))]
    for platform in PLATFORM_DEFAULTS:
        key_name = key_for_platform.get(platform)
        api_key = creds.get(key_name, "") if key_name else ""
        results.append(_test_platform_connection(platform, platform_cfg.get(platform, ""), api_key))

    ok = sum(1 for r in results if r["status"] == "ok")
    return jsonify({"results": results, "summary": {"total": len(results), "ok": ok}})


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


from web.routes.chat import chat_bp
from scripts.webhooks import webhooks_bp
from web.routes.features import features_bp
from web.routes.export import export_bp
from web.routes.operations import operations_bp
from web.routes.admin import admin_bp

app.register_blueprint(chat_bp)
app.register_blueprint(webhooks_bp)
app.register_blueprint(features_bp)
app.register_blueprint(export_bp)
app.register_blueprint(operations_bp)
app.register_blueprint(admin_bp)

# WSGI imports must initialize the schema too; production servers do not execute __main__.
init_db()


if __name__ == "__main__":
    # Opt-in Wazuh alert poller -- only starts when WAZUH_POLL_ENABLED is set.
    if os.environ.get("WAZUH_POLL_ENABLED", "").lower() in {"1", "true", "yes", "on"}:
        from web.services.wazuh_poller import get_poller
        get_poller().start()

    ip = get_local_ip()
    port = int(os.environ.get("AI_SOC_PORT", "5000"))
    if not 1 <= port <= 65535:
        raise ValueError("AI_SOC_PORT must be between 1 and 65535")
    print(f"\n{'='*50}")
    print(f"  AI SOC Operator")
    print(f"  Local:   http://localhost:{port}")
    print(f"  Network: http://{ip}:{port}")
    print(f"{'='*50}\n")
    # Debug mode can expose an interactive traceback, so it is opt-in even in
    # local development and must never be inferred from the bind address.
    debug = os.environ.get("AI_SOC_FLASK_DEBUG", "").lower() in {"1", "true", "yes"}
    app.run(host=os.environ.get("AI_SOC_BIND", "127.0.0.1"), port=port, debug=debug)
