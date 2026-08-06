"""Schema additions for SOC platform features.

This module is intentionally SQLite-first for the v1 local deployment, while
adding nullable org_id columns so future tenant isolation has a clean path.
"""

from __future__ import annotations

FEATURE_SCHEMA = """
-- Feature 1: Alert ingestion
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER,
    source TEXT NOT NULL,
    source_alert_id TEXT,
    case_id INTEGER,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    raw_payload TEXT NOT NULL,
    normalized_payload TEXT,
    status TEXT DEFAULT 'new',
    selected_playbook TEXT,
    job_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    queued_at TIMESTAMP,
    first_response_at TIMESTAMP,
    closed_at TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id)
);

-- Feature 2: RBAC
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    permissions TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS user_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_roles_unique
    ON user_roles(user_id, role_id);

-- Feature 3: Credential health (add columns to existing credentials table)
-- ALTER TABLE credentials ADD COLUMN last_tested_at TIMESTAMP;
-- ALTER TABLE credentials ADD COLUMN last_test_result TEXT DEFAULT 'unknown';
-- ALTER TABLE credentials ADD COLUMN last_test_message TEXT;
-- ALTER TABLE credentials ADD COLUMN active INTEGER DEFAULT 1;
-- ALTER TABLE credentials ADD COLUMN provider TEXT DEFAULT '';
-- Note: SQLite doesn't support ALTER ADD COLUMN IF NOT EXISTS,
-- so we handle this in code with try/except.

-- Feature 5: Case assignment + SLA
-- Cases table already has: id, title, severity, status, summary, created_at
-- Add: assignee_id, opened_at, closed_at

-- Feature 6: IOC correlation
CREATE TABLE IF NOT EXISTS observables (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER,
    alert_id INTEGER,
    case_id INTEGER,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT,
    metadata_json TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (alert_id) REFERENCES alerts(id),
    FOREIGN KEY (case_id) REFERENCES cases(id)
);

CREATE TABLE IF NOT EXISTS responder_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER,
    case_id INTEGER,
    action_type TEXT NOT NULL,
    target TEXT NOT NULL,
    platform TEXT NOT NULL,
    risk_tier INTEGER NOT NULL DEFAULT 3,
    status TEXT NOT NULL DEFAULT 'proposed',
    requested_by INTEGER,
    approved_by INTEGER,
    preview_json TEXT NOT NULL,
    result_json TEXT,
    rollback_note TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approved_at TIMESTAMP,
    executed_at TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id)
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    channel TEXT NOT NULL DEFAULT 'console',
    status TEXT NOT NULL DEFAULT 'pending',
    message TEXT NOT NULL,
    metadata_json TEXT DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_observables_value ON observables(value);
CREATE INDEX IF NOT EXISTS idx_observables_case_id ON observables(case_id);
CREATE INDEX IF NOT EXISTS idx_observables_alert_id ON observables(alert_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_case_id ON alerts(case_id);
CREATE INDEX IF NOT EXISTS idx_alerts_job_id ON alerts(job_id);
CREATE INDEX IF NOT EXISTS idx_responder_actions_case_id ON responder_actions(case_id);
"""


def init_feature_db(conn) -> None:
    """Initialize feature tables. Safe to call multiple times."""
    conn.executescript(FEATURE_SCHEMA)

    _add_missing_columns(
        conn,
        "alerts",
        {
            "org_id": "INTEGER",
            "selected_playbook": "TEXT",
            "job_id": "TEXT",
            "queued_at": "TIMESTAMP",
            "first_response_at": "TIMESTAMP",
            "closed_at": "TIMESTAMP",
        },
    )

    _add_missing_columns(
        conn,
        "observables",
        {
            "org_id": "INTEGER",
            "alert_id": "INTEGER",
            "metadata_json": "TEXT",
            "first_seen": "TIMESTAMP",
            "last_seen": "TIMESTAMP",
        },
    )

    # Add columns to existing credentials table if missing.
    existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(credentials)").fetchall()}
    alter_statements = []
    if "last_tested_at" not in existing_cols:
        alter_statements.append("ALTER TABLE credentials ADD COLUMN last_tested_at TIMESTAMP")
    if "last_test_result" not in existing_cols:
        alter_statements.append("ALTER TABLE credentials ADD COLUMN last_test_result TEXT DEFAULT 'unknown'")
    if "last_test_message" not in existing_cols:
        alter_statements.append("ALTER TABLE credentials ADD COLUMN last_test_message TEXT")
    if "active" not in existing_cols:
        alter_statements.append("ALTER TABLE credentials ADD COLUMN active INTEGER DEFAULT 1")
    if "provider" not in existing_cols:
        alter_statements.append("ALTER TABLE credentials ADD COLUMN provider TEXT DEFAULT ''")
    for stmt in alter_statements:
        try:
            conn.execute(stmt)
        except Exception:
            pass  # Column may already exist

    _add_missing_columns(
        conn,
        "cases",
        {
            "org_id": "INTEGER",
            "assignee_id": "INTEGER",
            "opened_at": "TIMESTAMP",
            "closed_at": "TIMESTAMP",
            "first_response_at": "TIMESTAMP",
            "sla_due_at": "TIMESTAMP",
        },
    )
    conn.execute("UPDATE cases SET opened_at = created_at WHERE opened_at IS NULL")

    # Seed default roles if empty
    import json
    default_roles = [
        ("admin", ["chat.read", "chat.act", "case.assign", "case.update", "case.close", "credential.manage", "alert.ingest", "report.export", "tool.execute", "responder.approve", "responder.execute", "role.manage"]),
        ("manager", ["chat.read", "case.assign", "case.update", "case.close", "alert.ingest", "report.export", "sla.view"]),
        ("senior_analyst", ["chat.read", "chat.act", "case.assign", "case.update", "case.close", "alert.ingest", "report.export", "tool.execute", "responder.approve"]),
        ("analyst", ["chat.read", "chat.act", "case.update", "alert.ingest", "report.export"]),
        ("read_only", ["chat.read", "report.export"]),
    ]
    for name, perms in default_roles:
        conn.execute(
            "INSERT OR IGNORE INTO roles (name, permissions) VALUES (?, ?)",
            (name, json.dumps(perms)),
        )

    conn.commit()


def ensure_admin_role(conn, user_id: int) -> None:
    """Assign the admin role to a user if they do not already have it."""
    init_feature_db(conn)
    role = conn.execute("SELECT id FROM roles WHERE name = 'admin'").fetchone()
    if not role:
        return
    conn.execute(
        "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
        (user_id, role["id"]),
    )
    conn.commit()


def _add_missing_columns(conn, table: str, columns: dict[str, str]) -> None:
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    for name, definition in columns.items():
        if name in existing:
            continue
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
        except Exception:
            pass
