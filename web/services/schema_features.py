"""Schema additions for features 1-6: alerts, RBAC, credentials, observables, case assignment."""

from __future__ import annotations

FEATURE_SCHEMA = """
-- Feature 1: Alert ingestion
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    source_alert_id TEXT,
    case_id INTEGER,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    raw_payload TEXT NOT NULL,
    normalized_payload TEXT,
    status TEXT DEFAULT 'new',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
    case_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT,
    metadata_json TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id)
);

CREATE INDEX IF NOT EXISTS idx_observables_value ON observables(value);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_case_id ON alerts(case_id);
"""


def init_feature_db(conn) -> None:
    """Initialize feature tables. Safe to call multiple times."""
    conn.executescript(FEATURE_SCHEMA)

    # Add columns to existing credentials table if missing
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

    # Add columns to cases table if missing
    existing_case_cols = {row[1] for row in conn.execute("PRAGMA table_info(cases)").fetchall()}
    if "assignee_id" not in existing_case_cols:
        try:
            conn.execute("ALTER TABLE cases ADD COLUMN assignee_id INTEGER")
        except Exception:
            pass
    if "opened_at" not in existing_case_cols:
        try:
            conn.execute("ALTER TABLE cases ADD COLUMN opened_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
        except Exception:
            pass
    if "closed_at" not in existing_case_cols:
        try:
            conn.execute("ALTER TABLE cases ADD COLUMN closed_at TIMESTAMP")
        except Exception:
            pass

    # Seed default roles if empty
    role_count = conn.execute("SELECT COUNT(*) FROM roles").fetchone()[0]
    if role_count == 0:
        import json
        default_roles = [
            ("admin", json.dumps(["chat.read", "chat.act", "case.assign", "case.update", "case.close", "credential.manage", "alert.ingest", "report.export", "tool.execute"])),
            ("senior_analyst", json.dumps(["chat.read", "chat.act", "case.assign", "case.update", "case.close", "alert.ingest", "report.export", "tool.execute"])),
            ("analyst", json.dumps(["chat.read", "chat.act", "case.update", "alert.ingest", "report.export"])),
        ]
        for name, perms in default_roles:
            conn.execute("INSERT INTO roles (name, permissions) VALUES (?, ?)", (name, perms))

    conn.commit()
