"""Schema additions for SOC platform features.

This module is intentionally SQLite-first for the v1 local deployment, while
adding nullable org_id columns so future tenant isolation has a clean path.
"""

from __future__ import annotations

FEATURE_SCHEMA = """
-- Production identity boundary: every operational record belongs to an organization.
CREATE TABLE IF NOT EXISTS organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS organization_memberships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizations(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE(org_id, user_id)
);

CREATE TABLE IF NOT EXISTS api_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    scopes_json TEXT NOT NULL DEFAULT '[]',
    active INTEGER NOT NULL DEFAULT 1,
    created_by INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizations(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ip_address TEXT,
    succeeded INTEGER NOT NULL DEFAULT 0,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_invitations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    created_by INTEGER NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizations(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS organization_policy_drafts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    source_name TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    evidence_path TEXT NOT NULL,
    extracted_json TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    extraction_model TEXT,
    status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft', 'approved', 'rejected')),
    created_by INTEGER NOT NULL,
    approved_by INTEGER,
    approved_at TIMESTAMP,
    rejected_by INTEGER,
    rejected_at TIMESTAMP,
    rejection_reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizations(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (approved_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS organization_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    version INTEGER NOT NULL,
    policy_json TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    source_draft_id INTEGER NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    approved_by INTEGER NOT NULL,
    approved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, version),
    FOREIGN KEY (org_id) REFERENCES organizations(id),
    FOREIGN KEY (source_draft_id) REFERENCES organization_policy_drafts(id),
    FOREIGN KEY (approved_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS api_rate_limits (
    bucket_key TEXT NOT NULL,
    window_start TIMESTAMP NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_key, window_start)
);

CREATE TABLE IF NOT EXISTS operations_state (
    component TEXT PRIMARY KEY,
    heartbeat_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    details_json TEXT NOT NULL DEFAULT '{}'
);

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
    org_id INTEGER,
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
    approval_digest TEXT,
    approval_expires_at TIMESTAMP,
    rejected_by INTEGER,
    rejected_at TIMESTAMP,
    rejection_reason TEXT,
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

CREATE TABLE IF NOT EXISTS capability_proposals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    reason TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'ai',
    manifest_json TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'proposed',
    requested_by INTEGER,
    approved_by INTEGER,
    approved_at TIMESTAMP,
    approval_expires_at TIMESTAMP,
    executed_at TIMESTAMP,
    rejected_by INTEGER,
    rejected_at TIMESTAMP,
    rejection_reason TEXT,
    result_json TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizations(id),
    FOREIGN KEY (requested_by) REFERENCES users(id),
    FOREIGN KEY (approved_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS responder_capabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    responder_type TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    enabled_by_proposal_id INTEGER,
    enabled_at TIMESTAMP,
    config_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(org_id, responder_type),
    FOREIGN KEY (org_id) REFERENCES organizations(id),
    FOREIGN KEY (enabled_by_proposal_id) REFERENCES capability_proposals(id)
);

CREATE INDEX IF NOT EXISTS idx_observables_value ON observables(value);
CREATE INDEX IF NOT EXISTS idx_observables_case_id ON observables(case_id);
CREATE INDEX IF NOT EXISTS idx_observables_alert_id ON observables(alert_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_case_id ON alerts(case_id);
CREATE INDEX IF NOT EXISTS idx_alerts_job_id ON alerts(job_id);
CREATE INDEX IF NOT EXISTS idx_responder_actions_case_id ON responder_actions(case_id);
CREATE INDEX IF NOT EXISTS idx_memberships_user_org ON organization_memberships(user_id, org_id);
CREATE INDEX IF NOT EXISTS idx_api_clients_org ON api_clients(org_id);
CREATE INDEX IF NOT EXISTS idx_login_attempts_window ON login_attempts(username, ip_address, attempted_at);
CREATE INDEX IF NOT EXISTS idx_user_invitations_org_user ON user_invitations(org_id, user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_org_policy_drafts_status ON organization_policy_drafts(org_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_org_policies_active ON organization_policies(org_id, active, version);
CREATE INDEX IF NOT EXISTS idx_notifications_delivery ON notifications(status, created_at);
CREATE INDEX IF NOT EXISTS idx_capability_proposals_org_status ON capability_proposals(org_id, status, created_at);
"""


def init_feature_db(conn) -> None:
    """Initialize feature tables. Safe to call multiple times."""
    conn.executescript(FEATURE_SCHEMA)

    _add_missing_columns(
        conn,
        "users",
        {
            "default_org_id": "INTEGER",
            "password_changed_at": "TIMESTAMP",
            "disabled_at": "TIMESTAMP",
            "display_name": "TEXT",
            "email": "TEXT",
            "must_change_password": "INTEGER NOT NULL DEFAULT 0",
            "session_version": "INTEGER NOT NULL DEFAULT 0",
        },
    )
    _add_missing_columns(conn, "user_roles", {"org_id": "INTEGER", "source": "TEXT NOT NULL DEFAULT 'manual'", "policy_id": "INTEGER"})
    _add_missing_columns(conn, "credentials", {"org_id": "INTEGER"})
    _add_missing_columns(conn, "platform_config", {"org_id": "INTEGER"})
    _add_missing_columns(
        conn,
        "runs",
        {
            "org_id": "INTEGER",
            "requested_by": "INTEGER",
            "idempotency_key": "TEXT",
            "current_step": "TEXT",
            "cancel_requested": "INTEGER DEFAULT 0",
            "first_response_at": "TIMESTAMP",
        },
    )
    _add_missing_columns(conn, "activity_log", {"org_id": "INTEGER", "actor_id": "INTEGER", "request_id": "TEXT"})

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
        "responder_actions",
        {
            "approval_digest": "TEXT",
            "approval_expires_at": "TIMESTAMP",
            "rejected_by": "INTEGER",
            "rejected_at": "TIMESTAMP",
            "rejection_reason": "TEXT",
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

    _add_missing_columns(
        conn,
        "notifications",
        {
            "attempt_count": "INTEGER NOT NULL DEFAULT 0",
            "max_attempts": "INTEGER NOT NULL DEFAULT 5",
            "next_attempt_at": "TIMESTAMP",
            "last_error": "TEXT",
            "dedup_key": "TEXT",
            "dead_lettered_at": "TIMESTAMP",
        },
    )
    # This index must be created after upgrading older notification tables that
    # did not yet have the deduplication column.
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_notifications_org_dedup "
        "ON notifications(org_id, dedup_key) WHERE dedup_key IS NOT NULL"
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
        ("admin", ["chat.read", "chat.act", "case.assign", "case.update", "case.close", "credential.manage", "alert.ingest", "report.export", "tool.execute", "responder.approve", "responder.execute", "role.manage", "user.manage", "policy.manage", "policy.approve", "playbook.manage", "learning.review", "api_client.manage", "sla.view", "notification.manage", "capability.propose", "capability.approve", "capability.execute"]),
        ("manager", ["chat.read", "case.assign", "case.update", "case.close", "alert.ingest", "report.export", "sla.view", "learning.review", "notification.manage", "capability.approve"]),
        ("senior_analyst", ["chat.read", "chat.act", "case.assign", "case.update", "case.close", "alert.ingest", "report.export", "tool.execute", "responder.approve", "learning.review", "sla.view", "capability.propose"]),
        ("analyst", ["chat.read", "chat.act", "case.update", "alert.ingest", "report.export"]),
        ("read_only", ["chat.read", "report.export"]),
    ]
    for name, perms in default_roles:
        conn.execute(
            "INSERT INTO roles (name, permissions) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET permissions = excluded.permissions",
            (name, json.dumps(perms)),
        )

    # Existing single-user installations are migrated into a default organization.
    default_org = conn.execute("SELECT id FROM organizations ORDER BY id LIMIT 1").fetchone()
    if not default_org:
        cursor = conn.execute("INSERT INTO organizations (name, slug) VALUES ('Default Organization', 'default')")
        default_org_id = int(cursor.lastrowid)
    else:
        default_org_id = int(default_org["id"])
    conn.execute("UPDATE users SET default_org_id = ? WHERE default_org_id IS NULL", (default_org_id,))
    conn.execute(
        """
        INSERT OR IGNORE INTO organization_memberships (org_id, user_id)
        SELECT COALESCE(default_org_id, ?), id FROM users
        """,
        (default_org_id,),
    )
    conn.execute("UPDATE user_roles SET org_id = ? WHERE org_id IS NULL", (default_org_id,))
    for table in ("credentials", "platform_config", "runs", "cases", "alerts", "observables", "responder_actions", "notifications", "activity_log"):
        try:
            conn.execute(f"UPDATE {table} SET org_id = ? WHERE org_id IS NULL", (default_org_id,))
        except Exception:
            pass

    # The original indexes were single-organization; rebuild them around tenant identity.
    conn.execute("DROP INDEX IF EXISTS idx_user_roles_unique")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_roles_unique ON user_roles(org_id, user_id, role_id)")
    _migrate_platform_config_unique_key(conn)

    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_runs_idempotency ON runs(org_id, idempotency_key) WHERE idempotency_key IS NOT NULL")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_source_unique ON alerts(org_id, source, source_alert_id) WHERE source_alert_id IS NOT NULL")

    # Bootstrap predates RBAC. Grant the first legacy account initial admin
    # only while the installation has no role assignments of any kind.
    first_user = conn.execute("SELECT id, default_org_id FROM users ORDER BY id LIMIT 1").fetchone()
    assigned_roles = conn.execute("SELECT COUNT(*) FROM user_roles").fetchone()[0]
    admin_role = conn.execute("SELECT id FROM roles WHERE name = 'admin'").fetchone()
    if first_user and admin_role and assigned_roles == 0:
        conn.execute(
            "INSERT INTO user_roles (user_id, role_id, org_id) VALUES (?, ?, ?)",
            (first_user["id"], admin_role["id"], first_user["default_org_id"]),
        )

    conn.commit()


def ensure_admin_role(conn, user_id: int, org_id: int | None = None) -> None:
    """Assign the admin role to a user if they do not already have it."""
    init_feature_db(conn)
    role = conn.execute("SELECT id FROM roles WHERE name = 'admin'").fetchone()
    if not role:
        return
    if org_id is None:
        user = conn.execute("SELECT default_org_id FROM users WHERE id = ?", (user_id,)).fetchone()
        org_id = int(user["default_org_id"]) if user and user["default_org_id"] else None
    conn.execute(
        "INSERT OR IGNORE INTO user_roles (user_id, role_id, org_id) VALUES (?, ?, ?)",
        (user_id, role["id"], org_id),
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


def _migrate_platform_config_unique_key(conn) -> None:
    row = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'platform_config'").fetchone()
    sql = str(row["sql"] if row else "").lower().replace("\n", " ")
    if "platform text unique" not in sql:
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_platform_config_org_platform ON platform_config(org_id, platform)")
        return
    conn.executescript(
        """
        ALTER TABLE platform_config RENAME TO platform_config_legacy;
        CREATE TABLE platform_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            platform TEXT NOT NULL,
            base_url TEXT,
            enabled INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(org_id, platform),
            FOREIGN KEY (org_id) REFERENCES organizations(id)
        );
        INSERT INTO platform_config (id, org_id, platform, base_url, enabled, updated_at)
        SELECT id, org_id, platform, base_url, enabled, updated_at FROM platform_config_legacy;
        DROP TABLE platform_config_legacy;
        """
    )
