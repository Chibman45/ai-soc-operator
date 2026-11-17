"""Install PostgreSQL tenant isolation policies for organization-owned tables."""

from __future__ import annotations

import argparse
import os
import re

from web.services.database import PostgresConnection

TENANT_TABLES = (
    "activity_log", "ai_provider_config", "alert_assessments", "alert_verdicts", "alerts",
    "api_clients", "capability_proposals", "cases", "chat_actions", "chat_threads", "codex_device_sessions",
    "configuration_snapshots", "credentials",
    "dl_approvals", "dl_corpora", "dl_corpus_samples", "dl_deployments", "dl_drift_windows",
    "dl_org_keys", "dl_replay_results", "dl_replay_runs", "dl_rollback_events", "dl_rule_artifacts",
    "document_ingestions", "external_objects", "ground_truth_events", "infrastructure_migrations",
    "infrastructure_settings", "integration_sync_state", "intel_events", "jobs", "notifications", "observables", "organization_architecture_drafts",
    "organization_architecture_profiles", "organization_policies", "organization_policy_drafts",
    "platform_config", "playbook_drafts", "responder_actions", "responder_capabilities", "rule_recommendations",
    "runs", "user_invitations", "user_roles",
)


def policy_statements(table: str) -> tuple[str, str, str]:
    if not re.fullmatch(r"[a-z][a-z0-9_]*", table):
        raise ValueError("unsafe table name")
    expression = "org_id = NULLIF(current_setting('app.current_org_id', true), '')::bigint"
    return (
        f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY',
        f'DROP POLICY IF EXISTS ai_soc_tenant_isolation ON "{table}"',
        f'CREATE POLICY ai_soc_tenant_isolation ON "{table}" USING ({expression}) WITH CHECK ({expression})',
    )


def install_rls(conn, tables: tuple[str, ...] = TENANT_TABLES) -> list[str]:
    installed: list[str] = []
    for table in tables:
        exists = conn.execute(
            "SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ? AND column_name = 'org_id'",
            (table,),
        ).fetchone()
        if not exists:
            continue
        for statement in policy_statements(table):
            conn.execute(statement)
        installed.append(table)
    conn.commit()
    return installed


def main() -> int:
    parser = argparse.ArgumentParser(description="Install tenant RLS policies in PostgreSQL")
    parser.add_argument("--dsn-env", default="AI_SOC_POSTGRES_ADMIN_DSN", help="Environment variable containing the administrative DSN")
    args = parser.parse_args()
    dsn = os.environ.get(args.dsn_env, "").strip()
    if not dsn:
        parser.error(f"{args.dsn_env} is not set")
    conn = PostgresConnection(dsn)
    try:
        installed = install_rls(conn)
    finally:
        conn.close()
    print(f"Installed tenant isolation on {len(installed)} tables")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
