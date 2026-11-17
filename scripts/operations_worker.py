"""Production operations worker for notifications, SLA scans, and approvals."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import time
from pathlib import Path

from scripts.common import ROOT, audit
from scripts.job_queue import JobQueue
from web.services.capabilities import execute_capability_proposal
from web.services.credential_vault import open_secret
from web.services.database import connect_database
from web.services.distributed_lock import acquire_lease, init_lock_schema, release_lease
from web.services.external_sync import sync_misp_events, sync_thehive_cases
from web.services.notifications import dispatch_pending, notify_case_event
from web.services.playbook_jobs import dispatch_playbook_job
from web.services.schema_features import init_feature_db

DB_PATH = ROOT / "data" / "soc_operator.db"
_LAST_EXTERNAL_SYNC: dict[int | None, float] = {}


def connect(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = connect_database(db_path)
    init_feature_db(conn)
    init_lock_schema(conn)
    return conn


def scan_workflow_notifications(conn: sqlite3.Connection, org_id: int | None = None) -> int:
    queued = 0
    org_params = (org_id,) if org_id is not None else ()
    case_query = "SELECT id, org_id, title, severity FROM cases WHERE status != 'closed' AND severity IN ('high', 'critical')"
    job_query = "SELECT id, org_id, error_message FROM jobs WHERE status = 'failed' AND org_id IS NOT NULL"
    if org_id is not None:
        case_query += " AND org_id = ?"  # nosec B608 - fixed tenant predicate; value remains parameterized.
        job_query += " AND org_id = ?"  # nosec B608 - fixed tenant predicate; value remains parameterized.
    for case in conn.execute(
        case_query,
        org_params,
    ).fetchall():
        notify_case_event(
            conn,
            org_id=int(case["org_id"]),
            event_type="high_severity_case",
            severity=case["severity"],
            message=f"{case['severity'].upper()} case {case['id']}: {case['title']}",
            metadata={"case_id": case["id"]},
            dedup_key=f"case:{case['id']}:high",
        )
        queued += 1
    for job in conn.execute(
        job_query,
        org_params,
    ).fetchall():
        notify_case_event(
            conn,
            org_id=int(job["org_id"]),
            event_type="job_failed",
            severity="high",
            message=f"Job {job['id']} failed: {job['error_message'] or 'unknown error'}",
            metadata={"job_id": job["id"]},
            dedup_key=f"job:{job['id']}:failed",
        )
        queued += 1
    warning_minutes = max(1, int(os.environ.get("AI_SOC_SLA_WARNING_MINUTES", "60")))
    sla_query = """
        SELECT id, org_id, title, sla_due_at,
               CASE WHEN sla_due_at <= CURRENT_TIMESTAMP THEN 1 ELSE 0 END AS breached
        FROM cases
        WHERE status != 'closed' AND sla_due_at IS NOT NULL
          AND sla_due_at <= datetime('now', ?)
    """
    if org_id is not None:
        sla_query += " AND org_id = ?"  # nosec B608 - fixed tenant predicate; value remains parameterized.
    for case in conn.execute(
        sla_query,
        (f"+{warning_minutes} minutes", *org_params),
    ).fetchall():
        event_type = "sla_breach" if case["breached"] else "sla_warning"
        notify_case_event(
            conn,
            org_id=int(case["org_id"]),
            event_type=event_type,
            severity="critical" if case["breached"] else "high",
            message=f"Case {case['id']} {event_type.replace('_', ' ')}: {case['title']}",
            metadata={"case_id": case["id"], "sla_due_at": case["sla_due_at"]},
            dedup_key=f"case:{case['id']}:{event_type}",
        )
        queued += 1
    conn.commit()
    return queued


def execute_approved_capabilities(conn: sqlite3.Connection, limit: int = 10, org_id: int | None = None) -> list[dict]:
    params = (org_id, limit) if org_id is not None else (limit,)
    capability_query = """
        SELECT id, org_id FROM capability_proposals
        WHERE status = 'approved' AND approval_expires_at > CURRENT_TIMESTAMP
    """
    if org_id is not None:
        capability_query += " AND org_id = ?"  # nosec B608 - fixed tenant predicate.
    capability_query += " ORDER BY approved_at LIMIT ?"
    rows = conn.execute(
        capability_query,
        params,
    ).fetchall()
    results = []
    for row in rows:
        results.append(execute_capability_proposal(conn, int(row["id"]), org_id=int(row["org_id"])))
        conn.commit()
    return results


def recover_stale_capabilities(conn: sqlite3.Connection, org_id: int | None = None) -> int:
    """Fail closed when a worker died after claiming a capability proposal."""
    recovery_query = """
        UPDATE capability_proposals
        SET status = 'failed', result_json = ?, updated_at = CURRENT_TIMESTAMP
        WHERE status = 'executing' AND updated_at < datetime('now', '-15 minutes')
    """
    if org_id is not None:
        recovery_query += " AND org_id = ?"  # nosec B608 - fixed tenant predicate.
    result = conn.execute(
        recovery_query,
        (json.dumps({"ok": False, "error": "execution worker stopped before completion"}), *((org_id,) if org_id is not None else ())),
    )
    conn.commit()
    return int(result.rowcount)


def synchronize_external_platforms(conn, org_id: int | None = None) -> list[dict]:
    """Pull configured TheHive cases and MISP events with idempotent mappings."""
    if os.environ.get("AI_SOC_EXTERNAL_SYNC", "1").lower() not in {"1", "true", "yes"}:
        return []
    interval = max(30, int(os.environ.get("AI_SOC_EXTERNAL_SYNC_INTERVAL", "300")))
    if time.monotonic() - _LAST_EXTERNAL_SYNC.get(org_id, 0.0) < interval:
        return []
    _LAST_EXTERNAL_SYNC[org_id] = time.monotonic()
    from scripts.orchestrator import build_clients
    from web.app import load_config_for_web

    results: list[dict] = []
    organizations = ([{"id": org_id}] if org_id is not None else conn.execute("SELECT id FROM organizations ORDER BY id").fetchall())
    for organization in organizations:
        current_org_id = int(organization["id"])
        if hasattr(conn, "set_tenant_context"):
            conn.set_tenant_context(current_org_id)
        credentials = {
            row["key_name"]: open_secret(row["key_value"])
            for row in conn.execute(
                "SELECT key_name, key_value FROM credentials WHERE org_id = ?", (current_org_id,)
            ).fetchall()
        }
        clients = build_clients(load_config_for_web(current_org_id), credentials=credentials)
        for platform, syncer in (("thehive", sync_thehive_cases), ("misp", sync_misp_events)):
            client = clients.get(platform)
            if not client:
                continue
            lease_name = f"external-sync:{current_org_id}:{platform}"
            lease = acquire_lease(conn, lease_name, ttl_seconds=max(interval, 60))
            if not lease:
                continue
            try:
                results.append(
                    syncer(
                        conn,
                        org_id=current_org_id,
                        client=client,
                        limit=max(1, int(os.environ.get("AI_SOC_EXTERNAL_SYNC_LIMIT", "5000"))),
                    )
                )
                conn.commit()
            # Integration adapters are isolated so one unavailable platform cannot stop the worker.
            except Exception as exc:  # noqa: BLE001
                conn.commit()  # Preserve the integration error state for operators.
                audit("external_sync_failed", org_id=current_org_id, platform=platform, error=str(exc)[:500])
            finally:
                release_lease(conn, lease_name, lease)
    return results


def run_once(db_path: Path = DB_PATH) -> dict:
    # JobQueue owns the jobs schema, so initialize it before notification scans
    # on a brand-new deployment.
    queue = JobQueue(db_path)
    conn = connect(db_path)
    try:
        queued = 0
        stale_capabilities = 0
        capabilities: list[dict] = []
        integrations: list[dict] = []
        notifications: list[dict] = []
        organizations = conn.execute("SELECT id FROM organizations ORDER BY id").fetchall()
        org_ids = [int(organization["id"]) for organization in organizations]
        for org_id in org_ids:
            if hasattr(conn, "set_tenant_context"):
                conn.set_tenant_context(org_id)
            queued += scan_workflow_notifications(conn, org_id)
            stale_capabilities += recover_stale_capabilities(conn, org_id)
            capabilities.extend(execute_approved_capabilities(conn, org_id=org_id))
            integrations.extend(synchronize_external_platforms(conn, org_id))
            notifications.extend(dispatch_pending(conn, limit=50, org_id=org_id))
        conn.execute(
            """
            INSERT INTO operations_state (component, heartbeat_at, details_json)
            VALUES ('operations_worker', CURRENT_TIMESTAMP, ?)
            ON CONFLICT(component) DO UPDATE SET
                heartbeat_at = CURRENT_TIMESTAMP, details_json = excluded.details_json
            """,
            (json.dumps({"notifications": len(notifications), "capabilities": len(capabilities), "integrations": len(integrations)}),),
        )
        conn.commit()
    finally:
        conn.close()
    # Recovered jobs must be redelivered or they remain queued indefinitely.
    recovered = sum(
        queue.recover_stale_jobs(
            lambda job_id, tenant_id=org_id: dispatch_playbook_job(queue, job_id, tenant_id),
            org_id=org_id,
        )
        for org_id in org_ids
    )
    result = {
        "queued_notifications": queued,
        "dispatched_notifications": len(notifications),
        "executed_capabilities": len(capabilities),
        "recovered_capabilities": stale_capabilities,
        "recovered_jobs": recovered,
        "synchronized_integrations": len(integrations),
    }
    audit("operations_worker_cycle", **result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="AI SOC Operator operations worker")
    parser.add_argument("--once", action="store_true", help="Run one cycle and exit")
    parser.add_argument("--interval", type=int, default=int(os.environ.get("AI_SOC_WORKER_INTERVAL", "30")))
    args = parser.parse_args()
    if args.once:
        print(run_once())
        return 0
    while True:
        try:
            run_once()
        # The daemon loop records unexpected failures and retries on its next bounded interval.
        except Exception as exc:  # noqa: BLE001
            audit("operations_worker_error", error=str(exc)[:500])
        time.sleep(max(5, args.interval))


if __name__ == "__main__":
    raise SystemExit(main())
