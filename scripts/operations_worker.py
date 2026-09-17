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
from web.services.notifications import dispatch_pending, notify_case_event
from web.services.schema_features import init_feature_db


DB_PATH = ROOT / "data" / "soc_operator.db"


def connect(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    init_feature_db(conn)
    return conn


def scan_workflow_notifications(conn: sqlite3.Connection) -> int:
    queued = 0
    for case in conn.execute(
        "SELECT id, org_id, title, severity FROM cases WHERE status != 'closed' AND severity IN ('high', 'critical')"
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
        "SELECT id, org_id, error_message FROM jobs WHERE status = 'failed' AND org_id IS NOT NULL"
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
    for case in conn.execute(
        """
        SELECT id, org_id, title, sla_due_at,
               CASE WHEN sla_due_at <= CURRENT_TIMESTAMP THEN 1 ELSE 0 END AS breached
        FROM cases
        WHERE status != 'closed' AND sla_due_at IS NOT NULL
          AND sla_due_at <= datetime('now', ?)
        """,
        (f"+{warning_minutes} minutes",),
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


def execute_approved_capabilities(conn: sqlite3.Connection, limit: int = 10) -> list[dict]:
    rows = conn.execute(
        """
        SELECT id, org_id FROM capability_proposals
        WHERE status = 'approved' AND approval_expires_at > CURRENT_TIMESTAMP
        ORDER BY approved_at LIMIT ?
        """,
        (limit,),
    ).fetchall()
    results = []
    for row in rows:
        results.append(execute_capability_proposal(conn, int(row["id"]), org_id=int(row["org_id"])))
        conn.commit()
    return results


def recover_stale_capabilities(conn: sqlite3.Connection) -> int:
    """Fail closed when a worker died after claiming a capability proposal."""
    result = conn.execute(
        """
        UPDATE capability_proposals
        SET status = 'failed', result_json = ?, updated_at = CURRENT_TIMESTAMP
        WHERE status = 'executing' AND updated_at < datetime('now', '-15 minutes')
        """,
        (json.dumps({"ok": False, "error": "execution worker stopped before completion"}),),
    )
    conn.commit()
    return int(result.rowcount)


def run_once(db_path: Path = DB_PATH) -> dict:
    # JobQueue owns the jobs schema, so initialize it before notification scans
    # on a brand-new deployment.
    queue = JobQueue(db_path)
    conn = connect(db_path)
    try:
        queued = scan_workflow_notifications(conn)
        stale_capabilities = recover_stale_capabilities(conn)
        capabilities = execute_approved_capabilities(conn)
        notifications = dispatch_pending(conn, limit=50)
        conn.execute(
            """
            INSERT INTO operations_state (component, heartbeat_at, details_json)
            VALUES ('operations_worker', CURRENT_TIMESTAMP, ?)
            ON CONFLICT(component) DO UPDATE SET
                heartbeat_at = CURRENT_TIMESTAMP, details_json = excluded.details_json
            """,
            (json.dumps({"notifications": len(notifications), "capabilities": len(capabilities)}),),
        )
        conn.commit()
    finally:
        conn.close()
    recovered = queue.recover_stale_jobs()
    result = {
        "queued_notifications": queued,
        "dispatched_notifications": len(notifications),
        "executed_capabilities": len(capabilities),
        "recovered_capabilities": stale_capabilities,
        "recovered_jobs": recovered,
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
        except Exception as exc:
            audit("operations_worker_error", error=str(exc)[:500])
        time.sleep(max(5, args.interval))


if __name__ == "__main__":
    raise SystemExit(main())
