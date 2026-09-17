"""Process-independent dispatch and execution for persisted playbook jobs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from scripts.common import ROOT
from scripts.job_queue import JobQueue
from web.services.database import connect_database, runtime_queue_settings


DB_PATH = ROOT / "data" / "soc_operator.db"


def execute_persisted_playbook_job(
    job_id: str,
    alert: dict[str, Any],
    progress_cb: Callable[[float], None],
) -> dict[str, Any]:
    """Rebuild execution context from durable rows instead of request closures."""
    from web.app import _execute_run_job, load_config_for_web
    from web.services.alert_ingest import _create_run_for_ingested_alert

    conn = connect_database(DB_PATH)
    job = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if not job:
        conn.close()
        raise ValueError("persisted job does not exist")
    org_id = int(job["org_id"])
    run_id = int(job["run_id"] or 0)
    alert_row = None
    if not run_id:
        alert_row = conn.execute(
            "SELECT * FROM alerts WHERE job_id = ? AND org_id = ?", (job_id, org_id)
        ).fetchone()
        if not alert_row:
            conn.close()
            raise ValueError("queued alert does not exist")
        run_id = _create_run_for_ingested_alert(
            conn,
            job["playbook_path"].split("/")[-1].split("\\")[-1],
            int(alert_row["id"]),
            alert_row["source"],
            org_id,
        )
        conn.execute("UPDATE jobs SET run_id = ? WHERE id = ? AND org_id = ?", (run_id, job_id, org_id))
        conn.execute("UPDATE alerts SET status = 'running' WHERE id = ? AND org_id = ?", (alert_row["id"], org_id))
        conn.commit()
    conn.close()

    playbook_path = Path(job["playbook_path"])
    config = load_config_for_web(org_id) or json.loads(job["config_json"] or "{}")
    try:
        result = _execute_run_job(run_id, playbook_path, alert, config, progress_cb, org_id)
    except Exception:
        if alert_row:
            conn = connect_database(DB_PATH)
            conn.execute("UPDATE alerts SET status = 'failed' WHERE id = ? AND org_id = ?", (alert_row["id"], org_id))
            conn.commit()
            conn.close()
        raise
    if alert_row:
        conn = connect_database(DB_PATH)
        case = conn.execute(
            "SELECT id FROM cases WHERE run_id = ? AND org_id = ? ORDER BY id DESC LIMIT 1", (run_id, org_id)
        ).fetchone()
        case_id = case["id"] if case else None
        conn.execute(
            "UPDATE alerts SET status = 'case_created', case_id = ?, first_response_at = CURRENT_TIMESTAMP WHERE id = ? AND org_id = ?",
            (case_id, alert_row["id"], org_id),
        )
        if case_id:
            conn.execute(
                "UPDATE observables SET case_id = ? WHERE alert_id = ? AND org_id = ? AND case_id IS NULL",
                (case_id, alert_row["id"], org_id),
            )
        conn.commit()
        conn.close()
    return result


def dispatch_playbook_job(job_queue: JobQueue, job_id: str) -> str:
    """Send to Celery when configured, otherwise use the bounded local pool."""
    if runtime_queue_settings():
        from scripts.celery_app import celery_app

        celery_app.send_task("ai_soc.execute_playbook_job", args=[job_id], task_id=f"playbook-{job_id}")
        return "celery"
    job_queue.execute_job(
        job_id,
        lambda alert, progress: execute_persisted_playbook_job(job_id, alert, progress),
    )
    return "local"
