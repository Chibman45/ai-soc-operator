"""Job queue for persistent, pausable playbook execution.

Replaces daemon threads with persistent job storage and worker management.
Jobs can be paused, resumed, cancelled, and monitored via web portal.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

try:
    from .common import ROOT, Session, audit, utc_now
except ImportError:
    from scripts.common import ROOT, Session, audit, utc_now


class JobStatus(str, Enum):
    """Job execution status."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobControlSignal(RuntimeError):
    """Internal cooperative stop signal raised at progress checkpoints."""


class JobPaused(JobControlSignal):
    pass


class JobCancelled(JobControlSignal):
    pass


@dataclass
class JobResult:
    """Result of a job execution."""
    job_id: str
    status: JobStatus
    result: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    progress: float = 0.0  # 0.0 to 1.0
    started_at: Optional[str] = None
    finished_at: Optional[str] = None


class JobQueue:
    """Persistent job queue backed by SQLite."""

    def __init__(self, db_path: Path = ROOT / "data" / "soc_operator.db"):
        self.db_path = db_path
        self._workers: dict[str, threading.Thread] = {}
        self._executors: dict[str, Callable] = {}
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        """Get database connection."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        """Initialize job queue schema."""
        conn = self._get_conn()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    run_id INTEGER,
                    playbook_path TEXT NOT NULL,
                    alert_json TEXT NOT NULL,
                    config_json TEXT NOT NULL,
                    result_json TEXT,
                    error_message TEXT,
                    progress REAL DEFAULT 0.0,
                    started_at TIMESTAMP,
                    finished_at TIMESTAMP,
                    paused_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    org_id INTEGER,
                    idempotency_key TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 3,
                    worker_id TEXT,
                    lease_expires_at TIMESTAMP,
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY (run_id) REFERENCES runs(id)
                );
                
                CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
                CREATE INDEX IF NOT EXISTS idx_jobs_run_id ON jobs(run_id);
            """)
            existing = {row[1] for row in conn.execute("PRAGMA table_info(jobs)").fetchall()}
            for name, definition in {
                "org_id": "INTEGER",
                "idempotency_key": "TEXT",
                "attempt_count": "INTEGER NOT NULL DEFAULT 0",
                "max_attempts": "INTEGER NOT NULL DEFAULT 3",
                "worker_id": "TEXT",
                "lease_expires_at": "TIMESTAMP",
                "cancel_requested": "INTEGER NOT NULL DEFAULT 0",
            }.items():
                if name not in existing:
                    conn.execute(f"ALTER TABLE jobs ADD COLUMN {name} {definition}")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_idempotency ON jobs(org_id, idempotency_key) WHERE idempotency_key IS NOT NULL")
            conn.commit()
        finally:
            conn.close()

    def create_job(
        self,
        run_id: int,
        playbook_path: str,
        alert: dict[str, Any],
        config: dict[str, Any],
        org_id: int | None = None,
        idempotency_key: str | None = None,
        max_attempts: int = 3,
    ) -> str:
        """Create and queue a new job.
        
        Returns:
            Job ID
        """
        import uuid
        job_id = str(uuid.uuid4())

        conn = self._get_conn()
        try:
            if idempotency_key:
                existing = conn.execute(
                    "SELECT id FROM jobs WHERE org_id = ? AND idempotency_key = ?",
                    (org_id, idempotency_key),
                ).fetchone()
                if existing:
                    return str(existing["id"])
            conn.execute(
                """INSERT INTO jobs
                   (id, org_id, run_id, status, playbook_path, alert_json, config_json,
                    idempotency_key, max_attempts)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    job_id,
                    org_id,
                    run_id,
                    JobStatus.PENDING.value,
                    playbook_path,
                    json.dumps(alert),
                    json.dumps(config),
                    idempotency_key,
                    max(1, max_attempts),
                ),
            )
            conn.commit()
        finally:
            conn.close()

        audit("job_created", job_id=job_id, run_id=run_id, playbook=playbook_path)
        return job_id

    def get_job(self, job_id: str) -> JobResult:
        """Get job status and result."""
        conn = self._get_conn()
        try:
            job = conn.execute(
                "SELECT * FROM jobs WHERE id = ?", (job_id,)
            ).fetchone()
            if not job:
                return JobResult(
                    job_id=job_id,
                    status=JobStatus.FAILED,
                    error="Job not found",
                )

            result = None
            if job["result_json"]:
                result = json.loads(job["result_json"])

            return JobResult(
                job_id=job_id,
                status=JobStatus(job["status"]),
                result=result,
                error=job["error_message"],
                progress=float(job["progress"] or 0.0),
                started_at=job["started_at"],
                finished_at=job["finished_at"],
            )
        finally:
            conn.close()

    def update_job_progress(self, job_id: str, progress: float) -> None:
        """Update job progress (0.0 to 1.0)."""
        progress = max(0.0, min(1.0, progress))
        conn = self._get_conn()
        try:
            conn.execute(
                """
                UPDATE jobs
                SET progress = ?, updated_at = CURRENT_TIMESTAMP,
                    lease_expires_at = CASE
                        WHEN status = 'running' THEN datetime('now', '+5 minutes')
                        ELSE lease_expires_at
                    END
                WHERE id = ?
                """,
                (progress, job_id),
            )
            conn.commit()
        finally:
            conn.close()

    def update_job_status(
        self,
        job_id: str,
        status: JobStatus,
        result: Optional[dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> None:
        """Update job status and result."""
        conn = self._get_conn()
        try:
            result_json = json.dumps(result) if result else None
            finished_at = utc_now() if status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED) else None

            conn.execute(
                """UPDATE jobs SET status = ?, result_json = ?, error_message = ?, 
                   finished_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
                (status.value, result_json, error, finished_at, job_id),
            )
            conn.commit()

            if status == JobStatus.COMPLETED:
                audit("job_completed", job_id=job_id)
            elif status == JobStatus.FAILED:
                audit("job_failed", job_id=job_id, error=error)
            elif status == JobStatus.CANCELLED:
                audit("job_cancelled", job_id=job_id)
        finally:
            conn.close()

    def pause_job(self, job_id: str) -> bool:
        """Pause a running job."""
        conn = self._get_conn()
        try:
            job = conn.execute(
                "SELECT status FROM jobs WHERE id = ?", (job_id,)
            ).fetchone()
            if not job or job["status"] != JobStatus.RUNNING.value:
                return False

            conn.execute(
                "UPDATE jobs SET status = ?, paused_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (JobStatus.PAUSED.value, job_id),
            )
            conn.commit()
            audit("job_paused", job_id=job_id)
            return True
        finally:
            conn.close()

    def resume_job(self, job_id: str) -> bool:
        """Resume a paused job."""
        conn = self._get_conn()
        try:
            job = conn.execute(
                "SELECT status FROM jobs WHERE id = ?", (job_id,)
            ).fetchone()
            if not job or job["status"] != JobStatus.PAUSED.value:
                return False

            conn.execute(
                "UPDATE jobs SET status = ?, paused_at = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (JobStatus.PENDING.value, job_id),
            )
            conn.commit()
            audit("job_resumed", job_id=job_id)
            executor = self._executors.get(job_id)
            if executor:
                self.execute_job(job_id, executor)
            return True
        finally:
            conn.close()

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a job."""
        conn = self._get_conn()
        try:
            job = conn.execute(
                "SELECT status FROM jobs WHERE id = ?", (job_id,)
            ).fetchone()
            if not job:
                return False

            if job["status"] in (JobStatus.COMPLETED.value, JobStatus.FAILED.value, JobStatus.CANCELLED.value):
                return False  # Already terminal

            conn.execute(
                "UPDATE jobs SET cancel_requested = 1, status = ?, error_message = ?, finished_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (JobStatus.CANCELLED.value, "Cancelled by user", job_id),
            )
            conn.commit()
            audit("job_cancelled", job_id=job_id)
            return True
        finally:
            conn.close()

    def list_jobs(
        self,
        status: Optional[JobStatus] = None,
        limit: int = 50,
    ) -> list[JobResult]:
        """List jobs, optionally filtered by status."""
        conn = self._get_conn()
        try:
            if status:
                query = "SELECT * FROM jobs WHERE status = ? ORDER BY created_at DESC LIMIT ?"
                rows = conn.execute(query, (status.value, limit)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()

            return [
                JobResult(
                    job_id=row["id"],
                    status=JobStatus(row["status"]),
                    result=json.loads(row["result_json"]) if row["result_json"] else None,
                    error=row["error_message"],
                    progress=float(row["progress"] or 0.0),
                    started_at=row["started_at"],
                    finished_at=row["finished_at"],
                )
                for row in rows
            ]
        finally:
            conn.close()

    def execute_job(
        self,
        job_id: str,
        executor: Callable[[dict[str, Any], Callable[[float], None]], dict[str, Any]],
    ) -> None:
        """Execute a job in a thread pool (not daemon).
        
        Args:
            job_id: Job ID to execute
            executor: Callable that takes (alert, progress_callback) and returns result dict
        """
        self._executors[job_id] = executor

        def worker():
            try:
                worker_id = f"local-{threading.get_ident()}"
                conn = self._get_conn()
                try:
                    claimed = conn.execute(
                        """
                        UPDATE jobs
                        SET status = ?, started_at = COALESCE(started_at, CURRENT_TIMESTAMP),
                            attempt_count = attempt_count + 1, worker_id = ?,
                            lease_expires_at = datetime('now', '+5 minutes'), updated_at = CURRENT_TIMESTAMP
                        WHERE id = ? AND status = ? AND cancel_requested = 0
                          AND attempt_count < max_attempts
                        """,
                        (JobStatus.RUNNING.value, worker_id, job_id, JobStatus.PENDING.value),
                    ).rowcount
                    conn.commit()
                finally:
                    conn.close()
                if not claimed:
                    return

                # Load job data
                conn = self._get_conn()
                try:
                    job = conn.execute(
                        "SELECT * FROM jobs WHERE id = ?", (job_id,)
                    ).fetchone()
                    if not job:
                        self.update_job_status(job_id, JobStatus.FAILED, error="Job not found")
                        return

                    alert = json.loads(job["alert_json"])
                except Exception as e:
                    self.update_job_status(job_id, JobStatus.FAILED, error=str(e))
                    return
                finally:
                    conn.close()

                # Define progress callback
                def update_progress(progress: float):
                    if 0 <= progress <= 1.0:
                        control = self.get_job(job_id).status
                        if control == JobStatus.CANCELLED:
                            raise JobCancelled("Job cancellation requested")
                        if control == JobStatus.PAUSED:
                            raise JobPaused("Job pause requested")
                        self.update_job_progress(job_id, progress)

                # Execute
                result = executor(alert, update_progress)
                self.update_job_status(job_id, JobStatus.COMPLETED, result=result)

            except JobPaused:
                audit("job_worker_paused", job_id=job_id)
            except JobCancelled:
                self.update_job_status(job_id, JobStatus.CANCELLED, error="Cancelled by user")
            except Exception as e:
                self.update_job_status(job_id, JobStatus.FAILED, error=str(e)[:500])
            finally:
                self._workers.pop(job_id, None)

        # Start worker in non-daemon thread
        thread = threading.Thread(target=worker, daemon=False)
        self._workers[job_id] = thread
        thread.start()

    def recover_stale_jobs(self) -> int:
        """Retry recoverable leases and fail jobs that exhausted their attempts."""
        conn = self._get_conn()
        try:
            recovered = conn.execute(
                """
                UPDATE jobs
                SET status = 'pending', worker_id = NULL, lease_expires_at = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE status = 'running' AND lease_expires_at IS NOT NULL
                  AND lease_expires_at < CURRENT_TIMESTAMP AND attempt_count < max_attempts
                """
            ).rowcount
            exhausted = conn.execute(
                """
                UPDATE jobs
                SET status = 'failed', worker_id = NULL, lease_expires_at = NULL,
                    error_message = 'Worker lease expired after maximum attempts',
                    finished_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE status = 'running' AND lease_expires_at IS NOT NULL
                  AND lease_expires_at < CURRENT_TIMESTAMP AND attempt_count >= max_attempts
                """
            ).rowcount
            conn.commit()
        finally:
            conn.close()
        if recovered:
            audit("stale_jobs_recovered", count=recovered)
        if exhausted:
            audit("stale_jobs_failed", count=exhausted)
        return int(recovered)

    def wait_for_job(self, job_id: str, timeout: Optional[int] = None) -> JobResult:
        """Wait for a job to complete."""
        start_time = time.time()
        while True:
            result = self.get_job(job_id)
            if result.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
                return result

            if timeout and (time.time() - start_time) > timeout:
                return JobResult(
                    job_id=job_id,
                    status=JobStatus.FAILED,
                    error=f"Timeout after {timeout} seconds",
                )

            time.sleep(0.5)  # Poll every 500ms
