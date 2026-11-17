"""Job queue for persistent, pausable playbook execution.

Replaces daemon threads with persistent job storage and worker management.
Jobs can be paused, resumed, cancelled, and monitored via web portal.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

try:
    from .common import ROOT, audit, utc_now
except ImportError:
    from scripts.common import ROOT, audit, utc_now


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


class JobLeaseLost(JobControlSignal):
    """Raised when a replacement worker owns a newer lease generation."""


@dataclass
class JobResult:
    """Result of a job execution."""
    job_id: str
    status: JobStatus
    result: dict[str, Any] | None = None
    error: str | None = None
    progress: float = 0.0  # 0.0 to 1.0
    started_at: str | None = None
    finished_at: str | None = None


class JobQueue:
    """Persistent job queue backed by SQLite."""

    def __init__(self, db_path: Path = ROOT / "data" / "soc_operator.db"):
        self.db_path = db_path
        self.max_workers = max(1, int(os.environ.get("AI_SOC_LOCAL_MAX_WORKERS", "4")))
        self._pool = ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="soc-job")
        self._workers: dict[str, Future] = {}
        self._worker_lock = threading.Lock()
        self._executors: dict[str, Callable] = {}
        self.lease_seconds = max(15, int(os.environ.get("AI_SOC_JOB_LEASE_SECONDS", "300")))
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        """Get database connection."""
        from web.services.database import connect_database

        conn = connect_database(self.db_path)
        # Queue-only bootstrap databases may be created before the web schema.
        # SQLite historically permits that ordering; PostgreSQL deployments are
        # initialized from the complete migrated schema before workers start.
        if isinstance(conn, sqlite3.Connection):
            conn.execute("PRAGMA foreign_keys = OFF")
        return conn

    @staticmethod
    def _bind_tenant(conn, org_id: int | None) -> None:
        if org_id is not None and hasattr(conn, "set_tenant_context"):
            conn.set_tenant_context(org_id)

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
                    lease_generation INTEGER NOT NULL DEFAULT 0,
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
                "lease_generation": "INTEGER NOT NULL DEFAULT 0",
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
        job_id = str(uuid.uuid4())

        conn = self._get_conn()
        try:
            self._bind_tenant(conn, org_id)
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

    def get_job(self, job_id: str, org_id: int | None = None) -> JobResult:
        """Get job status and result."""
        conn = self._get_conn()
        try:
            self._bind_tenant(conn, org_id)
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

    def update_job_progress(
        self,
        job_id: str,
        progress: float,
        *,
        worker_id: str | None = None,
        lease_generation: int | None = None,
        org_id: int | None = None,
    ) -> bool:
        """Update progress only while the caller still owns the active lease."""
        progress = max(0.0, min(1.0, progress))
        conn = self._get_conn()
        try:
            self._bind_tenant(conn, org_id)
            params: list[Any] = [progress, f"+{self.lease_seconds} seconds", job_id]
            if worker_id is not None and lease_generation is not None:
                params.extend([worker_id, lease_generation])
                query = """
                UPDATE jobs
                SET progress = ?, updated_at = CURRENT_TIMESTAMP,
                    lease_expires_at = CASE
                        WHEN status = 'running' THEN datetime('now', ?)
                        ELSE lease_expires_at
                    END
                WHERE id = ?
                  AND status = 'running' AND worker_id = ? AND lease_generation = ?
                """
            else:
                query = """
                UPDATE jobs
                SET progress = ?, updated_at = CURRENT_TIMESTAMP,
                    lease_expires_at = CASE
                        WHEN status = 'running' THEN datetime('now', ?)
                        ELSE lease_expires_at
                    END
                WHERE id = ?
                """
            updated = conn.execute(query, params).rowcount
            conn.commit()
            return bool(updated)
        finally:
            conn.close()

    def update_job_status(
        self,
        job_id: str,
        status: JobStatus,
        result: dict[str, Any] | None = None,
        error: str | None = None,
        *,
        worker_id: str | None = None,
        lease_generation: int | None = None,
        org_id: int | None = None,
    ) -> bool:
        """Update status, optionally fenced to the current lease owner."""
        conn = self._get_conn()
        try:
            self._bind_tenant(conn, org_id)
            result_json = json.dumps(result) if result else None
            finished_at = utc_now() if status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED) else None
            params: list[Any] = [status.value, result_json, error, finished_at, status.value, job_id]
            if worker_id is not None and lease_generation is not None:
                params.extend([worker_id, lease_generation])
                query = """UPDATE jobs SET status = ?, result_json = ?, error_message = ?,
                   finished_at = ?, updated_at = CURRENT_TIMESTAMP,
                   lease_expires_at = CASE
                       WHEN ? IN ('completed', 'failed', 'cancelled') THEN NULL
                       ELSE lease_expires_at
                   END
                   WHERE id = ?
                     AND status = 'running' AND worker_id = ? AND lease_generation = ?"""
            else:
                query = """UPDATE jobs SET status = ?, result_json = ?, error_message = ?,
                   finished_at = ?, updated_at = CURRENT_TIMESTAMP,
                   lease_expires_at = CASE
                       WHEN ? IN ('completed', 'failed', 'cancelled') THEN NULL
                       ELSE lease_expires_at
                   END
                   WHERE id = ?"""
            updated = conn.execute(query, params).rowcount
            conn.commit()

            if not updated:
                return False
            if status == JobStatus.COMPLETED:
                audit("job_completed", job_id=job_id)
            elif status == JobStatus.FAILED:
                audit("job_failed", job_id=job_id, error=error)
            elif status == JobStatus.CANCELLED:
                audit("job_cancelled", job_id=job_id)
            return True
        finally:
            conn.close()

    def pause_job(self, job_id: str, org_id: int | None = None) -> bool:
        """Pause a running job."""
        conn = self._get_conn()
        try:
            self._bind_tenant(conn, org_id)
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

    def resume_job(self, job_id: str, org_id: int | None = None) -> bool:
        """Resume a paused job."""
        conn = self._get_conn()
        try:
            self._bind_tenant(conn, org_id)
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
                self.execute_job(job_id, executor, org_id=org_id)
            return True
        finally:
            conn.close()

    def cancel_job(self, job_id: str, org_id: int | None = None) -> bool:
        """Cancel a job."""
        conn = self._get_conn()
        try:
            self._bind_tenant(conn, org_id)
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
        status: JobStatus | None = None,
        limit: int = 50,
        org_id: int | None = None,
    ) -> list[JobResult]:
        """List jobs, optionally filtered by status."""
        conn = self._get_conn()
        try:
            self._bind_tenant(conn, org_id)
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
        *,
        org_id: int | None = None,
    ) -> None:
        """Execute a job in a thread pool (not daemon).
        
        Args:
            job_id: Job ID to execute
            executor: Callable that takes (alert, progress_callback) and returns result dict
        """
        self._executors[job_id] = executor

        def worker():
            self.run_job(job_id, executor, worker_id=f"local-{threading.get_ident()}", org_id=org_id)
        # A bounded pool prevents an alert burst from creating one operating-
        # system thread per alert while preserving durable pending job rows.
        future = self._pool.submit(worker)
        with self._worker_lock:
            self._workers[job_id] = future
        future.add_done_callback(lambda _future: self._forget_worker(job_id))

    def run_job(
        self,
        job_id: str,
        executor: Callable[[dict[str, Any], Callable[[float], None]], dict[str, Any]],
        *,
        worker_id: str = "worker",
        org_id: int | None = None,
    ) -> bool:
        """Atomically claim and execute one persisted job in the current process."""
        try:
            conn = self._get_conn()
            try:
                self._bind_tenant(conn, org_id)
                claimed = conn.execute(
                    """
                    UPDATE jobs
                    SET status = ?, started_at = COALESCE(started_at, CURRENT_TIMESTAMP),
                        attempt_count = attempt_count + 1, worker_id = ?,
                        lease_generation = lease_generation + 1,
                        lease_expires_at = datetime('now', ?), updated_at = CURRENT_TIMESTAMP
                    WHERE id = ? AND status = ? AND cancel_requested = 0
                      AND attempt_count < max_attempts
                    """,
                    (
                        JobStatus.RUNNING.value,
                        worker_id,
                        f"+{self.lease_seconds} seconds",
                        job_id,
                        JobStatus.PENDING.value,
                    ),
                ).rowcount
                conn.commit()
            finally:
                conn.close()
            if not claimed:
                return False

            conn = self._get_conn()
            try:
                self._bind_tenant(conn, org_id)
                job = conn.execute(
                    "SELECT * FROM jobs WHERE id = ? AND worker_id = ? AND status = 'running'",
                    (job_id, worker_id),
                ).fetchone()
                if not job:
                    return False
                alert = json.loads(job["alert_json"])
                lease_generation = int(job["lease_generation"])
            finally:
                conn.close()

            heartbeat_stop = threading.Event()

            def heartbeat() -> None:
                # Lease renewal is independent of executor progress so a long
                # platform call does not look like a dead worker.
                interval = max(5.0, self.lease_seconds / 3)
                while not heartbeat_stop.wait(interval):
                    if not self.update_job_progress(
                        job_id,
                        self.get_job(job_id, org_id).progress,
                        worker_id=worker_id,
                        lease_generation=lease_generation,
                        org_id=org_id,
                    ):
                        return

            heartbeat_thread = threading.Thread(
                target=heartbeat,
                name=f"lease-{job_id[:8]}",
                daemon=True,
            )
            heartbeat_thread.start()

            def update_progress(progress: float):
                if 0 <= progress <= 1.0:
                    control = self.get_job(job_id, org_id).status
                    if control == JobStatus.CANCELLED:
                        raise JobCancelled("Job cancellation requested")
                    if control == JobStatus.PAUSED:
                        raise JobPaused("Job pause requested")
                    if not self.update_job_progress(
                        job_id,
                        progress,
                        worker_id=worker_id,
                        lease_generation=lease_generation,
                        org_id=org_id,
                    ):
                        raise JobLeaseLost("Job lease is owned by a replacement worker")

            try:
                result = executor(alert, update_progress)
            finally:
                heartbeat_stop.set()
                heartbeat_thread.join(timeout=1)
            updated = self.update_job_status(
                job_id,
                JobStatus.COMPLETED,
                result=result,
                worker_id=worker_id,
                lease_generation=lease_generation,
                org_id=org_id,
            )
            if not updated:
                audit("job_stale_completion_ignored", job_id=job_id, worker_id=worker_id)
            return updated
        except JobPaused:
            audit("job_worker_paused", job_id=job_id)
        except JobLeaseLost:
            audit("job_worker_lease_lost", job_id=job_id, worker_id=worker_id)
        except JobCancelled:
            audit("job_worker_cancelled", job_id=job_id, worker_id=worker_id)
        # A job boundary must persist any executor failure instead of killing the worker.
        except Exception as exc:  # noqa: BLE001
            generation = locals().get("lease_generation")
            self.update_job_status(
                job_id,
                JobStatus.FAILED,
                error=str(exc)[:500],
                worker_id=worker_id if generation is not None else None,
                lease_generation=generation,
                org_id=org_id,
            )
        return False

    def _forget_worker(self, job_id: str) -> None:
        with self._worker_lock:
            self._workers.pop(job_id, None)

    def worker_stats(self) -> dict[str, int]:
        with self._worker_lock:
            active = sum(1 for future in self._workers.values() if future.running())
            queued = sum(1 for future in self._workers.values() if not future.running() and not future.done())
        return {"max_workers": self.max_workers, "active": active, "queued": queued}

    def recover_stale_jobs(
        self,
        dispatcher: Callable[[str], None] | None = None,
        *,
        org_id: int | None = None,
    ) -> int:
        """Retry expired leases and optionally redeliver them to the broker."""
        conn = self._get_conn()
        try:
            self._bind_tenant(conn, org_id)
            recoverable = [
                str(row["id"])
                for row in conn.execute(
                    """
                    SELECT id FROM jobs
                    WHERE status = 'running' AND lease_expires_at IS NOT NULL
                      AND lease_expires_at < CURRENT_TIMESTAMP AND attempt_count < max_attempts
                    """
                ).fetchall()
            ]
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
            audit("stale_jobs_recovered", count=recovered, job_ids=recoverable)
            if dispatcher:
                for recovered_job_id in recoverable:
                    dispatcher(recovered_job_id)
        if exhausted:
            audit("stale_jobs_failed", count=exhausted)
        return int(recovered)

    def wait_for_job(self, job_id: str, timeout: int | None = None, *, org_id: int | None = None) -> JobResult:
        """Wait for a job to complete."""
        start_time = time.time()
        while True:
            result = self.get_job(job_id, org_id)
            if result.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
                return result

            if timeout and (time.time() - start_time) > timeout:
                return JobResult(
                    job_id=job_id,
                    status=JobStatus.FAILED,
                    error=f"Timeout after {timeout} seconds",
                )

            time.sleep(0.5)  # Poll every 500ms
