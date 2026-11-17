from __future__ import annotations

import sqlite3
import tempfile
import threading
from pathlib import Path

from scripts.job_queue import JobQueue, JobStatus


def _queue(root: str) -> JobQueue:
    return JobQueue(Path(root) / "queue.db")


def test_expired_worker_cannot_overwrite_replacement_result():
    with tempfile.TemporaryDirectory() as root:
        queue = _queue(root)
        job_id = queue.create_job(1, "playbooks/test.yaml", {"value": 1}, {})
        started = threading.Event()
        release = threading.Event()

        def slow_executor(_alert, _progress):
            started.set()
            assert release.wait(5)
            return {"worker": "stale"}

        stale = threading.Thread(
            target=lambda: queue.run_job(job_id, slow_executor, worker_id="worker-old")
        )
        stale.start()
        assert started.wait(5)

        conn = sqlite3.connect(queue.db_path)
        conn.execute("UPDATE jobs SET lease_expires_at = datetime('now', '-1 minute') WHERE id = ?", (job_id,))
        conn.commit()
        conn.close()
        assert queue.recover_stale_jobs() == 1

        assert queue.run_job(
            job_id,
            lambda _alert, _progress: {"worker": "replacement"},
            worker_id="worker-new",
        )
        release.set()
        stale.join(timeout=5)

        result = queue.get_job(job_id)
        assert result.status == JobStatus.COMPLETED
        assert result.result == {"worker": "replacement"}


def test_recovery_dispatches_each_requeued_job_once():
    with tempfile.TemporaryDirectory() as root:
        queue = _queue(root)
        job_id = queue.create_job(1, "playbooks/test.yaml", {}, {})
        conn = sqlite3.connect(queue.db_path)
        conn.execute(
            "UPDATE jobs SET status = 'running', attempt_count = 1, worker_id = 'lost', "
            "lease_generation = 1, lease_expires_at = datetime('now', '-1 minute') WHERE id = ?",
            (job_id,),
        )
        conn.commit()
        conn.close()

        dispatched: list[str] = []
        assert queue.recover_stale_jobs(dispatched.append) == 1
        assert dispatched == [job_id]
        assert queue.recover_stale_jobs(dispatched.append) == 0
        assert dispatched == [job_id]
