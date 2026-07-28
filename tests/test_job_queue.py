"""Tests for persistent job queue setup."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.job_queue import JobQueue, JobStatus


class JobQueueTests(unittest.TestCase):
    def test_creates_missing_database_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "missing" / "soc_operator.db"
            queue = JobQueue(db_path)
            job_id = queue.create_job(
                run_id=1,
                playbook_path="playbooks/test.yaml",
                alert={"rule": {"name": "Test"}},
                config={},
            )

            self.assertTrue(db_path.is_file())
            self.assertEqual(queue.get_job(job_id).status, JobStatus.PENDING)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
