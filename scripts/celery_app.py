"""Celery entry point for PostgreSQL/Redis scale-out deployments."""

from __future__ import annotations

from celery import Celery

from scripts.common import ROOT
from scripts.job_queue import JobQueue
from web.services.database import runtime_queue_settings
from web.services.playbook_jobs import execute_persisted_playbook_job


settings = runtime_queue_settings()
celery_app = Celery(
    "ai_soc_operator",
    broker=settings.get("broker_url", "redis://127.0.0.1:6379/0"),
    backend=settings.get("result_backend", "redis://127.0.0.1:6379/1"),
)
celery_app.conf.update(task_acks_late=True, worker_prefetch_multiplier=1, task_reject_on_worker_lost=True)


@celery_app.task(name="ai_soc.execute_playbook_job", bind=True)
def execute_playbook_job(self, job_id: str) -> bool:
    queue = JobQueue(ROOT / "data" / "soc_operator.db")
    return queue.run_job(
        job_id,
        lambda alert, progress: execute_persisted_playbook_job(job_id, alert, progress),
        worker_id=f"celery-{self.request.id}",
    )
