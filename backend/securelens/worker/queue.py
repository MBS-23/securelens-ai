"""Database-backed job queue.

Claiming is a conditional UPDATE (``... WHERE id = :id AND status = 'QUEUED'``),
which is atomic on PostgreSQL and SQLite alike, so several workers can poll
the same table without taking the same job twice.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from securelens.core.config import get_settings
from securelens.enums import JobKind, JobStatus
from securelens.models import Job
from securelens.models.base import utcnow

STALE_AFTER = timedelta(minutes=30)


def enqueue(db: Session, kind: JobKind, payload: dict[str, Any], *, priority: int = 100) -> Job:
    job = Job(kind=kind, payload=payload, status=JobStatus.QUEUED, priority=priority,
              max_attempts=get_settings().job_max_attempts, run_after=utcnow())
    db.add(job)
    db.flush()
    return job


def claim_next(db: Session, worker_id: str, kinds: set[str] | None = None) -> Job | None:
    now = utcnow()
    query = (select(Job.id).where(Job.status == JobStatus.QUEUED, Job.run_after <= now)
             .order_by(Job.priority, Job.created_at).limit(5))
    if kinds:
        query = query.where(Job.kind.in_(kinds))
    for job_id in db.scalars(query).all():
        claimed = db.execute(
            update(Job)
            .where(Job.id == job_id, Job.status == JobStatus.QUEUED)
            .values(status=JobStatus.RUNNING, locked_by=worker_id[:120], locked_at=now, heartbeat_at=now,
                    attempts=Job.attempts + 1)
            .execution_options(synchronize_session=False)
        ).rowcount
        db.commit()
        if claimed == 1:
            return db.get(Job, job_id)
    return None


def heartbeat(db: Session, job_id: uuid.UUID) -> None:
    db.execute(update(Job).where(Job.id == job_id).values(heartbeat_at=utcnow()))
    db.commit()


def complete(db: Session, job: Job) -> None:
    job.status = JobStatus.SUCCEEDED
    job.finished_at = utcnow()
    job.last_error = None
    db.commit()


def fail(db: Session, job: Job, error: str, *, retry: bool) -> None:
    job.last_error = error[:4000]
    if retry and job.attempts < job.max_attempts:
        job.status = JobStatus.QUEUED
        job.run_after = utcnow() + timedelta(seconds=30 * job.attempts)
        job.locked_by = None
    else:
        job.status = JobStatus.FAILED
        job.finished_at = utcnow()
    db.commit()


def recover_stale(db: Session) -> int:
    """Requeue jobs whose worker stopped sending heartbeats (crashed or killed)."""
    cutoff = utcnow() - STALE_AFTER
    stale = db.scalars(select(Job).where(Job.status == JobStatus.RUNNING, Job.heartbeat_at < cutoff)).all()
    for job in stale:
        fail(db, job, "worker stopped responding", retry=True)
    return len(stale)
