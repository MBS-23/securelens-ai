"""Job dispatch for ``securelens-worker``.

The API process only enqueues jobs. Workers claim them from the database,
run the handler (scans analyse code in a sandboxed child process) and record
the outcome. A heartbeat thread keeps long jobs from being mistaken for
crashed ones; jobs whose worker stops heart-beating are re-queued.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
import uuid
from collections.abc import Callable
from contextlib import contextmanager

from sqlalchemy.orm import Session

from securelens.core.config import get_settings
from securelens.core.database import session_factory
from securelens.enums import JobKind
from securelens.models import Job
from securelens.worker import queue

log = logging.getLogger("securelens.worker")

HEARTBEAT_SECONDS = 60.0


class RetryableJobError(Exception):
    """A transient failure: the job is re-queued (up to its attempt limit)."""


def _handle_scan(db: Session, job: Job, *, sandbox: bool) -> None:
    from securelens.services.scans import execute_scan

    execute_scan(db, uuid.UUID(str(job.payload["scan_id"])), sandbox=sandbox)


HANDLERS: dict[str, Callable[..., None]] = {
    JobKind.SCAN: _handle_scan,
}


def register(kind: JobKind, handler: Callable[..., None]) -> None:
    HANDLERS[kind] = handler


@contextmanager
def _heartbeat(job_id: uuid.UUID):
    stop = threading.Event()

    def beat() -> None:
        while not stop.wait(HEARTBEAT_SECONDS):
            try:
                with session_factory()() as hb:
                    queue.heartbeat(hb, job_id)
            except Exception:  # never let the heartbeat thread kill the job
                log.warning("heartbeat for job %s failed", job_id, exc_info=True)

    thread = threading.Thread(target=beat, name=f"heartbeat-{job_id}", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=5)


def process_job(db: Session, job: Job, *, sandbox: bool = True) -> None:
    handler = HANDLERS.get(job.kind)
    if handler is None:
        queue.fail(db, job, f"no handler is installed for {job.kind} jobs", retry=False)
        return
    started = time.monotonic()
    try:
        with _heartbeat(job.id):
            handler(db, job, sandbox=sandbox)
    except RetryableJobError as exc:
        db.rollback()
        queue.fail(db, db.get(Job, job.id) or job, str(exc), retry=True)
        log.warning("job %s (%s) will be retried: %s", job.id, job.kind, exc)
        return
    except Exception as exc:
        log.exception("job %s (%s) failed", job.id, job.kind)
        db.rollback()
        queue.fail(db, db.get(Job, job.id) or job, f"{type(exc).__name__}: {str(exc)[:500]}", retry=False)
        return
    queue.complete(db, db.get(Job, job.id) or job)
    log.info("job %s (%s) finished in %.1fs", job.id, job.kind, time.monotonic() - started)


def process_available_jobs(worker_id: str, max_jobs: int = 50, *, sandbox: bool = True,
                           kinds: set[str] | None = None) -> int:
    """Run queued jobs until the queue is empty or ``max_jobs`` have run. Returns the number run."""
    processed = 0
    with session_factory()() as db:
        queue.recover_stale(db)
        while processed < max_jobs:
            job = queue.claim_next(db, worker_id, kinds)
            if job is None:
                break
            process_job(db, job, sandbox=sandbox)
            processed += 1
    return processed


def run_forever(worker_id: str, *, sandbox: bool = True, kinds: set[str] | None = None) -> None:
    stopping = threading.Event()

    def request_stop(signum, _frame) -> None:
        log.info("received signal %s; finishing the current job before stopping", signum)
        stopping.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    poll = get_settings().worker_poll_seconds
    log.info("worker %s started (sandbox=%s)", worker_id, sandbox)
    while not stopping.is_set():
        try:
            ran = process_available_jobs(worker_id, max_jobs=10, sandbox=sandbox, kinds=kinds)
        except Exception:
            log.exception("worker loop error; retrying")
            ran = 0
        if not ran:
            stopping.wait(poll)
    log.info("worker %s stopped", worker_id)
