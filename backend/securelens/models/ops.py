"""Operational tables: the job queue, reports, integrations and the audit log."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from securelens.models.base import Base, SoftDelete, Timestamps, UTCDateTime, UUIDPrimaryKey, utcnow


class Job(UUIDPrimaryKey, Timestamps, Base):
    """Database-backed work queue consumed by ``securelens-worker``.

    Workers claim jobs atomically (``FOR UPDATE SKIP LOCKED`` on PostgreSQL,
    a guarded UPDATE on SQLite), so several workers can run safely.
    """

    __tablename__ = "jobs"
    __table_args__ = (Index("ix_jobs_status_run_after", "status", "run_after"),)

    kind: Mapped[str] = mapped_column(String(32))
    payload: Mapped[dict[str, Any]] = mapped_column(default=dict)
    status: Mapped[str] = mapped_column(String(16), default="QUEUED")
    priority: Mapped[int] = mapped_column(Integer, default=100)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=2)
    run_after: Mapped[datetime] = mapped_column(default=utcnow)
    locked_by: Mapped[str | None] = mapped_column(String(120), default=None)
    locked_at: Mapped[datetime | None] = mapped_column(default=None)
    heartbeat_at: Mapped[datetime | None] = mapped_column(default=None)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)
    last_error: Mapped[str | None] = mapped_column(Text, default=None)


class Report(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "reports"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), default=None
    )
    test_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("test_runs.id", ondelete="SET NULL"), default=None
    )
    format: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(300))
    content: Mapped[str] = mapped_column(Text)
    content_type: Mapped[str] = mapped_column(String(100))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    generated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )


class Integration(UUIDPrimaryKey, Timestamps, SoftDelete, Base):
    """External integration. ``config`` holds references to secrets
    (``env:NAME``), never the secret values themselves."""

    __tablename__ = "integrations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), default=None, index=True
    )
    kind: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(200))
    config: Mapped[dict[str, Any]] = mapped_column(default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_event_at: Mapped[datetime | None] = mapped_column(default=None)


class AuditLog(UUIDPrimaryKey, Base):
    """Append-only record of security-relevant actions.

    Deliberately has no ``updated_at``: rows are never modified.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_org_created", "organization_id", "created_at"),)

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="SET NULL"), default=None
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None, index=True
    )
    actor_api_key_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("api_keys.id", ondelete="SET NULL"), default=None
    )
    actor_label: Mapped[str | None] = mapped_column(String(320), default=None)
    action: Mapped[str] = mapped_column(String(100), index=True)
    outcome: Mapped[str] = mapped_column(String(16), default="SUCCESS")
    target_type: Mapped[str | None] = mapped_column(String(50), default=None)
    target_id: Mapped[str | None] = mapped_column(String(64), default=None)
    ip: Mapped[str | None] = mapped_column(String(64), default=None)
    user_agent: Mapped[str | None] = mapped_column(String(300), default=None)
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, server_default=func.now())
