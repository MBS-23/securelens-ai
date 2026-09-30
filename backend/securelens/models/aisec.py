"""AI Security Engine persistence: targets, the test library, runs and results."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from securelens.models.base import Base, SoftDelete, Timestamps, UUIDPrimaryKey


class AITarget(UUIDPrimaryKey, Timestamps, SoftDelete, Base):
    """An AI application under evaluation.

    ``config`` never contains credentials: header values reference secrets by
    name (``${secret:NAME}``) and are resolved from the environment by the
    worker at request time.
    """

    __tablename__ = "ai_targets"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(16))
    description: Mapped[str] = mapped_column(Text, default="")
    config: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )


class SecurityTest(UUIDPrimaryKey, Timestamps, SoftDelete, Base):
    """A test case. Built-in tests have no organization; custom tests belong to one."""

    __tablename__ = "security_tests"
    __table_args__ = (
        Index(
            "uq_security_tests_builtin_key",
            "test_key",
            unique=True,
            postgresql_where=text("organization_id IS NULL"),
            sqlite_where=text("organization_id IS NULL"),
        ),
        Index(
            "uq_security_tests_org_key",
            "organization_id",
            "test_key",
            unique=True,
            postgresql_where=text("organization_id IS NOT NULL"),
            sqlite_where=text("organization_id IS NOT NULL"),
        ),
    )

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), default=None, index=True
    )
    test_key: Mapped[str] = mapped_column(String(40))
    version: Mapped[int] = mapped_column(Integer, default=1)
    category: Mapped[str] = mapped_column(String(32), index=True)
    subcategory: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    attack_scenario: Mapped[str] = mapped_column(Text, default="")
    expected_behavior: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(12))
    ai_risk_category: Mapped[str] = mapped_column(String(80))
    recommendation: Mapped[str] = mapped_column(Text, default="")
    definition: Mapped[dict[str, Any]] = mapped_column(default=dict)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )


class TestRun(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "test_runs"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ai_targets.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(16), default="QUEUED", index=True)
    config: Mapped[dict[str, Any]] = mapped_column(default=dict)
    baseline_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("test_runs.id", ondelete="SET NULL"), default=None
    )
    summary: Mapped[dict[str, Any]] = mapped_column(default=dict)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    queued_at: Mapped[datetime | None] = mapped_column(default=None)
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )


class TestResult(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "test_results"

    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("test_runs.id", ondelete="CASCADE"), index=True)
    security_test_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("security_tests.id", ondelete="SET NULL"), default=None
    )
    test_key: Mapped[str] = mapped_column(String(40))
    test_version: Mapped[int] = mapped_column(Integer, default=1)
    category: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(300))
    result: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(12))
    failure_layer: Mapped[str | None] = mapped_column(String(24), default=None)
    repetitions: Mapped[int] = mapped_column(Integer, default=1)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    transcript: Mapped[list[Any]] = mapped_column(default=list)
    criteria: Mapped[list[Any]] = mapped_column(default=list)
    observations: Mapped[list[Any]] = mapped_column(default=list)
    reason: Mapped[str | None] = mapped_column(Text, default=None)
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), default=None
    )
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
