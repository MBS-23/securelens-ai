"""The unified finding model and everything that hangs off a finding.

A ``Finding`` is a project-level issue identified by a scoped fingerprint; it
carries the lifecycle status. Each time a scan (or an AI test run) observes
it, a ``FindingOccurrence`` records where and with what ``Evidence``. History
is never deleted: occurrences, analyses, remediations and retest results
accumulate.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from securelens.models.base import Base, Timestamps, UUIDPrimaryKey


class Finding(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("project_id", "fingerprint"),
        UniqueConstraint("project_id", "public_id"),
        Index("ix_findings_project_status_severity", "project_id", "status", "severity"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    repository_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("repositories.id", ondelete="SET NULL"), default=None, index=True
    )
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("ai_targets.id", ondelete="SET NULL"), default=None, index=True
    )
    public_id: Mapped[str] = mapped_column(String(24))
    fingerprint: Mapped[str] = mapped_column(String(64))
    engine_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    engine: Mapped[str] = mapped_column(String(8))
    source_kind: Mapped[str] = mapped_column(String(16))
    rule_id: Mapped[str] = mapped_column(String(120))
    vuln_class: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(300))
    category: Mapped[str] = mapped_column(String(120))
    severity: Mapped[str] = mapped_column(String(12))
    confidence: Mapped[str] = mapped_column(String(12))
    verification: Mapped[str] = mapped_column(String(16), default="DETECTED")
    status: Mapped[str] = mapped_column(String(16), default="OPEN")
    exploitability: Mapped[str] = mapped_column(String(20), default="POSSIBLE")
    cwe: Mapped[list[Any]] = mapped_column(default=list)
    owasp: Mapped[list[Any]] = mapped_column(default=list)
    file_path: Mapped[str | None] = mapped_column(String(1024), default=None)
    line: Mapped[int | None] = mapped_column(Integer, default=None)
    description: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    remediation_guidance: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list[Any]] = mapped_column(default=list)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    first_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), default=None
    )
    last_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), default=None
    )
    first_seen_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("test_runs.id", ondelete="SET NULL"), default=None
    )
    last_seen_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("test_runs.id", ondelete="SET NULL"), default=None
    )
    first_seen_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]
    resolved_at: Mapped[datetime | None] = mapped_column(default=None)
    resolved_by_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), default=None
    )
    status_reason: Mapped[str | None] = mapped_column(Text, default=None)
    status_changed_at: Mapped[datetime | None] = mapped_column(default=None)
    status_changed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )

    occurrences: Mapped[list[FindingOccurrence]] = relationship(
        back_populates="finding", order_by="FindingOccurrence.created_at"
    )


class FindingOccurrence(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "finding_occurrences"
    __table_args__ = (
        UniqueConstraint("finding_id", "scan_id"),
        UniqueConstraint("finding_id", "test_run_id"),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), default=None, index=True
    )
    test_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("test_runs.id", ondelete="CASCADE"), default=None, index=True
    )
    file_path: Mapped[str | None] = mapped_column(String(1024), default=None)
    start_line: Mapped[int | None] = mapped_column(Integer, default=None)
    end_line: Mapped[int | None] = mapped_column(Integer, default=None)
    start_col: Mapped[int | None] = mapped_column(Integer, default=None)
    end_col: Mapped[int | None] = mapped_column(Integer, default=None)
    function_name: Mapped[str | None] = mapped_column(String(300), default=None)
    snippet: Mapped[str | None] = mapped_column(Text, default=None)
    severity: Mapped[str] = mapped_column(String(12))
    confidence: Mapped[str] = mapped_column(String(12))
    scanners: Mapped[list[Any]] = mapped_column(default=list)
    correlation: Mapped[dict[str, Any]] = mapped_column(default=dict)

    finding: Mapped[Finding] = relationship(back_populates="occurrences")
    evidence: Mapped[list[Evidence]] = relationship(back_populates="occurrence", order_by="Evidence.created_at")


class Evidence(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "evidence"

    occurrence_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("finding_occurrences.id", ondelete="CASCADE"), index=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(24))
    source: Mapped[str] = mapped_column(String(64))
    summary: Mapped[str] = mapped_column(Text)
    location: Mapped[dict[str, Any] | None] = mapped_column(default=None)
    data: Mapped[dict[str, Any]] = mapped_column(default=dict)

    occurrence: Mapped[FindingOccurrence] = relationship(back_populates="evidence")


class SecretFinding(UUIDPrimaryKey, Timestamps, Base):
    """Secret-specific metadata. The secret itself is never stored — only a
    masked rendering and a keyed hash used to recognise the same value again."""

    __tablename__ = "secret_findings"

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    secret_type: Mapped[str] = mapped_column(String(100))
    file_path: Mapped[str] = mapped_column(String(1024))
    line: Mapped[int] = mapped_column(Integer)
    masked_value: Mapped[str] = mapped_column(String(200))
    secret_hash: Mapped[str] = mapped_column(String(64), index=True)
    entropy: Mapped[float | None] = mapped_column(Float, default=None)
    detector: Mapped[str] = mapped_column(String(64))


class AIAnalysis(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "ai_analyses"

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(16), default="QUEUED")
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str | None] = mapped_column(String(120), default=None)
    verdict: Mapped[str | None] = mapped_column(String(32), default=None)
    output: Mapped[dict[str, Any] | None] = mapped_column(default=None)
    raw_output_excerpt: Mapped[str | None] = mapped_column(Text, default=None)
    context_sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    prompt_version: Mapped[str] = mapped_column(String(16))
    input_tokens: Mapped[int | None] = mapped_column(Integer, default=None)
    output_tokens: Mapped[int | None] = mapped_column(Integer, default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )


class Remediation(UUIDPrimaryKey, Timestamps, Base):
    """A proposed fix. Never applied silently: a developer must review it, and a
    subsequent scan decides whether the finding is actually resolved."""

    __tablename__ = "remediations"

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    ai_analysis_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("ai_analyses.id", ondelete="SET NULL"), default=None
    )
    origin: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="PROPOSED")
    file_path: Mapped[str | None] = mapped_column(String(1024), default=None)
    source_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), default=None
    )
    base_sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    patch: Mapped[str | None] = mapped_column(Text, default=None)
    changes: Mapped[list[Any]] = mapped_column(default=list)
    summary: Mapped[str] = mapped_column(Text, default="")
    validation: Mapped[dict[str, Any]] = mapped_column(default=dict)
    applied_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("snapshots.id", ondelete="SET NULL"), default=None
    )
    retest_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), default=None
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    decided_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    decided_at: Mapped[datetime | None] = mapped_column(default=None)
    decision_note: Mapped[str | None] = mapped_column(Text, default=None)


class Retest(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "retests"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(8))  # SCAN | AI_RUN
    baseline_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), default=None
    )
    retest_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), default=None, index=True
    )
    baseline_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("test_runs.id", ondelete="SET NULL"), default=None
    )
    retest_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("test_runs.id", ondelete="SET NULL"), default=None, index=True
    )
    status: Mapped[str] = mapped_column(String(16), default="COMPLETED")
    summary: Mapped[dict[str, Any]] = mapped_column(default=dict)
    gate_status: Mapped[str | None] = mapped_column(String(8), default=None)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )


class RetestResult(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "retest_results"
    __table_args__ = (UniqueConstraint("retest_id", "finding_id"),)

    retest_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("retests.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    result: Mapped[str] = mapped_column(String(16))
    match_method: Mapped[str] = mapped_column(String(16), default="NONE")
    before: Mapped[dict[str, Any] | None] = mapped_column(default=None)
    after: Mapped[dict[str, Any] | None] = mapped_column(default=None)
    notes: Mapped[str | None] = mapped_column(Text, default=None)
