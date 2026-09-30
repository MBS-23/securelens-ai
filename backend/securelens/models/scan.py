"""Scans, the files each scan analysed, and the dependency inventory."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from securelens.models.base import Base, Timestamps, UUIDPrimaryKey


class Scan(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_project_created", "project_id", "created_at"),)

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    repository_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("repositories.id", ondelete="SET NULL"), default=None, index=True
    )
    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("snapshots.id", ondelete="SET NULL"), default=None
    )
    status: Mapped[str] = mapped_column(String(16), default="QUEUED", index=True)
    trigger: Mapped[str] = mapped_column(String(16), default="MANUAL")
    scope: Mapped[str] = mapped_column(String(16), default="FULL")
    baseline_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), default=None
    )
    config: Mapped[dict[str, Any]] = mapped_column(default=dict)
    progress: Mapped[dict[str, Any]] = mapped_column(default=dict)
    stats: Mapped[dict[str, Any]] = mapped_column(default=dict)
    risk_index: Mapped[float | None] = mapped_column(Float, default=None)
    gate_status: Mapped[str | None] = mapped_column(String(8), default=None)
    gate_reasons: Mapped[list[Any]] = mapped_column(default=list)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    queued_at: Mapped[datetime | None] = mapped_column(default=None)
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    api_key_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("api_keys.id", ondelete="SET NULL"), default=None
    )


class ScanFile(UUIDPrimaryKey, Timestamps, Base):
    """File inventory of a scan. Content stays in snapshot storage, never here."""

    __tablename__ = "scan_files"
    __table_args__ = (UniqueConstraint("scan_id", "path"),)

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    path: Mapped[str] = mapped_column(String(1024))
    language: Mapped[str | None] = mapped_column(String(32), default=None)
    size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    line_count: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    status: Mapped[str] = mapped_column(String(24))
    detail: Mapped[str | None] = mapped_column(String(500), default=None)


class Dependency(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "dependencies"
    __table_args__ = (
        UniqueConstraint("scan_id", "ecosystem", "name", "version", "manifest_path"),
        Index("ix_dependencies_name", "ecosystem", "name"),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    ecosystem: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(300))
    version: Mapped[str | None] = mapped_column(String(120), default=None)
    version_spec: Mapped[str | None] = mapped_column(String(300), default=None)
    manifest_path: Mapped[str] = mapped_column(String(1024))
    direct: Mapped[bool] = mapped_column(Boolean, default=True)
    dev: Mapped[bool] = mapped_column(Boolean, default=False)
    vuln_status: Mapped[str] = mapped_column(String(32), default="NOT_VERIFIED")
    advisory_ids: Mapped[list[Any]] = mapped_column(default=list)
    source: Mapped[str | None] = mapped_column(String(50), default=None)
