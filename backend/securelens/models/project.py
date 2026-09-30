"""Projects, their members, source repositories and immutable source snapshots."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import BigInteger, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from securelens.models.base import Base, SoftDelete, Timestamps, UUIDPrimaryKey
from securelens.models.identity import Organization


class Project(UUIDPrimaryKey, Timestamps, SoftDelete, Base):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("organization_id", "slug"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")
    # Only used by the risk engine when explicitly supplied.
    business_criticality: Mapped[str | None] = mapped_column(String(16), default=None)
    exposure: Mapped[str] = mapped_column(String(24), default="UNKNOWN")
    gate_policy: Mapped[dict[str, Any] | None] = mapped_column(default=None)
    # Per-project counters for human-readable finding IDs (SL-001, SL-AI-001).
    finding_seq: Mapped[int] = mapped_column(Integer, default=0)
    ai_finding_seq: Mapped[int] = mapped_column(Integer, default=0)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )

    organization: Mapped[Organization] = relationship()


class ProjectMember(UUIDPrimaryKey, Timestamps, Base):
    """Grants DEVELOPER and VIEWER members access to a specific project."""

    __tablename__ = "project_members"
    __table_args__ = (UniqueConstraint("project_id", "user_id"),)

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)


class Repository(UUIDPrimaryKey, Timestamps, SoftDelete, Base):
    """A source of code inside a project: a git remote or a series of uploads."""

    __tablename__ = "repositories"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    source_type: Mapped[str] = mapped_column(String(16))
    url: Mapped[str | None] = mapped_column(String(500), default=None)
    default_branch: Mapped[str | None] = mapped_column(String(200), default=None)


class Snapshot(UUIDPrimaryKey, Timestamps, Base):
    """An immutable copy of the source that a scan analysed.

    The raw bytes live in the storage directory; the database holds metadata.
    A PATCH snapshot is a parent snapshot with a reviewed remediation applied.
    """

    __tablename__ = "snapshots"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    repository_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("repositories.id", ondelete="SET NULL"), default=None, index=True
    )
    origin: Mapped[str] = mapped_column(String(24))
    status: Mapped[str] = mapped_column(String(16), default="PENDING")
    upload_key: Mapped[str | None] = mapped_column(String(300), default=None)
    upload_name: Mapped[str | None] = mapped_column(String(300), default=None)
    parent_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("snapshots.id", ondelete="SET NULL"), default=None
    )
    git_ref: Mapped[str | None] = mapped_column(String(200), default=None)
    git_commit: Mapped[str | None] = mapped_column(String(64), default=None)
    file_count: Mapped[int] = mapped_column(Integer, default=0)
    total_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
