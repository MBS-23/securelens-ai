"""Identity and access: organizations, users, memberships, sessions, API keys."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from securelens.models.base import Base, SoftDelete, Timestamps, UUIDPrimaryKey


class Organization(UUIDPrimaryKey, Timestamps, SoftDelete, Base):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(100), unique=True)
    # Risk-engine weights and the default security-gate policy. Never secrets.
    settings: Mapped[dict[str, Any]] = mapped_column(default=dict)

    memberships: Mapped[list[Membership]] = relationship(back_populates="organization")


class User(UUIDPrimaryKey, Timestamps, SoftDelete, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True)
    display_name: Mapped[str] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(default=None)
    last_login_at: Mapped[datetime | None] = mapped_column(default=None)
    password_changed_at: Mapped[datetime | None] = mapped_column(default=None)

    memberships: Mapped[list[Membership]] = relationship(back_populates="user")


class Membership(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("organization_id", "user_id"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(32))

    organization: Mapped[Organization] = relationship(back_populates="memberships")
    user: Mapped[User] = relationship(back_populates="memberships")


class UserSession(UUIDPrimaryKey, Timestamps, Base):
    """Opaque server-side session. Only a SHA-256 of the token is stored."""

    __tablename__ = "sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]
    ip: Mapped[str | None] = mapped_column(String(64), default=None)
    user_agent: Mapped[str | None] = mapped_column(String(300), default=None)
    revoked_at: Mapped[datetime | None] = mapped_column(default=None)

    user: Mapped[User] = relationship()


class APIKey(UUIDPrimaryKey, Timestamps, Base):
    """Credential for the CLI and CI pipelines. Only a SHA-256 of the key is stored."""

    __tablename__ = "api_keys"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), default=None, index=True
    )
    name: Mapped[str] = mapped_column(String(200))
    prefix: Mapped[str] = mapped_column(String(16), index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    role: Mapped[str] = mapped_column(String(32))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    last_used_at: Mapped[datetime | None] = mapped_column(default=None)
    expires_at: Mapped[datetime | None] = mapped_column(default=None)
    revoked_at: Mapped[datetime | None] = mapped_column(default=None)
