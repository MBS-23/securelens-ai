from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

from securelens.enums import Role
from securelens.schemas.common import APIModel, ORMModel


def _normalise_email(value: str) -> str:
    return value.strip().lower()


class LoginIn(APIModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("email")
    @classmethod
    def _norm(cls, value: str) -> str:
        return _normalise_email(value)


class BootstrapIn(APIModel):
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=1, max_length=256)
    organization_name: str = Field(min_length=2, max_length=200)
    bootstrap_token: str | None = Field(default=None, max_length=256)


class ChangePasswordIn(APIModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class MembershipOut(BaseModel):
    organization_id: uuid.UUID
    organization_name: str
    organization_slug: str
    role: Role
    permissions: list[str]


class UserOut(ORMModel):
    id: uuid.UUID
    email: str
    display_name: str
    is_active: bool
    last_login_at: datetime | None = None
    created_at: datetime


class MeOut(BaseModel):
    user: UserOut | None
    api_key_prefix: str | None = None
    memberships: list[MembershipOut]
    csrf_token: str | None = None


class LoginOut(BaseModel):
    user: UserOut
    memberships: list[MembershipOut]
    csrf_token: str
    expires_at: datetime


class OrganizationOut(ORMModel):
    id: uuid.UUID
    name: str
    slug: str
    created_at: datetime


class OrganizationCreateIn(APIModel):
    name: str = Field(min_length=2, max_length=200)


class MemberOut(BaseModel):
    membership_id: uuid.UUID
    user_id: uuid.UUID
    email: str
    display_name: str
    role: Role
    is_active: bool
    created_at: datetime


class MemberCreateIn(APIModel):
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=200)
    role: Role
    # Only used when the account does not exist yet.
    initial_password: str | None = Field(default=None, max_length=256)


class MemberUpdateIn(APIModel):
    role: Role


class APIKeyCreateIn(APIModel):
    name: str = Field(min_length=1, max_length=200)
    role: Role = Role.DEVELOPER
    project_id: uuid.UUID | None = None
    expires_in_days: int | None = Field(default=90, ge=1, le=730)


class APIKeyOut(ORMModel):
    id: uuid.UUID
    name: str
    prefix: str
    role: Role
    project_id: uuid.UUID | None
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None


class APIKeyCreatedOut(APIKeyOut):
    key: str = Field(description="Shown once. Store it in your CI secret store.")


class AuditLogOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    actor_user_id: uuid.UUID | None
    actor_api_key_id: uuid.UUID | None
    actor_label: str | None
    action: str
    outcome: str
    target_type: str | None
    target_id: str | None
    ip: str | None
    user_agent: str | None
    details: dict
    created_at: datetime
