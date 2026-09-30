"""The authenticated caller, shared by the API layer and the services."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from securelens.enums import Role
from securelens.models import APIKey, Membership, Organization, User, UserSession


@dataclass
class Principal:
    user: User | None
    api_key: APIKey | None
    session: UserSession | None
    roles: dict[uuid.UUID, Role] = field(default_factory=dict)
    project_scope: uuid.UUID | None = None
    ip: str | None = None
    user_agent: str | None = None

    @property
    def label(self) -> str:
        if self.user is not None:
            return self.user.email
        if self.api_key is not None:
            return f"api-key:{self.api_key.prefix}"
        return "anonymous"

    @property
    def user_id(self) -> uuid.UUID | None:
        return self.user.id if self.user else None

    def role_in(self, organization_id: uuid.UUID) -> Role | None:
        return self.roles.get(organization_id)

    def org_ids(self) -> list[uuid.UUID]:
        return list(self.roles)


def load_roles(db: Session, user_id: uuid.UUID) -> dict[uuid.UUID, Role]:
    rows = db.execute(
        select(Membership.organization_id, Membership.role)
        .join(Organization, Organization.id == Membership.organization_id)
        .where(Membership.user_id == user_id, Organization.deleted_at.is_(None))
    ).all()
    return {org_id: Role(role) for org_id, role in rows}


def system_principal(organization_id: uuid.UUID, role: Role = Role.ADMIN, label: str = "system") -> Principal:
    """Used by the worker when it acts on behalf of the platform (e.g. webhooks)."""
    principal = Principal(user=None, api_key=None, session=None, roles={organization_id: role})
    principal.ip = None
    principal.user_agent = label
    return principal
