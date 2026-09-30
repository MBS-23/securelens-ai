"""External integrations and the secret references they use.

Integration ``config`` never holds a secret value. It holds a reference such
as ``env:SECURELENS_INTEGRATION_GITHUB_TOKEN`` that the worker resolves from
its environment when it needs the value. Only variables with the
``SECURELENS_INTEGRATION_`` prefix can be referenced, so an administrator
cannot point an integration at the application key or the database URL and
have it sent to a third party.
"""

from __future__ import annotations

import os
import re
from urllib.parse import urlsplit

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from securelens.core.errors import AppError
from securelens.enums import IntegrationKind
from securelens.models import Integration, Project, Repository

SECRET_REF_PREFIX = "env:"  # noqa: S105 - a reference prefix, not a secret
ALLOWED_ENV_PREFIX = "SECURELENS_INTEGRATION_"
_ENV_NAME = re.compile(r"^SECURELENS_INTEGRATION_[A-Z0-9_]{1,80}$")
DEFAULT_GIT_HOSTS = {IntegrationKind.GITHUB: ["github.com"]}


def validate_secret_ref(ref: str | None) -> str | None:
    """Accept ``env:SECURELENS_INTEGRATION_*`` references (or nothing)."""
    if ref is None or ref == "":
        return None
    if not ref.startswith(SECRET_REF_PREFIX) or not _ENV_NAME.match(ref[len(SECRET_REF_PREFIX):]):
        raise AppError(f"Secret references must look like env:{ALLOWED_ENV_PREFIX}NAME; secret values are never "
                       "stored in SecureLens", code="invalid_secret_ref", status_code=422)
    return ref


def resolve_secret_ref(ref: str | None) -> str | None:
    """Value of a validated reference, or None when it is missing or unset."""
    if not ref or not ref.startswith(SECRET_REF_PREFIX):
        return None
    name = ref[len(SECRET_REF_PREFIX):]
    if not _ENV_NAME.match(name):
        return None
    value = os.environ.get(name, "")
    return value or None


def secret_ref_status(ref: str | None) -> str:
    """For display: whether a reference is configured and resolvable — never the value."""
    if not ref:
        return "not configured"
    return "available" if resolve_secret_ref(ref) else "missing in the worker environment"


def integrations_for_project(db: Session, project: Project, kind: str | None = None) -> list[Integration]:
    query = select(Integration).where(
        Integration.organization_id == project.organization_id,
        Integration.enabled.is_(True),
        Integration.deleted_at.is_(None),
        or_(Integration.project_id.is_(None), Integration.project_id == project.id),
    )
    if kind:
        query = query.where(Integration.kind == kind)
    rows = list(db.scalars(query))
    # A project-specific integration takes precedence over an organization-wide one.
    rows.sort(key=lambda i: i.project_id is None)
    return rows


def git_token_for(db: Session, repo: Repository) -> str | None:
    """Token for cloning a private repository, from an enabled integration for its host."""
    if not repo.url:
        return None
    host = (urlsplit(repo.url).hostname or "").lower()
    project = db.get(Project, repo.project_id)
    if project is None:
        return None
    for integration in integrations_for_project(db, project):
        config = integration.config or {}
        hosts = [h.lower() for h in config.get("git_hosts") or DEFAULT_GIT_HOSTS.get(integration.kind, [])]
        if host in hosts:
            token = resolve_secret_ref(config.get("token_ref"))
            if token:
                return token
    return None
