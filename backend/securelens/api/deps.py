"""Authentication, CSRF enforcement and authorization helpers for the API.

Two credential types are accepted:

* a session cookie (browser dashboard) — state-changing requests must also
  carry ``X-CSRF-Token``, an HMAC of the session bound to the server key;
* ``Authorization: Bearer slk_...`` API keys (CLI / CI) — not ambient
  credentials, so no CSRF token is needed.

Object access always goes through ``load_project`` (or a loader that calls
it). Objects outside the caller's reach return 404, not 403, so their
existence is not disclosed.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from securelens.core.config import get_settings
from securelens.core.database import get_db
from securelens.core.errors import Forbidden, NotFound, Unauthorized
from securelens.core.permissions import ORG_WIDE_PROJECT_ROLES, Permission, has_permission
from securelens.core.principal import Principal, load_roles
from securelens.core.ratelimit import client_ip
from securelens.core.security import constant_time_equals, csrf_token_for, looks_like_api_key, sha256_hex
from securelens.enums import Role
from securelens.models import APIKey, Organization, Project, ProjectMember, User, UserSession
from securelens.models.base import utcnow

SESSION_COOKIE = "sl_session"
CSRF_COOKIE = "sl_csrf"
CSRF_HEADER = "x-csrf-token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _authenticate_api_key(db: Session, raw: str, request: Request) -> Principal:
    if not looks_like_api_key(raw):
        raise Unauthorized("Invalid credentials")
    key = db.scalar(select(APIKey).where(APIKey.key_hash == sha256_hex(raw)))
    now = utcnow()
    if key is None or key.revoked_at is not None or (key.expires_at is not None and key.expires_at <= now):
        raise Unauthorized("Invalid credentials")
    org = db.get(Organization, key.organization_id)
    if org is None or org.deleted_at is not None:
        raise Unauthorized("Invalid credentials")
    if key.last_used_at is None or now - key.last_used_at > timedelta(minutes=1):
        key.last_used_at = now
        db.commit()
    return Principal(
        user=None,
        api_key=key,
        session=None,
        roles={key.organization_id: Role(key.role)},
        project_scope=key.project_id,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )


def _authenticate_session(db: Session, token: str, request: Request) -> Principal:
    settings = get_settings()
    session = db.scalar(select(UserSession).where(UserSession.token_hash == sha256_hex(token)))
    now = utcnow()
    if (
        session is None
        or session.revoked_at is not None
        or session.expires_at <= now
        or session.last_seen_at + timedelta(minutes=settings.session_idle_minutes) <= now
    ):
        raise Unauthorized("Session expired or invalid")
    user = db.get(User, session.user_id)
    if user is None or not user.is_active or user.deleted_at is not None:
        raise Unauthorized("Session expired or invalid")

    if request.method not in SAFE_METHODS:
        supplied = request.headers.get(CSRF_HEADER, "")
        if not supplied or not constant_time_equals(supplied, csrf_token_for(session.token_hash)):
            raise Forbidden("Missing or invalid CSRF token", code="csrf_failed")

    if now - session.last_seen_at > timedelta(minutes=1):
        session.last_seen_at = now
        db.commit()

    return Principal(
        user=user,
        api_key=None,
        session=session,
        roles=load_roles(db, user.id),
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )


def get_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return _authenticate_api_key(db, auth[7:].strip(), request)
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        return _authenticate_session(db, token, request)
    raise Unauthorized("Authentication required")


def get_user_principal(principal: Principal = Depends(get_principal)) -> Principal:
    """For endpoints that only make sense for a signed-in person (not an API key)."""
    if principal.user is None:
        raise Forbidden("This action requires a user session")
    return principal


# --------------------------------------------------------------------------
# Authorization helpers
# --------------------------------------------------------------------------


def require_org_permission(principal: Principal, organization_id: uuid.UUID, permission: Permission) -> Role:
    role = principal.role_in(organization_id)
    if role is None:
        raise NotFound("Organization not found")
    if principal.project_scope is not None and permission in {
        Permission.MEMBER_MANAGE,
        Permission.SETTINGS_MANAGE,
        Permission.APIKEY_MANAGE,
        Permission.INTEGRATION_MANAGE,
        Permission.AUDIT_READ,
    }:
        raise Forbidden("Project-scoped API keys cannot perform organization administration")
    if not has_permission(role, permission):
        raise Forbidden("Your role does not allow this action")
    return role


def can_access_project(db: Session, principal: Principal, project: Project) -> bool:
    role = principal.role_in(project.organization_id)
    if role is None or project.deleted_at is not None:
        return False
    if principal.project_scope is not None and principal.project_scope != project.id:
        return False
    if role in ORG_WIDE_PROJECT_ROLES:
        return True
    if principal.user is None:
        # A DEVELOPER/VIEWER API key must be scoped to a project.
        return principal.project_scope == project.id
    return (
        db.scalar(
            select(ProjectMember.id).where(
                ProjectMember.project_id == project.id, ProjectMember.user_id == principal.user.id
            )
        )
        is not None
    )


def load_project(db: Session, principal: Principal, project_id: uuid.UUID, permission: Permission) -> Project:
    project = db.get(Project, project_id)
    if project is None or not can_access_project(db, principal, project):
        raise NotFound("Project not found")
    role = principal.role_in(project.organization_id)
    assert role is not None
    if not has_permission(role, permission):
        raise Forbidden("Your role does not allow this action")
    return project


def accessible_project_ids(db: Session, principal: Principal, organization_id: uuid.UUID | None = None) -> list[uuid.UUID]:
    """Every project the principal may read, optionally within one organization."""
    org_ids = [organization_id] if organization_id else principal.org_ids()
    result: list[uuid.UUID] = []
    for org_id in org_ids:
        role = principal.role_in(org_id)
        if role is None:
            continue
        query = select(Project.id).where(Project.organization_id == org_id, Project.deleted_at.is_(None))
        if principal.project_scope is not None:
            query = query.where(Project.id == principal.project_scope)
        elif role not in ORG_WIDE_PROJECT_ROLES:
            if principal.user is None:
                continue
            member_ids = select(ProjectMember.project_id).where(ProjectMember.user_id == principal.user.id)
            query = query.where(Project.id.in_(member_ids))
        result.extend(db.scalars(query).all())
    return result
