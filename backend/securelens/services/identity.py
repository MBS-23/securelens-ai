"""Accounts, sessions, organization membership and API keys."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from securelens.core import audit
from securelens.core.config import get_settings
from securelens.core.errors import AppError, Conflict, Forbidden, NotFound, Unauthorized
from securelens.core.permissions import can_assign_role, permissions_for
from securelens.core.security import (
    PasswordPolicyError,
    csrf_token_for,
    generate_api_key,
    hash_password,
    new_token,
    password_needs_rehash,
    sha256_hex,
    validate_password,
    verify_password,
)
from securelens.enums import ROLE_RANK, Role
from securelens.models import APIKey, Membership, Organization, Project, User, UserSession
from securelens.models.base import utcnow
from securelens.schemas.common import slugify
from securelens.schemas.identity import MembershipOut

if TYPE_CHECKING:  # pragma: no cover
    from securelens.core.principal import Principal


def normalise_email(email: str) -> str:
    return email.strip().lower()


def _check_password(password: str, email: str) -> None:
    try:
        validate_password(password, email=email)
    except PasswordPolicyError as exc:
        raise AppError(str(exc), code="weak_password", status_code=422) from exc


def unique_org_slug(db: Session, name: str) -> str:
    base = slugify(name, 90)
    slug, n = base, 1
    while db.scalar(select(Organization.id).where(Organization.slug == slug)) is not None:
        n += 1
        slug = f"{base}-{n}"
    return slug


def create_user(db: Session, *, email: str, display_name: str, password: str) -> User:
    email = normalise_email(email)
    if db.scalar(select(User.id).where(User.email == email)) is not None:
        raise Conflict("An account with this email already exists")
    _check_password(password, email)
    user = User(
        email=email,
        display_name=display_name.strip(),
        password_hash=hash_password(password),
        password_changed_at=utcnow(),
    )
    db.add(user)
    db.flush()
    return user


def create_organization(db: Session, *, name: str, owner: User) -> Organization:
    org = Organization(name=name.strip(), slug=unique_org_slug(db, name), settings={})
    db.add(org)
    db.flush()
    db.add(Membership(organization_id=org.id, user_id=owner.id, role=Role.OWNER))
    db.flush()
    return org


def users_exist(db: Session) -> bool:
    return (db.scalar(select(func.count(User.id))) or 0) > 0


def bootstrap(db: Session, *, email: str, display_name: str, password: str, organization_name: str,
              bootstrap_token: str | None, ip: str | None) -> tuple[User, Organization]:
    settings = get_settings()
    if users_exist(db):
        raise Conflict("This instance is already initialised", code="already_initialised")
    expected = settings.bootstrap_token.get_secret_value() if settings.bootstrap_token else None
    if settings.environment == "production" and not expected:
        raise Forbidden("Set SECURELENS_BOOTSTRAP_TOKEN (or use `securelens-manage bootstrap`) to initialise")
    if expected and bootstrap_token != expected:
        raise Forbidden("Invalid bootstrap token")
    user = create_user(db, email=email, display_name=display_name, password=password)
    org = create_organization(db, name=organization_name, owner=user)
    audit.record(db, "instance.bootstrap", organization_id=org.id, target_type="user", target_id=user.id,
                 actor_label=user.email, ip=ip)
    db.commit()
    return user, org


@dataclass
class LoginResult:
    user: User
    session: UserSession
    token: str
    csrf_token: str


def login(db: Session, *, email: str, password: str, ip: str | None, user_agent: str | None) -> LoginResult:
    settings = get_settings()
    email = normalise_email(email)
    user = db.scalar(select(User).where(User.email == email, User.deleted_at.is_(None)))
    now = utcnow()

    if user is not None and user.locked_until is not None and user.locked_until > now:
        # Still spend the hashing time so lockout is not observable by timing.
        verify_password(password, None)
        audit.record(db, "auth.login", outcome="DENIED", target_type="user", target_id=user.id,
                     actor_label=email, ip=ip, user_agent=user_agent, details={"reason": "locked"})
        db.commit()
        raise Unauthorized("Invalid email or password, or the account is temporarily locked")

    ok = verify_password(password, user.password_hash if user else None)
    if not ok or user is None or not user.is_active:
        if user is not None:
            user.failed_login_count += 1
            if user.failed_login_count >= settings.login_max_failures:
                user.locked_until = now + timedelta(minutes=settings.login_lockout_minutes)
                user.failed_login_count = 0
        audit.record(db, "auth.login", outcome="FAILURE", target_type="user",
                     target_id=user.id if user else None, actor_label=email, ip=ip, user_agent=user_agent)
        db.commit()
        raise Unauthorized("Invalid email or password, or the account is temporarily locked")

    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    token = new_token()
    session = UserSession(
        user_id=user.id,
        token_hash=sha256_hex(token),
        expires_at=now + timedelta(minutes=settings.session_ttl_minutes),
        last_seen_at=now,
        ip=ip,
        user_agent=(user_agent or "")[:300] or None,
    )
    db.add(session)
    audit.record(db, "auth.login", target_type="user", target_id=user.id, actor_label=email, ip=ip,
                 user_agent=user_agent)
    db.commit()
    return LoginResult(user=user, session=session, token=token, csrf_token=csrf_token_for(session.token_hash))


def logout(db: Session, principal: Principal) -> None:
    if principal.session is not None:
        principal.session.revoked_at = utcnow()
        audit.record(db, "auth.logout", principal=principal, target_type="user", target_id=principal.user_id)
        db.commit()


def change_password(db: Session, principal: Principal, *, current: str, new: str) -> None:
    user = principal.user
    assert user is not None
    if not verify_password(current, user.password_hash):
        audit.record(db, "auth.password_change", principal=principal, outcome="FAILURE", target_type="user",
                     target_id=user.id)
        db.commit()
        raise Unauthorized("Current password is incorrect")
    _check_password(new, user.email)
    user.password_hash = hash_password(new)
    user.password_changed_at = utcnow()
    # Every other session is revoked; the current one stays valid.
    for other in db.scalars(select(UserSession).where(UserSession.user_id == user.id,
                                                       UserSession.revoked_at.is_(None))):
        if principal.session is None or other.id != principal.session.id:
            other.revoked_at = utcnow()
    audit.record(db, "auth.password_change", principal=principal, target_type="user", target_id=user.id)
    db.commit()


def memberships_for(db: Session, principal: Principal) -> list[MembershipOut]:
    if not principal.roles:
        return []
    orgs = db.scalars(select(Organization).where(Organization.id.in_(principal.org_ids()))).all()
    return [
        MembershipOut(
            organization_id=org.id,
            organization_name=org.name,
            organization_slug=org.slug,
            role=principal.roles[org.id],
            permissions=permissions_for(principal.roles[org.id]),
        )
        for org in sorted(orgs, key=lambda o: o.name.lower())
    ]


# ---------------------------------------------------------------------------
# Members
# ---------------------------------------------------------------------------


def list_members(db: Session, organization_id: uuid.UUID) -> list[tuple[Membership, User]]:
    return list(
        db.execute(
            select(Membership, User)
            .join(User, User.id == Membership.user_id)
            .where(Membership.organization_id == organization_id, User.deleted_at.is_(None))
            .order_by(User.email)
        ).all()
    )


def add_member(db: Session, principal: Principal, organization_id: uuid.UUID, *, email: str,
               display_name: str, role: Role, initial_password: str | None) -> tuple[Membership, User]:
    actor_role = principal.role_in(organization_id)
    assert actor_role is not None
    if not can_assign_role(actor_role, role):
        raise Forbidden("You cannot grant this role")
    email = normalise_email(email)
    user = db.scalar(select(User).where(User.email == email, User.deleted_at.is_(None)))
    if user is None:
        if not initial_password:
            raise AppError("initial_password is required for a new account", code="password_required",
                           status_code=422)
        user = create_user(db, email=email, display_name=display_name, password=initial_password)
    existing = db.scalar(select(Membership).where(Membership.organization_id == organization_id,
                                                  Membership.user_id == user.id))
    if existing is not None:
        raise Conflict("This user is already a member")
    membership = Membership(organization_id=organization_id, user_id=user.id, role=role)
    db.add(membership)
    audit.record(db, "member.add", principal=principal, organization_id=organization_id, target_type="user",
                 target_id=user.id, details={"email": email, "role": role})
    db.commit()
    return membership, user


def _owner_count(db: Session, organization_id: uuid.UUID) -> int:
    return db.scalar(select(func.count(Membership.id)).where(Membership.organization_id == organization_id,
                                                              Membership.role == Role.OWNER)) or 0


def update_member(db: Session, principal: Principal, organization_id: uuid.UUID, membership_id: uuid.UUID,
                  role: Role) -> Membership:
    membership = db.get(Membership, membership_id)
    if membership is None or membership.organization_id != organization_id:
        raise NotFound("Member not found")
    actor_role = principal.role_in(organization_id)
    assert actor_role is not None
    current = Role(membership.role)
    if not can_assign_role(actor_role, role) or not can_assign_role(actor_role, current):
        raise Forbidden("You cannot change this member's role")
    if current == Role.OWNER and role != Role.OWNER and _owner_count(db, organization_id) <= 1:
        raise Conflict("An organization must keep at least one owner")
    membership.role = role
    audit.record(db, "member.role_change", principal=principal, organization_id=organization_id,
                 target_type="user", target_id=membership.user_id, details={"from": current, "to": role})
    db.commit()
    return membership


def remove_member(db: Session, principal: Principal, organization_id: uuid.UUID, membership_id: uuid.UUID) -> None:
    membership = db.get(Membership, membership_id)
    if membership is None or membership.organization_id != organization_id:
        raise NotFound("Member not found")
    actor_role = principal.role_in(organization_id)
    assert actor_role is not None
    current = Role(membership.role)
    if not can_assign_role(actor_role, current):
        raise Forbidden("You cannot remove this member")
    if current == Role.OWNER and _owner_count(db, organization_id) <= 1:
        raise Conflict("An organization must keep at least one owner")
    # Revoke the user's sessions' access to this org implicitly: membership is the grant.
    audit.record(db, "member.remove", principal=principal, organization_id=organization_id,
                 target_type="user", target_id=membership.user_id, details={"role": current})
    db.delete(membership)
    db.commit()


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


def create_api_key(db: Session, principal: Principal, organization_id: uuid.UUID, *, name: str, role: Role,
                   project_id: uuid.UUID | None, expires_in_days: int | None) -> tuple[APIKey, str]:
    actor_role = principal.role_in(organization_id)
    assert actor_role is not None
    # A key can never hold more privilege than the person creating it, and
    # never OWNER: ownership stays with people.
    if role == Role.OWNER or ROLE_RANK[role] > ROLE_RANK[actor_role]:
        raise Forbidden("An API key cannot have a higher role than yours, or the OWNER role")
    if project_id is not None:
        project = db.get(Project, project_id)
        if project is None or project.organization_id != organization_id or project.deleted_at is not None:
            raise NotFound("Project not found")
    elif ROLE_RANK[role] < ROLE_RANK[Role.SECURITY_ANALYST]:
        raise AppError("DEVELOPER and VIEWER keys must be scoped to a project", code="scope_required",
                       status_code=422)
    full, prefix, digest = generate_api_key()
    expires_at: datetime | None = utcnow() + timedelta(days=expires_in_days) if expires_in_days else None
    key = APIKey(organization_id=organization_id, project_id=project_id, name=name.strip(), prefix=prefix,
                 key_hash=digest, role=role, created_by_id=principal.user_id, expires_at=expires_at)
    db.add(key)
    db.flush()
    audit.record(db, "apikey.create", principal=principal, organization_id=organization_id,
                 target_type="api_key", target_id=key.id,
                 details={"name": name, "role": role, "project_id": str(project_id) if project_id else None})
    db.commit()
    return key, full


def revoke_api_key(db: Session, principal: Principal, organization_id: uuid.UUID, key_id: uuid.UUID) -> APIKey:
    key = db.get(APIKey, key_id)
    if key is None or key.organization_id != organization_id:
        raise NotFound("API key not found")
    if key.revoked_at is None:
        key.revoked_at = utcnow()
        audit.record(db, "apikey.revoke", principal=principal, organization_id=organization_id,
                     target_type="api_key", target_id=key.id, details={"prefix": key.prefix})
        db.commit()
    return key
