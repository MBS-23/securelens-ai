"""Organizations, members, API keys and the audit log."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from securelens.api.deps import get_principal, get_user_principal, require_org_permission
from securelens.core import audit
from securelens.core.database import get_db
from securelens.core.errors import Forbidden
from securelens.core.permissions import Permission
from securelens.core.principal import Principal
from securelens.enums import Role
from securelens.models import APIKey, AuditLog, Membership, Organization
from securelens.schemas.common import Message, Page
from securelens.schemas.identity import (
    APIKeyCreatedOut,
    APIKeyCreateIn,
    APIKeyOut,
    AuditLogOut,
    MemberCreateIn,
    MemberOut,
    MemberUpdateIn,
    OrganizationCreateIn,
    OrganizationOut,
)
from securelens.services import identity

router = APIRouter(prefix="/organizations", tags=["organizations"])


@router.get("", response_model=list[OrganizationOut])
def list_organizations(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    if not principal.roles:
        return []
    return db.scalars(
        select(Organization)
        .where(Organization.id.in_(principal.org_ids()), Organization.deleted_at.is_(None))
        .order_by(Organization.name)
    ).all()


@router.post("", response_model=OrganizationOut, status_code=201)
def create_organization(body: OrganizationCreateIn, principal: Principal = Depends(get_user_principal),
                        db: Session = Depends(get_db)):
    # Only people who already own an organization may create another one.
    if Role.OWNER not in principal.roles.values():
        raise Forbidden("Only organization owners can create organizations")
    assert principal.user is not None
    org = identity.create_organization(db, name=body.name, owner=principal.user)
    audit.record(db, "organization.create", principal=principal, organization_id=org.id,
                 target_type="organization", target_id=org.id, details={"name": org.name})
    db.commit()
    return org


def _member_out(membership, user) -> MemberOut:
    return MemberOut(membership_id=membership.id, user_id=user.id, email=user.email,
                     display_name=user.display_name, role=Role(membership.role), is_active=user.is_active,
                     created_at=membership.created_at)


@router.get("/{organization_id}/members", response_model=list[MemberOut])
def list_members(organization_id: uuid.UUID, principal: Principal = Depends(get_principal),
                 db: Session = Depends(get_db)):
    require_org_permission(principal, organization_id, Permission.MEMBER_READ)
    return [_member_out(m, u) for m, u in identity.list_members(db, organization_id)]


@router.post("/{organization_id}/members", response_model=MemberOut, status_code=201)
def add_member(organization_id: uuid.UUID, body: MemberCreateIn, principal: Principal = Depends(get_principal),
               db: Session = Depends(get_db)):
    require_org_permission(principal, organization_id, Permission.MEMBER_MANAGE)
    membership, user = identity.add_member(db, principal, organization_id, email=str(body.email),
                                           display_name=body.display_name, role=body.role,
                                           initial_password=body.initial_password)
    return _member_out(membership, user)


@router.patch("/{organization_id}/members/{membership_id}", response_model=MemberOut)
def update_member(organization_id: uuid.UUID, membership_id: uuid.UUID, body: MemberUpdateIn,
                  principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    require_org_permission(principal, organization_id, Permission.MEMBER_MANAGE)
    membership = identity.update_member(db, principal, organization_id, membership_id, body.role)
    from securelens.models import User

    return _member_out(membership, db.get(User, membership.user_id))


@router.delete("/{organization_id}/members/{membership_id}", response_model=Message)
def remove_member(organization_id: uuid.UUID, membership_id: uuid.UUID,
                  principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    require_org_permission(principal, organization_id, Permission.MEMBER_MANAGE)
    identity.remove_member(db, principal, organization_id, membership_id)
    return Message(message="Member removed")


@router.get("/{organization_id}/api-keys", response_model=list[APIKeyOut])
def list_api_keys(organization_id: uuid.UUID, principal: Principal = Depends(get_principal),
                  db: Session = Depends(get_db)):
    require_org_permission(principal, organization_id, Permission.APIKEY_MANAGE)
    return db.scalars(select(APIKey).where(APIKey.organization_id == organization_id)
                      .order_by(APIKey.created_at.desc())).all()


@router.post("/{organization_id}/api-keys", response_model=APIKeyCreatedOut, status_code=201)
def create_api_key(organization_id: uuid.UUID, body: APIKeyCreateIn,
                   principal: Principal = Depends(get_user_principal), db: Session = Depends(get_db)):
    require_org_permission(principal, organization_id, Permission.APIKEY_MANAGE)
    key, full = identity.create_api_key(db, principal, organization_id, name=body.name, role=body.role,
                                        project_id=body.project_id, expires_in_days=body.expires_in_days)
    return APIKeyCreatedOut(**APIKeyOut.model_validate(key).model_dump(), key=full)


@router.delete("/{organization_id}/api-keys/{key_id}", response_model=APIKeyOut)
def revoke_api_key(organization_id: uuid.UUID, key_id: uuid.UUID, principal: Principal = Depends(get_principal),
                   db: Session = Depends(get_db)):
    require_org_permission(principal, organization_id, Permission.APIKEY_MANAGE)
    return identity.revoke_api_key(db, principal, organization_id, key_id)


@router.get("/{organization_id}/audit-logs", response_model=Page[AuditLogOut])
def audit_logs(
    organization_id: uuid.UUID,
    action: str | None = Query(None, max_length=100),
    outcome: str | None = Query(None, max_length=16),
    actor: str | None = Query(None, max_length=320),
    since: datetime | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    require_org_permission(principal, organization_id, Permission.AUDIT_READ)
    # Organization events, plus account-level events (sign-in, password
    # changes) that concern people who are currently members.
    member_ids = list(db.scalars(select(Membership.user_id).where(Membership.organization_id == organization_id)))
    query = select(AuditLog).where(
        or_(
            AuditLog.organization_id == organization_id,
            and_(
                AuditLog.organization_id.is_(None),
                or_(
                    AuditLog.actor_user_id.in_(member_ids),
                    and_(AuditLog.target_type == "user", AuditLog.target_id.in_([str(m) for m in member_ids])),
                ),
            ),
        )
    )
    if action:
        query = query.where(AuditLog.action.startswith(action))
    if outcome:
        query = query.where(AuditLog.outcome == outcome.upper())
    if actor:
        query = query.where(AuditLog.actor_label.contains(actor.lower()))
    if since:
        query = query.where(AuditLog.created_at >= since)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(query.order_by(AuditLog.created_at.desc()).offset((page - 1) * page_size)
                      .limit(page_size)).all()
    return Page[AuditLogOut](items=[AuditLogOut.model_validate(r) for r in rows], total=total, page=page,
                             page_size=page_size)
