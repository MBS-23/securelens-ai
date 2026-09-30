"""Audit logging for security-relevant actions.

Callers pass only non-sensitive metadata. Rows are added to the caller's
session so they commit atomically with the action they describe; failure paths
(e.g. a rejected login) commit explicitly.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy.orm import Session

from securelens.models.ops import AuditLog

if TYPE_CHECKING:  # pragma: no cover
    from securelens.core.principal import Principal

_MAX_DETAIL_CHARS = 2000


def _clip(value: Any) -> Any:
    if isinstance(value, str):
        return value[:_MAX_DETAIL_CHARS]
    if isinstance(value, dict):
        return {str(k)[:100]: _clip(v) for k, v in list(value.items())[:50]}
    if isinstance(value, list | tuple):
        return [_clip(v) for v in list(value)[:50]]
    if isinstance(value, uuid.UUID):
        return str(value)
    return value


def record(
    db: Session,
    action: str,
    *,
    principal: Principal | None = None,
    organization_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: uuid.UUID | str | None = None,
    outcome: str = "SUCCESS",
    details: dict[str, Any] | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    actor_label: str | None = None,
) -> AuditLog:
    entry = AuditLog(
        organization_id=organization_id,
        actor_user_id=principal.user.id if principal and principal.user else None,
        actor_api_key_id=principal.api_key.id if principal and principal.api_key else None,
        actor_label=(actor_label or (principal.label if principal else None)),
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        ip=ip or (principal.ip if principal else None),
        user_agent=((user_agent or (principal.user_agent if principal else None)) or "")[:300] or None,
        details=_clip(details or {}),
    )
    db.add(entry)
    return entry
