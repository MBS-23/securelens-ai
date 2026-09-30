"""Role-based access control.

Roles are granted per organization (``Membership``). OWNER, ADMIN and
SECURITY_ANALYST see every project in their organization; DEVELOPER and VIEWER
see only projects they are explicitly added to (``ProjectMember``). Nobody
ever sees another organization's data.
"""

from __future__ import annotations

from enum import StrEnum

from securelens.enums import ROLE_RANK, FindingStatus, Role


class Permission(StrEnum):
    PROJECT_READ = "project:read"
    PROJECT_CREATE = "project:create"
    PROJECT_UPDATE = "project:update"
    PROJECT_DELETE = "project:delete"
    PROJECT_MEMBERS_MANAGE = "project:members:manage"
    SCAN_READ = "scan:read"
    SCAN_CREATE = "scan:create"
    SCAN_CANCEL = "scan:cancel"
    FINDING_READ = "finding:read"
    FINDING_UPDATE_STATUS = "finding:update_status"
    FINDING_TRIAGE = "finding:triage"
    AI_ANALYSIS_REQUEST = "ai_analysis:request"
    REMEDIATION_CREATE = "remediation:create"
    REMEDIATION_DECIDE = "remediation:decide"
    REPORT_READ = "report:read"
    REPORT_CREATE = "report:create"
    AISEC_READ = "aisec:read"
    AISEC_RUN = "aisec:run"
    AISEC_MANAGE = "aisec:manage"
    INTEGRATION_READ = "integration:read"
    INTEGRATION_MANAGE = "integration:manage"
    SETTINGS_READ = "settings:read"
    SETTINGS_MANAGE = "settings:manage"
    AUDIT_READ = "audit:read"
    MEMBER_READ = "member:read"
    MEMBER_MANAGE = "member:manage"
    APIKEY_MANAGE = "apikey:manage"


_VIEWER = {
    Permission.PROJECT_READ,
    Permission.SCAN_READ,
    Permission.FINDING_READ,
    Permission.REPORT_READ,
    Permission.AISEC_READ,
}
_DEVELOPER = _VIEWER | {
    Permission.SCAN_CREATE,
    Permission.FINDING_UPDATE_STATUS,
    Permission.AI_ANALYSIS_REQUEST,
    Permission.REMEDIATION_CREATE,
    Permission.REMEDIATION_DECIDE,
    Permission.REPORT_CREATE,
}
_ANALYST = _DEVELOPER | {
    Permission.PROJECT_CREATE,
    Permission.SCAN_CANCEL,
    Permission.FINDING_TRIAGE,
    Permission.AISEC_RUN,
    Permission.AISEC_MANAGE,
    Permission.INTEGRATION_READ,
    Permission.SETTINGS_READ,
    Permission.MEMBER_READ,
}
_ADMIN = _ANALYST | {
    Permission.PROJECT_UPDATE,
    Permission.PROJECT_DELETE,
    Permission.PROJECT_MEMBERS_MANAGE,
    Permission.INTEGRATION_MANAGE,
    Permission.SETTINGS_MANAGE,
    Permission.AUDIT_READ,
    Permission.MEMBER_MANAGE,
    Permission.APIKEY_MANAGE,
}

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset(_VIEWER),
    Role.DEVELOPER: frozenset(_DEVELOPER),
    Role.SECURITY_ANALYST: frozenset(_ANALYST),
    Role.ADMIN: frozenset(_ADMIN),
    Role.OWNER: frozenset(Permission),
}

# Roles that can see every project in their organization.
ORG_WIDE_PROJECT_ROLES = frozenset({Role.OWNER, Role.ADMIN, Role.SECURITY_ANALYST})

# Status transitions that need triage rights rather than plain update rights:
# declaring something a false positive or accepting its risk is a security
# decision, not a development one.
TRIAGE_STATUSES = frozenset({FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK})


def has_permission(role: Role | str, permission: Permission) -> bool:
    try:
        return permission in ROLE_PERMISSIONS[Role(role)]
    except ValueError:
        return False


def role_at_least(role: Role | str, minimum: Role) -> bool:
    return ROLE_RANK[Role(role)] >= ROLE_RANK[minimum]


def can_assign_role(actor_role: Role | str, target_role: Role | str) -> bool:
    """Admins manage roles below their own; only owners grant OWNER or ADMIN."""
    actor, target = Role(actor_role), Role(target_role)
    if actor == Role.OWNER:
        return True
    if actor == Role.ADMIN:
        return ROLE_RANK[target] < ROLE_RANK[Role.ADMIN]
    return False


def permissions_for(role: Role | str) -> list[str]:
    return sorted(p.value for p in ROLE_PERMISSIONS[Role(role)])
