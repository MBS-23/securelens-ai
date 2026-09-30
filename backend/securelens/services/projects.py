"""Projects, project membership and source repositories."""

from __future__ import annotations

import re
import uuid
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from securelens.core import audit
from securelens.core.config import get_settings
from securelens.core.errors import AppError, Conflict, NotFound
from securelens.core.principal import Principal
from securelens.enums import ACTIVE_STATUSES, Severity
from securelens.models import Finding, Membership, Project, ProjectMember, Repository, Scan, User
from securelens.models.base import utcnow
from securelens.schemas.common import slugify
from securelens.schemas.project import ProjectCreateIn, ProjectSummaryOut, ProjectUpdateIn, RepositoryCreateIn

_BRANCH_RE = re.compile(r"^(?!-)(?!.*\.\.)(?!.*//)[A-Za-z0-9._/-]{1,200}(?<!\.lock)(?<!/)$")
_REPO_PATH_RE = re.compile(r"^/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+){1,4}?(\.git)?/?$")


def unique_project_slug(db: Session, organization_id: uuid.UUID, name: str) -> str:
    base = slugify(name, 100)
    slug, n = base, 1
    while db.scalar(select(Project.id).where(Project.organization_id == organization_id,
                                             Project.slug == slug)) is not None:
        n += 1
        slug = f"{base}-{n}"
    return slug


def create_project(db: Session, principal: Principal, body: ProjectCreateIn) -> Project:
    project = Project(
        organization_id=body.organization_id,
        name=body.name.strip(),
        slug=unique_project_slug(db, body.organization_id, body.name),
        description=body.description.strip(),
        business_criticality=body.business_criticality,
        exposure=body.exposure,
        gate_policy=body.gate_policy.model_dump(mode="json") if body.gate_policy else None,
        created_by_id=principal.user_id,
    )
    db.add(project)
    db.flush()
    audit.record(db, "project.create", principal=principal, organization_id=project.organization_id,
                 target_type="project", target_id=project.id, details={"name": project.name})
    db.commit()
    return project


def update_project(db: Session, principal: Principal, project: Project, body: ProjectUpdateIn) -> Project:
    changes: dict[str, object] = {}
    if body.name is not None and body.name.strip() != project.name:
        project.name = body.name.strip()
        changes["name"] = project.name
    if body.description is not None:
        project.description = body.description.strip()
        changes["description"] = True
    if body.clear_business_criticality:
        project.business_criticality = None
        changes["business_criticality"] = None
    elif body.business_criticality is not None:
        project.business_criticality = body.business_criticality
        changes["business_criticality"] = body.business_criticality
    if body.exposure is not None:
        project.exposure = body.exposure
        changes["exposure"] = body.exposure
    if body.clear_gate_policy:
        project.gate_policy = None
        changes["gate_policy"] = None
    elif body.gate_policy is not None:
        project.gate_policy = body.gate_policy.model_dump(mode="json")
        changes["gate_policy"] = project.gate_policy
    audit.record(db, "project.update", principal=principal, organization_id=project.organization_id,
                 target_type="project", target_id=project.id, details=changes)
    db.commit()
    return project


def delete_project(db: Session, principal: Principal, project: Project) -> None:
    """Soft delete. Scan history is retained; the slug is freed for reuse."""
    project.deleted_at = utcnow()
    project.slug = f"{project.slug[:80]}--deleted-{project.id.hex[:8]}"
    audit.record(db, "project.delete", principal=principal, organization_id=project.organization_id,
                 target_type="project", target_id=project.id, details={"name": project.name})
    db.commit()


def summarise(db: Session, projects: list[Project]) -> list[ProjectSummaryOut]:
    if not projects:
        return []
    ids = [p.id for p in projects]
    counts: dict[uuid.UUID, dict[str, int]] = {pid: {} for pid in ids}
    rows = db.execute(
        select(Finding.project_id, Finding.severity, func.count(Finding.id))
        .where(Finding.project_id.in_(ids), Finding.status.in_([s.value for s in ACTIVE_STATUSES]))
        .group_by(Finding.project_id, Finding.severity)
    ).all()
    for pid, severity, count in rows:
        counts[pid][severity] = count
    latest: dict[uuid.UUID, Scan] = {}
    for scan in db.scalars(select(Scan).where(Scan.project_id.in_(ids)).order_by(Scan.created_at.desc())):
        latest.setdefault(scan.project_id, scan)
    out = []
    for project in projects:
        c = counts[project.id]
        scan = latest.get(project.id)
        out.append(ProjectSummaryOut(
            **{k: getattr(project, k) for k in ProjectSummaryOut.model_fields if hasattr(project, k)
               and k not in {"open_findings", "critical_open", "high_open", "last_scan_at", "last_scan_status",
                             "risk_index"}},
            open_findings=sum(c.values()),
            critical_open=c.get(Severity.CRITICAL, 0),
            high_open=c.get(Severity.HIGH, 0),
            last_scan_at=scan.created_at if scan else None,
            last_scan_status=scan.status if scan else None,
            risk_index=scan.risk_index if scan else None,
        ))
    return out


def list_project_members(db: Session, project: Project) -> list[tuple[ProjectMember, User]]:
    return list(db.execute(
        select(ProjectMember, User).join(User, User.id == ProjectMember.user_id)
        .where(ProjectMember.project_id == project.id).order_by(User.email)
    ).all())


def add_project_member(db: Session, principal: Principal, project: Project,
                       user_id: uuid.UUID) -> tuple[ProjectMember, User]:
    membership = db.scalar(select(Membership).where(Membership.organization_id == project.organization_id,
                                                    Membership.user_id == user_id))
    user = db.get(User, user_id)
    if membership is None or user is None or user.deleted_at is not None:
        raise NotFound("User is not a member of this organization")
    if db.scalar(select(ProjectMember.id).where(ProjectMember.project_id == project.id,
                                                ProjectMember.user_id == user_id)) is not None:
        raise Conflict("User already has access to this project")
    member = ProjectMember(project_id=project.id, user_id=user_id)
    db.add(member)
    audit.record(db, "project.member_add", principal=principal, organization_id=project.organization_id,
                 target_type="project", target_id=project.id, details={"user_id": str(user_id)})
    db.commit()
    return member, user


def remove_project_member(db: Session, principal: Principal, project: Project, user_id: uuid.UUID) -> None:
    member = db.scalar(select(ProjectMember).where(ProjectMember.project_id == project.id,
                                                   ProjectMember.user_id == user_id))
    if member is None:
        raise NotFound("Project member not found")
    db.delete(member)
    audit.record(db, "project.member_remove", principal=principal, organization_id=project.organization_id,
                 target_type="project", target_id=project.id, details={"user_id": str(user_id)})
    db.commit()


# ---------------------------------------------------------------------------
# Repositories
# ---------------------------------------------------------------------------


def validate_git_url(url: str) -> str:
    """Accept only credential-free HTTPS URLs to an allow-listed git host.

    Blocks ``file://``, ``ssh://``, ``ext::`` and other transports, embedded
    credentials, and anything that could be read as a git command-line option.
    """
    url = url.strip()
    parts = urlsplit(url)
    allowed = {h.lower() for h in get_settings().git_allowed_hosts}
    host = (parts.hostname or "").lower()
    if parts.scheme != "https":
        raise AppError("Only https:// repository URLs are supported", code="invalid_repository_url",
                       status_code=422)
    if parts.username or parts.password or "@" in parts.netloc:
        raise AppError("Repository URLs must not contain credentials; configure an integration token instead",
                       code="invalid_repository_url", status_code=422)
    if host not in allowed:
        raise AppError(f"Repository host must be one of: {', '.join(sorted(allowed))}",
                       code="invalid_repository_url", status_code=422)
    if parts.port not in (None, 443) or parts.query or parts.fragment:
        raise AppError("Repository URL must not include a port, query or fragment",
                       code="invalid_repository_url", status_code=422)
    if not _REPO_PATH_RE.match(parts.path):
        raise AppError("Repository URL must look like https://host/owner/repository",
                       code="invalid_repository_url", status_code=422)
    return f"https://{host}{parts.path.rstrip('/')}"


def validate_branch(branch: str | None) -> str | None:
    if branch is None or branch == "":
        return None
    if not _BRANCH_RE.match(branch):
        raise AppError("Invalid branch name", code="invalid_branch", status_code=422)
    return branch


def create_repository(db: Session, principal: Principal, project: Project, body: RepositoryCreateIn) -> Repository:
    url = None
    if body.source_type == "GIT":
        if not body.url:
            raise AppError("A git repository needs a URL", code="invalid_repository_url", status_code=422)
        url = validate_git_url(body.url)
    repo = Repository(project_id=project.id, name=body.name.strip(), source_type=body.source_type, url=url,
                      default_branch=validate_branch(body.default_branch))
    db.add(repo)
    db.flush()
    audit.record(db, "repository.create", principal=principal, organization_id=project.organization_id,
                 target_type="repository", target_id=repo.id, details={"name": repo.name, "url": url})
    db.commit()
    return repo


def get_repository(db: Session, project: Project, repository_id: uuid.UUID) -> Repository:
    repo = db.get(Repository, repository_id)
    if repo is None or repo.project_id != project.id or repo.deleted_at is not None:
        raise NotFound("Repository not found")
    return repo
