"""Projects, project members and repositories."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from securelens.api.deps import accessible_project_ids, get_principal, load_project, require_org_permission
from securelens.core import audit
from securelens.core.database import get_db
from securelens.core.permissions import Permission
from securelens.core.principal import Principal
from securelens.models import Project, Repository
from securelens.schemas.common import Message
from securelens.schemas.project import (
    ProjectCreateIn,
    ProjectMemberIn,
    ProjectMemberOut,
    ProjectOut,
    ProjectSummaryOut,
    ProjectUpdateIn,
    RepositoryCreateIn,
    RepositoryOut,
)
from securelens.services import projects as svc

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("", response_model=list[ProjectSummaryOut])
def list_projects(organization_id: uuid.UUID | None = Query(None), principal: Principal = Depends(get_principal),
                  db: Session = Depends(get_db)):
    ids = accessible_project_ids(db, principal, organization_id)
    if not ids:
        return []
    projects = db.scalars(select(Project).where(Project.id.in_(ids)).order_by(Project.name)).all()
    return svc.summarise(db, list(projects))


@router.post("", response_model=ProjectOut, status_code=201)
def create_project(body: ProjectCreateIn, principal: Principal = Depends(get_principal),
                   db: Session = Depends(get_db)):
    require_org_permission(principal, body.organization_id, Permission.PROJECT_CREATE)
    return svc.create_project(db, principal, body)


@router.get("/{project_id}", response_model=ProjectSummaryOut)
def get_project(project_id: uuid.UUID, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.PROJECT_READ)
    return svc.summarise(db, [project])[0]


@router.patch("/{project_id}", response_model=ProjectOut)
def update_project(project_id: uuid.UUID, body: ProjectUpdateIn, principal: Principal = Depends(get_principal),
                   db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.PROJECT_UPDATE)
    return svc.update_project(db, principal, project, body)


@router.delete("/{project_id}", response_model=Message)
def delete_project(project_id: uuid.UUID, principal: Principal = Depends(get_principal),
                   db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.PROJECT_DELETE)
    svc.delete_project(db, principal, project)
    return Message(message="Project deleted")


@router.get("/{project_id}/members", response_model=list[ProjectMemberOut])
def list_members(project_id: uuid.UUID, principal: Principal = Depends(get_principal),
                 db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.PROJECT_READ)
    return [ProjectMemberOut(user_id=u.id, email=u.email, display_name=u.display_name, added_at=m.created_at)
            for m, u in svc.list_project_members(db, project)]


@router.post("/{project_id}/members", response_model=ProjectMemberOut, status_code=201)
def add_member(project_id: uuid.UUID, body: ProjectMemberIn, principal: Principal = Depends(get_principal),
               db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.PROJECT_MEMBERS_MANAGE)
    member, user = svc.add_project_member(db, principal, project, body.user_id)
    return ProjectMemberOut(user_id=user.id, email=user.email, display_name=user.display_name,
                            added_at=member.created_at)


@router.delete("/{project_id}/members/{user_id}", response_model=Message)
def remove_member(project_id: uuid.UUID, user_id: uuid.UUID, principal: Principal = Depends(get_principal),
                  db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.PROJECT_MEMBERS_MANAGE)
    svc.remove_project_member(db, principal, project, user_id)
    return Message(message="Access removed")


@router.get("/{project_id}/repositories", response_model=list[RepositoryOut])
def list_repositories(project_id: uuid.UUID, principal: Principal = Depends(get_principal),
                      db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.PROJECT_READ)
    return db.scalars(select(Repository).where(Repository.project_id == project.id,
                                               Repository.deleted_at.is_(None)).order_by(Repository.name)).all()


@router.post("/{project_id}/repositories", response_model=RepositoryOut, status_code=201)
def create_repository(project_id: uuid.UUID, body: RepositoryCreateIn, principal: Principal = Depends(get_principal),
                      db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.SCAN_CREATE)
    return svc.create_repository(db, principal, project, body)


@router.delete("/{project_id}/repositories/{repository_id}", response_model=Message)
def delete_repository(project_id: uuid.UUID, repository_id: uuid.UUID, principal: Principal = Depends(get_principal),
                      db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.PROJECT_UPDATE)
    repo = svc.get_repository(db, project, repository_id)
    from securelens.models.base import utcnow

    repo.deleted_at = utcnow()
    audit.record(db, "repository.delete", principal=principal, organization_id=project.organization_id,
                 target_type="repository", target_id=repo.id)
    db.commit()
    return Message(message="Repository removed")
