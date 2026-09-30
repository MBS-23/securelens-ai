"""Findings: list, detail with evidence and explanation, lifecycle and verification changes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from securelens.api.deps import get_principal, load_project
from securelens.core.database import get_db
from securelens.core.permissions import Permission
from securelens.core.principal import Principal
from securelens.schemas.common import Page
from securelens.schemas.finding import FindingDetailOut, FindingOut, StatusUpdateIn, VerificationUpdateIn
from securelens.services import findings as svc

router = APIRouter(prefix="/projects/{project_id}/findings", tags=["findings"])


def _upper(values: list[str] | None) -> list[str] | None:
    return [v.upper() for v in values] if values else None


@router.get("", response_model=Page[FindingOut])
def list_findings(project_id: uuid.UUID, status: list[str] | None = Query(None),
                  severity: list[str] | None = Query(None), engine: str | None = Query(None, max_length=8),
                  source_kind: list[str] | None = Query(None), verification: list[str] | None = Query(None),
                  repository_id: uuid.UUID | None = None, scan_id: uuid.UUID | None = None,
                  vuln_class: str | None = Query(None, max_length=64), path: str | None = Query(None, max_length=1024),
                  q: str | None = Query(None, max_length=200), active: bool = False,
                  sort: str = Query("severity", pattern="^(severity|risk|newest|last_seen|id)$"),
                  page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
                  principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.FINDING_READ)
    filters = svc.FindingFilters(status=_upper(status), severity=_upper(severity),
                                 engine=engine.upper() if engine else None, source_kind=_upper(source_kind),
                                 verification=_upper(verification), repository_id=repository_id, scan_id=scan_id,
                                 vuln_class=vuln_class, path=path, q=q, active_only=active)
    rows, total = svc.list_findings(db, project, filters, sort=sort, page=page, page_size=page_size)
    return Page[FindingOut](items=[FindingOut.model_validate(r) for r in rows], total=total, page=page,
                            page_size=page_size)


@router.get("/{finding_id}", response_model=FindingDetailOut)
def get_finding(project_id: uuid.UUID, finding_id: uuid.UUID, principal: Principal = Depends(get_principal),
                db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.FINDING_READ)
    return svc.detail(db, project, svc.get_finding(db, project, finding_id))


@router.patch("/{finding_id}/status", response_model=FindingOut)
def update_status(project_id: uuid.UUID, finding_id: uuid.UUID, body: StatusUpdateIn,
                  principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.FINDING_UPDATE_STATUS)
    finding = svc.get_finding(db, project, finding_id)
    return svc.update_status(db, principal, project, finding, body.status, body.reason)


@router.patch("/{finding_id}/verification", response_model=FindingOut)
def update_verification(project_id: uuid.UUID, finding_id: uuid.UUID, body: VerificationUpdateIn,
                        principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.FINDING_TRIAGE)
    finding = svc.get_finding(db, project, finding_id)
    return svc.update_verification(db, principal, project, finding, body.verification, body.reason)
