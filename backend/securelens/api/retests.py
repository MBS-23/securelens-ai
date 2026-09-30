"""Retest results: what a new scan (or AI test run) resolved, kept, introduced or could not test."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from securelens.api.deps import get_principal, load_project
from securelens.core.database import get_db
from securelens.core.errors import NotFound
from securelens.core.permissions import Permission
from securelens.core.principal import Principal
from securelens.models import Finding, Retest, RetestResult
from securelens.schemas.finding import RetestDetailOut, RetestOut, RetestResultOut

router = APIRouter(prefix="/projects/{project_id}/retests", tags=["retests"])

_RESULT_ORDER = {"REGRESSION": 0, "NEW": 1, "STILL_OPEN": 2, "NOT_TESTED": 3, "NOT_REPRODUCED": 4, "RESOLVED": 5}


@router.get("", response_model=list[RetestOut])
def list_retests(project_id: uuid.UUID, limit: int = Query(50, ge=1, le=200),
                 principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.SCAN_READ)
    return db.scalars(select(Retest).where(Retest.project_id == project.id)
                      .order_by(Retest.created_at.desc()).limit(limit)).all()


@router.get("/{retest_id}", response_model=RetestDetailOut)
def get_retest(project_id: uuid.UUID, retest_id: uuid.UUID, principal: Principal = Depends(get_principal),
               db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.SCAN_READ)
    retest = db.get(Retest, retest_id)
    if retest is None or retest.project_id != project.id:
        raise NotFound("Retest not found")
    rows = db.execute(select(RetestResult, Finding).join(Finding, Finding.id == RetestResult.finding_id)
                      .where(RetestResult.retest_id == retest.id)).all()
    results = [RetestResultOut(finding_id=f.id, public_id=f.public_id, title=f.title, vuln_class=f.vuln_class,
                               result=r.result, match_method=r.match_method, before=r.before, after=r.after,
                               notes=r.notes) for r, f in rows]
    results.sort(key=lambda r: (_RESULT_ORDER.get(r.result, 9), r.public_id))
    return RetestDetailOut(**RetestOut.model_validate(retest).model_dump(), results=results)
