"""Finding queries and lifecycle changes.

Status (lifecycle) and verification (how the finding is known) are separate:

* OPEN / IN_PROGRESS — developers and above.
* FALSE_POSITIVE / ACCEPTED_RISK — security decisions: analysts and above,
  always with a reason.
* RESOLVED by hand — analysts and above, with a reason. The normal path is a
  rescan: SecureLens marks a finding resolved only when the affected file was
  analysed again and the issue is gone. A suggested fix never resolves anything.
* Verification CONFIRMED / FALSE_POSITIVE / DETECTED — analysts and above.
  AI_SUGGESTED is set only by AI analysis and cannot be chosen by hand.

Every change is written to the audit log.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session, selectinload

from securelens.core import audit
from securelens.core.errors import AppError, Forbidden, NotFound
from securelens.core.permissions import Permission, has_permission
from securelens.core.principal import Principal
from securelens.enums import SEVERITY_ORDER, FindingStatus, Severity, Verification
from securelens.findings import explain as explainer
from securelens.models import Finding, FindingOccurrence, Project, Retest, RetestResult
from securelens.models.base import utcnow
from securelens.schemas.finding import EvidenceOut, FindingDetailOut, OccurrenceOut, RetestHistoryOut

_SORTS = {
    "severity": None,  # handled explicitly (severity rank, then risk)
    "risk": Finding.risk_score.desc(),
    "newest": Finding.first_seen_at.desc(),
    "last_seen": Finding.last_seen_at.desc(),
    "id": Finding.public_id,
}


@dataclass
class FindingFilters:
    status: list[str] | None = None
    severity: list[str] | None = None
    engine: str | None = None
    source_kind: list[str] | None = None
    verification: list[str] | None = None
    repository_id: uuid.UUID | None = None
    scan_id: uuid.UUID | None = None
    vuln_class: str | None = None
    path: str | None = None
    q: str | None = None
    active_only: bool = False


def _severity_rank():
    from sqlalchemy import case

    return case({s.value: SEVERITY_ORDER[s] for s in Severity}, value=Finding.severity, else_=-1)


def query(project: Project, filters: FindingFilters) -> Select:
    stmt = select(Finding).where(Finding.project_id == project.id)
    if filters.active_only:
        stmt = stmt.where(Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.REOPENED]))
    if filters.status:
        stmt = stmt.where(Finding.status.in_(filters.status))
    if filters.severity:
        stmt = stmt.where(Finding.severity.in_(filters.severity))
    if filters.engine:
        stmt = stmt.where(Finding.engine == filters.engine)
    if filters.source_kind:
        stmt = stmt.where(Finding.source_kind.in_(filters.source_kind))
    if filters.verification:
        stmt = stmt.where(Finding.verification.in_(filters.verification))
    if filters.repository_id:
        stmt = stmt.where(Finding.repository_id == filters.repository_id)
    if filters.vuln_class:
        stmt = stmt.where(Finding.vuln_class == filters.vuln_class)
    if filters.path:
        stmt = stmt.where(Finding.file_path == filters.path)
    if filters.scan_id:
        seen = select(FindingOccurrence.finding_id).where(FindingOccurrence.scan_id == filters.scan_id)
        stmt = stmt.where(Finding.id.in_(seen))
    if filters.q:
        term = f"%{filters.q.strip()[:200].replace('%', '').replace('_', '')}%"
        stmt = stmt.where(or_(Finding.title.ilike(term), Finding.public_id.ilike(term), Finding.file_path.ilike(term),
                              Finding.rule_id.ilike(term)))
    return stmt


def list_findings(db: Session, project: Project, filters: FindingFilters, *, sort: str = "severity", page: int = 1,
                  page_size: int = 50) -> tuple[list[Finding], int]:
    stmt = query(project, filters)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    if sort == "severity" or sort not in _SORTS:
        stmt = stmt.order_by(_severity_rank().desc(), Finding.risk_score.desc(), Finding.public_id)
    else:
        stmt = stmt.order_by(_SORTS[sort], Finding.public_id)
    rows = db.scalars(stmt.offset((page - 1) * page_size).limit(page_size)).all()
    return list(rows), total


def get_finding(db: Session, project: Project, finding_id: uuid.UUID) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None or finding.project_id != project.id:
        raise NotFound("Finding not found")
    return finding


def detail(db: Session, project: Project, finding: Finding) -> FindingDetailOut:
    occurrences = db.scalars(
        select(FindingOccurrence).where(FindingOccurrence.finding_id == finding.id)
        .options(selectinload(FindingOccurrence.evidence))
        .order_by(FindingOccurrence.created_at.desc()).limit(20)
    ).all()
    history = db.execute(
        select(RetestResult, Retest).join(Retest, Retest.id == RetestResult.retest_id)
        .where(RetestResult.finding_id == finding.id).order_by(RetestResult.created_at.desc()).limit(50)
    ).all()
    latest = occurrences[0] if occurrences else None
    evidence = [EvidenceOut.model_validate(e).model_dump() for e in (latest.evidence if latest else [])]
    explanation = explainer.explain(
        vuln_class=finding.vuln_class, title=finding.title, severity=finding.severity,
        confidence=finding.confidence, exploitability=finding.exploitability, evidence=evidence,
        file_path=finding.file_path, line=finding.line)
    base = {k: getattr(finding, k) for k in FindingDetailOut.model_fields
            if k not in {"occurrences", "retests", "explanation", "learning"} and hasattr(finding, k)}
    return FindingDetailOut(
        **base,
        occurrences=[OccurrenceOut.model_validate(o) for o in occurrences],
        retests=[RetestHistoryOut(retest_id=rt.id, result=rr.result, match_method=rr.match_method, notes=rr.notes,
                                  created_at=rr.created_at, retest_scan_id=rt.retest_scan_id,
                                  retest_run_id=rt.retest_run_id) for rr, rt in history],
        explanation=explanation,
        learning=learning_link(finding.vuln_class, explanation.get("language")),
    )


def learning_link(vuln_class: str, language: str | None) -> dict | None:
    """Academy lesson for this vulnerability class, when one exists."""
    try:
        from securelens.academy.content import lesson_for
    except ImportError:
        return None
    lesson = lesson_for(vuln_class, language)
    return {"lesson_id": lesson.id, "title": lesson.title, "language": lesson.language} if lesson else None


def update_status(db: Session, principal: Principal, project: Project, finding: Finding, status: FindingStatus,
                  reason: str | None) -> Finding:
    role = principal.role_in(project.organization_id)
    assert role is not None
    needs_triage = status in (FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK, FindingStatus.RESOLVED)
    if status == FindingStatus.REOPENED:
        raise AppError("REOPENED is set by SecureLens when a resolved issue reappears; set OPEN to reopen by hand",
                       code="invalid_status", status_code=422)
    if needs_triage and not has_permission(role, Permission.FINDING_TRIAGE):
        if status == FindingStatus.RESOLVED:
            raise Forbidden("Resolve findings by fixing the code and running a new scan; marking them resolved by "
                            "hand needs the Security Analyst role")
        raise Forbidden("Marking a finding as false positive or accepted risk needs the Security Analyst role")
    if needs_triage and not (reason and reason.strip()):
        raise AppError("A reason is required for this status", code="reason_required", status_code=422)
    previous = finding.status
    now = utcnow()
    finding.status = status
    finding.status_reason = (reason or "").strip() or None
    finding.status_changed_at = now
    finding.status_changed_by_id = principal.user_id
    if status == FindingStatus.RESOLVED:
        finding.resolved_at = now
    elif previous == FindingStatus.RESOLVED:
        finding.resolved_at = None
        finding.resolved_by_scan_id = None
    if status == FindingStatus.FALSE_POSITIVE:
        finding.verification = Verification.FALSE_POSITIVE
    elif previous == FindingStatus.FALSE_POSITIVE and finding.verification == Verification.FALSE_POSITIVE:
        finding.verification = Verification.DETECTED
    audit.record(db, "finding.status", principal=principal, organization_id=project.organization_id,
                 target_type="finding", target_id=finding.id,
                 details={"public_id": finding.public_id, "from": previous, "to": status, "reason": reason})
    db.commit()
    return finding


def update_verification(db: Session, principal: Principal, project: Project, finding: Finding,
                        verification: Verification, reason: str | None) -> Finding:
    role = principal.role_in(project.organization_id)
    assert role is not None
    if not has_permission(role, Permission.FINDING_TRIAGE):
        raise Forbidden("Changing verification needs the Security Analyst role")
    if verification in (Verification.AI_SUGGESTED, Verification.NOT_TESTED):
        raise AppError(f"{verification} is set by SecureLens, not by hand", code="invalid_verification",
                       status_code=422)
    if verification in (Verification.CONFIRMED, Verification.FALSE_POSITIVE) and not (reason and reason.strip()):
        raise AppError("A reason is required", code="reason_required", status_code=422)
    previous = finding.verification
    finding.verification = verification
    if verification == Verification.FALSE_POSITIVE:
        finding.status = FindingStatus.FALSE_POSITIVE
        finding.status_reason = reason
        finding.status_changed_at = utcnow()
        finding.status_changed_by_id = principal.user_id
    elif finding.status == FindingStatus.FALSE_POSITIVE:
        finding.status = FindingStatus.OPEN
        finding.status_changed_at = utcnow()
        finding.status_changed_by_id = principal.user_id
    audit.record(db, "finding.verification", principal=principal, organization_id=project.organization_id,
                 target_type="finding", target_id=finding.id,
                 details={"public_id": finding.public_id, "from": previous, "to": verification, "reason": reason})
    db.commit()
    return finding
