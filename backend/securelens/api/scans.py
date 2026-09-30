"""Scans: uploads, repository scans, results, source view, reports and CI imports."""

from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from fastapi.responses import Response
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from securelens.api.deps import get_principal, load_project
from securelens.core import audit, storage
from securelens.core.database import get_db
from securelens.core.errors import AppError, Forbidden, NotFound
from securelens.core.permissions import Permission, has_permission
from securelens.core.principal import Principal
from securelens.enums import SEVERITY_ORDER, ScanStatus, ScanTrigger, Severity
from securelens.models import Dependency, Finding, FindingOccurrence, Project, Repository, Scan, ScanFile, Snapshot
from securelens.reporting import FORMATS
from securelens.scanners.secrets.masking import redact_text
from securelens.schemas.common import Page
from securelens.schemas.finding import FindingOut
from securelens.schemas.scan import (
    CLIImportIn,
    DependencyOut,
    FileContentOut,
    RepositoryScanIn,
    RescanIn,
    ScanConfigIn,
    ScanFileOut,
    ScanListOut,
    ScanOut,
)
from securelens.services import findings as finding_service
from securelens.services import projects as project_service
from securelens.services import reports as report_service
from securelens.services import scans as svc

router = APIRouter(prefix="/projects/{project_id}", tags=["scans"])

MAX_VIEW_BYTES = 1024 * 1024


def get_scan(db: Session, project: Project, scan_id: uuid.UUID) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.project_id != project.id:
        raise NotFound("Scan not found")
    return scan


def _parse_config(raw: str | None) -> ScanConfigIn:
    if not raw:
        return ScanConfigIn()
    try:
        return ScanConfigIn.model_validate(json.loads(raw))
    except (ValueError, ValidationError) as exc:
        raise AppError("config must be a JSON object with scanners, exclude, scope and external",
                       code="invalid_config", status_code=422) from exc


def _trigger(principal: Principal) -> ScanTrigger:
    return ScanTrigger.API if principal.api_key is not None else ScanTrigger.MANUAL


@router.post("/uploads", response_model=ScanOut, status_code=202)
def upload(project_id: uuid.UUID, file: UploadFile = File(...), repository_id: uuid.UUID | None = Form(None),
           repository_name: str | None = Form(None, max_length=200), config: str | None = Form(None, max_length=10000),
           baseline_scan_id: uuid.UUID | None = Form(None), principal: Principal = Depends(get_principal),
           db: Session = Depends(get_db)):
    """Upload a ZIP/TAR archive or a single source file. The worker extracts and analyses it."""
    project = load_project(db, principal, project_id, Permission.SCAN_CREATE)
    return svc.create_upload_scan(db, principal, project, filename=file.filename or "upload", stream=file.file,
                                  repository_id=repository_id, repository_name=repository_name,
                                  config=_parse_config(config), baseline_scan_id=baseline_scan_id,
                                  trigger=_trigger(principal))


@router.post("/retests/upload", response_model=ScanOut, status_code=202)
def upload_retest(project_id: uuid.UUID, baseline_scan_id: uuid.UUID = Form(...), file: UploadFile = File(...),
                  config: str | None = Form(None, max_length=10000), principal: Principal = Depends(get_principal),
                  db: Session = Depends(get_db)):
    """Upload fixed code and compare it with an earlier scan of the same repository."""
    project = load_project(db, principal, project_id, Permission.SCAN_CREATE)
    baseline = get_scan(db, project, baseline_scan_id)
    return svc.create_upload_scan(db, principal, project, filename=file.filename or "upload", stream=file.file,
                                  repository_id=baseline.repository_id, repository_name=None,
                                  config=_parse_config(config), baseline_scan_id=baseline.id,
                                  trigger=ScanTrigger.RETEST)


@router.post("/scans", response_model=ScanOut, status_code=202)
def scan_repository(project_id: uuid.UUID, body: RepositoryScanIn, principal: Principal = Depends(get_principal),
                    db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.SCAN_CREATE)
    repo = project_service.get_repository(db, project, body.repository_id)
    return svc.create_repository_scan(db, principal, project, repo, branch=body.branch, config=body.config,
                                      baseline_scan_id=body.baseline_scan_id, trigger=_trigger(principal))


@router.post("/scans/import", response_model=ScanOut, status_code=201)
def import_report(project_id: uuid.UUID, body: CLIImportIn, principal: Principal = Depends(get_principal),
                  db: Session = Depends(get_db)):
    """Store a report produced by `securelens scan` in CI (`securelens push`)."""
    project = load_project(db, principal, project_id, Permission.SCAN_CREATE)
    return svc.import_cli_report(db, principal, project, repository_name=body.repository_name, report=body.report,
                                 commit=body.commit, branch=body.branch)


@router.get("/scans", response_model=Page[ScanListOut])
def list_scans(project_id: uuid.UUID, status: str | None = Query(None, max_length=16),
               repository_id: uuid.UUID | None = None, page: int = Query(1, ge=1),
               page_size: int = Query(25, ge=1, le=100), principal: Principal = Depends(get_principal),
               db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.SCAN_READ)
    query = select(Scan).where(Scan.project_id == project.id)
    if status:
        query = query.where(Scan.status == status.upper())
    if repository_id:
        query = query.where(Scan.repository_id == repository_id)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    scans = db.scalars(query.order_by(Scan.created_at.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    repo_names = dict(db.execute(select(Repository.id, Repository.name).where(
        Repository.id.in_({s.repository_id for s in scans if s.repository_id}))).all()) if scans else {}
    items = [ScanListOut(**ScanOut.model_validate(s).model_dump(), repository_name=repo_names.get(s.repository_id))
             for s in scans]
    return Page[ScanListOut](items=items, total=total, page=page, page_size=page_size)


@router.get("/scans/{scan_id}", response_model=ScanListOut)
def get_scan_detail(project_id: uuid.UUID, scan_id: uuid.UUID, principal: Principal = Depends(get_principal),
                    db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.SCAN_READ)
    scan = get_scan(db, project, scan_id)
    repo = db.get(Repository, scan.repository_id) if scan.repository_id else None
    return ScanListOut(**ScanOut.model_validate(scan).model_dump(), repository_name=repo.name if repo else None)


@router.post("/scans/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(project_id: uuid.UUID, scan_id: uuid.UUID, principal: Principal = Depends(get_principal),
                db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.SCAN_READ)
    scan = get_scan(db, project, scan_id)
    role = principal.role_in(project.organization_id)
    own = principal.user_id is not None and scan.created_by_id == principal.user_id
    if not (has_permission(role, Permission.SCAN_CANCEL) or (own and has_permission(role, Permission.SCAN_CREATE))):
        raise Forbidden("You can cancel only your own scans")
    return svc.cancel(db, principal, project, scan)


@router.post("/scans/{scan_id}/rescan", response_model=ScanOut, status_code=202)
def rescan(project_id: uuid.UUID, scan_id: uuid.UUID, body: RescanIn | None = None,
           principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.SCAN_CREATE)
    scan = get_scan(db, project, scan_id)
    return svc.rescan(db, principal, project, scan, body.config if body else None)


@router.get("/scans/{scan_id}/files", response_model=list[ScanFileOut])
def scan_files(project_id: uuid.UUID, scan_id: uuid.UUID, principal: Principal = Depends(get_principal),
               db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.SCAN_READ)
    scan = get_scan(db, project, scan_id)
    return db.scalars(select(ScanFile).where(ScanFile.scan_id == scan.id).order_by(ScanFile.path).limit(50000)).all()


@router.get("/scans/{scan_id}/file", response_model=FileContentOut)
def scan_file_content(project_id: uuid.UUID, scan_id: uuid.UUID, path: str = Query(..., min_length=1, max_length=1024),
                      principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    """A scanned file with secrets masked, plus the findings reported in it (for the code viewer)."""
    project = load_project(db, principal, project_id, Permission.SCAN_READ)
    scan = get_scan(db, project, scan_id)
    record = db.scalar(select(ScanFile).where(ScanFile.scan_id == scan.id, ScanFile.path == path))
    snapshot = db.get(Snapshot, scan.snapshot_id) if scan.snapshot_id else None
    if record is None or snapshot is None:
        raise NotFound("File not found in this scan")
    root = storage.snapshot_path(snapshot.id)
    target = storage.safe_join(root, path)
    if not target.is_file() or target.is_symlink():
        raise NotFound("The source of this scan is no longer stored")
    raw = target.read_bytes()[: MAX_VIEW_BYTES + 1]
    if b"\x00" in raw[:8192]:
        raise AppError("Binary files cannot be displayed", code="binary_file", status_code=422)
    truncated = len(raw) > MAX_VIEW_BYTES
    text = raw[:MAX_VIEW_BYTES].decode("utf-8", errors="replace")
    masked = redact_text(text, path) or ""
    redacted = masked != text
    markers = []
    for occ, finding in db.execute(
            select(FindingOccurrence, Finding).join(Finding, Finding.id == FindingOccurrence.finding_id)
            .where(FindingOccurrence.scan_id == scan.id, FindingOccurrence.file_path == path)).all():
        markers.append({"finding_id": str(finding.id), "public_id": finding.public_id, "title": finding.title,
                        "severity": occ.severity, "confidence": occ.confidence, "line": occ.start_line,
                        "end_line": occ.end_line, "status": finding.status, "verification": finding.verification})
    markers.sort(key=lambda m: (m["line"] or 0, -SEVERITY_ORDER.get(Severity(m["severity"]), 0)))
    if truncated:
        masked += "\n\n[SecureLens: file truncated at 1 MB for display]"
    return FileContentOut(path=path, language=record.language, content=masked, redacted=redacted, findings=markers)


@router.get("/scans/{scan_id}/findings", response_model=Page[FindingOut])
def scan_findings(project_id: uuid.UUID, scan_id: uuid.UUID, severity: list[str] | None = Query(None),
                  page: int = Query(1, ge=1), page_size: int = Query(100, ge=1, le=500),
                  principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.FINDING_READ)
    scan = get_scan(db, project, scan_id)
    filters = finding_service.FindingFilters(scan_id=scan.id, severity=[s.upper() for s in severity or []] or None)
    rows, total = finding_service.list_findings(db, project, filters, page=page, page_size=page_size)
    return Page[FindingOut](items=[FindingOut.model_validate(r) for r in rows], total=total, page=page,
                            page_size=page_size)


@router.get("/scans/{scan_id}/dependencies", response_model=list[DependencyOut])
def scan_dependencies(project_id: uuid.UUID, scan_id: uuid.UUID, principal: Principal = Depends(get_principal),
                      db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.SCAN_READ)
    scan = get_scan(db, project, scan_id)
    return db.scalars(select(Dependency).where(Dependency.scan_id == scan.id)
                      .order_by(Dependency.vuln_status, Dependency.ecosystem, Dependency.name)).all()


@router.get("/scans/{scan_id}/report")
def scan_report(project_id: uuid.UUID, scan_id: uuid.UUID, format: str = Query("html"),
                principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    project = load_project(db, principal, project_id, Permission.REPORT_READ)
    scan = get_scan(db, project, scan_id)
    fmt = format.lower()
    if fmt not in FORMATS:
        raise AppError(f"format must be one of: {', '.join(FORMATS)}", code="invalid_format", status_code=422)
    if scan.status != ScanStatus.COMPLETED:
        raise AppError("Reports are available once the scan has completed", code="scan_not_completed",
                       status_code=409)
    content, content_type, filename = report_service.render_scan_report(db, project, scan, fmt)
    audit.record(db, "report.download", principal=principal, organization_id=project.organization_id,
                 target_type="scan", target_id=scan.id, details={"format": fmt})
    db.commit()
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    if fmt == "html":
        # The report is viewed as a document; it runs no scripts and loads nothing external.
        headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
    return Response(content=content, media_type=content_type, headers=headers)
