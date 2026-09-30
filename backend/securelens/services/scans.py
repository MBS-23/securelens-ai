"""Scan lifecycle.

API side:  create_*_scan() — validate, store the upload, create Snapshot + Scan,
           enqueue a job. Nothing is parsed or extracted in the API process.
Worker:    execute_scan() — materialize the snapshot (safe extraction / hardened
           git clone), analyse it in the sandbox, add dependency intelligence,
           correlate, then persist_results().
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import BinaryIO

from sqlalchemy import select
from sqlalchemy.orm import Session

from securelens.core import audit, storage
from securelens.core.config import Settings, get_settings
from securelens.core.errors import AppError, Conflict, NotFound
from securelens.core.principal import Principal
from securelens.core.security import keyed_hash
from securelens.enums import (
    ACTIVE_STATUSES,
    Engine,
    FindingStatus,
    JobKind,
    RemediationStatus,
    RepositorySourceType,
    RetestResultKind,
    ScanScope,
    ScanStatus,
    ScanTrigger,
    SnapshotOrigin,
    SnapshotStatus,
    SourceKind,
)
from securelens.findings import fingerprint as fp
from securelens.findings import retest as retest_engine
from securelens.findings import risk as risk_engine
from securelens.findings.gate import GateItem, GatePolicy, evaluate
from securelens.findings.model import Evidence as EngineEvidence
from securelens.findings.model import Finding as EngineFinding
from securelens.findings.model import Location, ScanResult
from securelens.ingest import IngestError, Limits, clone_repository, is_archive, materialize_upload
from securelens.models import (
    Dependency,
    Evidence,
    Finding,
    FindingOccurrence,
    Organization,
    Project,
    Remediation,
    Repository,
    Retest,
    RetestResult,
    Scan,
    ScanFile,
    SecretFinding,
    Snapshot,
)
from securelens.models.base import utcnow
from securelens.scanners import engine
from securelens.scanners.base import ScanOptions
from securelens.scanners.workspace import LANGUAGE_BY_EXTENSION
from securelens.schemas.scan import ScanConfigIn
from securelens.worker import queue
from securelens.worker.sandbox import SandboxError, SandboxLimits, run_isolated

log = logging.getLogger(__name__)

TEXT_UPLOAD_EXTENSIONS = set(LANGUAGE_BY_EXTENSION) | {
    ".txt", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".env", ".properties", ".xml", ".lock", ".md",
    ".sh", ".sql", ".html", ".htm", ".vue", ".svelte", ".tf", ".gradle"}
BLOCKED_UPLOAD_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".bin", ".msi", ".apk", ".dmg", ".iso", ".jar", ".war",
                             ".class", ".pyc", ".o", ".a"}


# ----------------------------------------------------------------- options


def scan_options_for(scan: Scan, settings: Settings) -> ScanOptions:
    cfg = scan.config or {}
    external = dict.fromkeys(settings.external_scanners, "auto") if cfg.get("external", True) else {}
    if settings.advisory_db_dir:
        source = "offline"
    elif settings.osv_enabled:
        source = "osv"
    else:
        source = "none"
    return ScanOptions(
        scanners=set(cfg.get("scanners", ["sast", "secrets", "dependencies"])),
        external=external,
        exclude=list(cfg.get("exclude", [])),
        max_file_kb=settings.max_file_kb,
        max_files=settings.max_files,
        vulnerability_source=source,
        offline_db=settings.advisory_db_dir,
        osv_url=settings.osv_api_url,
        time_budget_seconds=float(settings.scan_timeout_seconds),
        secret_hash_key=bytes.fromhex(keyed_hash("secret-fingerprint", "scan-engine")),
    )


def _limits(settings: Settings) -> Limits:
    return Limits(max_files=settings.max_files, max_total_bytes=settings.max_extracted_mb * 1024 * 1024,
                  max_file_bytes=64 * 1024 * 1024, max_ratio=settings.max_compression_ratio)


# ------------------------------------------------------------ API: create


def _validate_baseline(db: Session, project: Project, baseline_scan_id: uuid.UUID | None) -> Scan | None:
    if baseline_scan_id is None:
        return None
    baseline = db.get(Scan, baseline_scan_id)
    if baseline is None or baseline.project_id != project.id:
        raise NotFound("Baseline scan not found")
    if baseline.status != ScanStatus.COMPLETED:
        raise Conflict("The baseline scan has not completed")
    return baseline


def _repository_for_upload(db: Session, project: Project, repository_id: uuid.UUID | None,
                           repository_name: str | None, filename: str) -> Repository:
    if repository_id is not None:
        repo = db.get(Repository, repository_id)
        if repo is None or repo.project_id != project.id or repo.deleted_at is not None:
            raise NotFound("Repository not found")
        return repo
    name = (repository_name or Path(filename).name.split(".")[0] or "upload").strip()[:200]
    existing = db.scalar(select(Repository).where(Repository.project_id == project.id, Repository.name == name,
                                                  Repository.source_type == RepositorySourceType.UPLOAD,
                                                  Repository.deleted_at.is_(None)))
    if existing is not None:
        return existing
    repo = Repository(project_id=project.id, name=name, source_type=RepositorySourceType.UPLOAD)
    db.add(repo)
    db.flush()
    return repo


def _new_scan(db: Session, principal: Principal, project: Project, *, repository: Repository, snapshot: Snapshot,
              config: ScanConfigIn, trigger: ScanTrigger, scope: str, baseline: Scan | None) -> Scan:
    scan = Scan(project_id=project.id, repository_id=repository.id, snapshot_id=snapshot.id,
                status=ScanStatus.QUEUED, trigger=trigger, scope=scope,
                baseline_scan_id=baseline.id if baseline else None, config=config.model_dump(mode="json"),
                progress={"stage": "queued", "percent": 0}, queued_at=utcnow(), created_by_id=principal.user_id,
                api_key_id=principal.api_key.id if principal.api_key else None)
    db.add(scan)
    db.flush()
    queue.enqueue(db, JobKind.SCAN, {"scan_id": str(scan.id)})
    audit.record(db, "scan.create", principal=principal, organization_id=project.organization_id,
                 target_type="scan", target_id=scan.id,
                 details={"trigger": trigger, "repository": repository.name,
                          "baseline": str(baseline.id) if baseline else None})
    return scan


def create_upload_scan(db: Session, principal: Principal, project: Project, *, filename: str, stream: BinaryIO,
                       repository_id: uuid.UUID | None, repository_name: str | None, config: ScanConfigIn,
                       baseline_scan_id: uuid.UUID | None, trigger: ScanTrigger = ScanTrigger.MANUAL) -> Scan:
    settings = get_settings()
    lower = filename.lower()
    suffix = Path(lower).suffix
    archive = is_archive(lower)
    if suffix in BLOCKED_UPLOAD_EXTENSIONS:
        raise AppError("Executable and binary uploads are not accepted", code="unsupported_upload", status_code=422)
    if not archive and suffix not in TEXT_UPLOAD_EXTENSIONS and Path(lower).name not in {"dockerfile", "makefile"}:
        raise AppError("Upload a ZIP/TAR archive or a single source file", code="unsupported_upload", status_code=422)
    baseline = _validate_baseline(db, project, baseline_scan_id)
    key, size = storage.save_stream(stream, settings.max_upload_mb * 1024 * 1024)
    repo = _repository_for_upload(db, project, repository_id, repository_name, filename)
    if baseline is not None and baseline.repository_id != repo.id:
        raise AppError("The baseline scan belongs to a different repository", code="baseline_mismatch",
                       status_code=422)
    snapshot = Snapshot(project_id=project.id, repository_id=repo.id,
                        origin=SnapshotOrigin.UPLOAD_ARCHIVE if archive else SnapshotOrigin.UPLOAD_FILE,
                        status=SnapshotStatus.PENDING, upload_key=key, upload_name=Path(filename).name[:300],
                        total_bytes=size, created_by_id=principal.user_id)
    db.add(snapshot)
    db.flush()
    scope = ScanScope.PARTIAL if not archive else config.scope
    scan = _new_scan(db, principal, project, repository=repo, snapshot=snapshot, config=config,
                     trigger=ScanTrigger.RETEST if baseline and trigger == ScanTrigger.MANUAL else trigger,
                     scope=scope, baseline=baseline)
    db.commit()
    return scan


def create_repository_scan(db: Session, principal: Principal, project: Project, repository: Repository, *,
                           branch: str | None, config: ScanConfigIn, baseline_scan_id: uuid.UUID | None,
                           trigger: ScanTrigger = ScanTrigger.MANUAL, extra: dict | None = None) -> Scan:
    if repository.source_type != RepositorySourceType.GIT or not repository.url:
        raise AppError("This repository has no git URL; upload a new archive instead", code="not_git",
                       status_code=422)
    from securelens.services.projects import validate_branch

    baseline = _validate_baseline(db, project, baseline_scan_id)
    snapshot = Snapshot(project_id=project.id, repository_id=repository.id, origin=SnapshotOrigin.GIT,
                        status=SnapshotStatus.PENDING, git_ref=validate_branch(branch) or repository.default_branch,
                        created_by_id=principal.user_id)
    db.add(snapshot)
    db.flush()
    scan = _new_scan(db, principal, project, repository=repository, snapshot=snapshot, config=config,
                     trigger=ScanTrigger.RETEST if baseline and trigger == ScanTrigger.MANUAL else trigger,
                     scope=config.scope, baseline=baseline)
    if extra:
        scan.config = {**scan.config, "_integration": extra}
    db.commit()
    return scan


def create_snapshot_scan(db: Session, principal: Principal, project: Project, snapshot: Snapshot, *,
                         config: ScanConfigIn | None, trigger: ScanTrigger, baseline: Scan | None,
                         scope: str = ScanScope.FULL) -> Scan:
    repo = db.get(Repository, snapshot.repository_id) if snapshot.repository_id else None
    if repo is None:
        raise NotFound("Repository not found")
    scan = _new_scan(db, principal, project, repository=repo, snapshot=snapshot, config=config or ScanConfigIn(),
                     trigger=trigger, scope=scope, baseline=baseline)
    db.commit()
    return scan


def _stored_config(scan: Scan) -> ScanConfigIn:
    """The user-facing scan options of an earlier scan (without integration or import metadata)."""
    stored = {k: v for k, v in (scan.config or {}).items() if k in ScanConfigIn.model_fields}
    try:
        return ScanConfigIn.model_validate(stored)
    except ValueError:
        return ScanConfigIn()


def rescan(db: Session, principal: Principal, project: Project, scan: Scan, config: ScanConfigIn | None) -> Scan:
    snapshot = db.get(Snapshot, scan.snapshot_id) if scan.snapshot_id else None
    if snapshot is None:
        raise Conflict("This scan has no stored source (for example a CLI import) and cannot be re-run")
    cfg = config or _stored_config(scan)
    if snapshot.origin == SnapshotOrigin.GIT:
        repo = db.get(Repository, snapshot.repository_id) if snapshot.repository_id else None
        if repo is None or repo.deleted_at is not None:
            raise NotFound("Repository not found")
        # A git rescan fetches the branch again, so it analyses the current code.
        return create_repository_scan(db, principal, project, repo, branch=snapshot.git_ref, config=cfg,
                                      baseline_scan_id=None)
    return create_snapshot_scan(db, principal, project, snapshot, config=cfg, trigger=ScanTrigger.MANUAL,
                                baseline=None, scope=scan.scope)


def cancel(db: Session, principal: Principal, project: Project, scan: Scan) -> Scan:
    if scan.status not in (ScanStatus.QUEUED, ScanStatus.RUNNING):
        raise Conflict("Only queued or running scans can be cancelled")
    scan.status = ScanStatus.CANCELLED
    scan.finished_at = utcnow()
    scan.progress = {"stage": "cancelled", "percent": scan.progress.get("percent", 0)}
    audit.record(db, "scan.cancel", principal=principal, organization_id=project.organization_id,
                 target_type="scan", target_id=scan.id)
    db.commit()
    return scan


# --------------------------------------------------------- worker: execute


def _progress(db: Session, scan: Scan, stage: str, percent: int) -> None:
    scan.progress = {"stage": stage, "percent": percent}
    db.commit()


def materialize_snapshot(db: Session, snapshot: Snapshot, settings: Settings) -> Path:
    dest = storage.snapshot_path(snapshot.id)
    if snapshot.status == SnapshotStatus.READY and dest.exists():
        return dest
    storage.remove_tree(dest)
    limits = _limits(settings)
    if snapshot.origin in (SnapshotOrigin.UPLOAD_ARCHIVE, SnapshotOrigin.UPLOAD_FILE):
        report = materialize_upload(storage.upload_path(snapshot.upload_key or ""), snapshot.upload_name or "upload",
                                    dest, limits)
    elif snapshot.origin == SnapshotOrigin.GIT:
        repo = db.get(Repository, snapshot.repository_id)
        if repo is None or not repo.url:
            raise IngestError("Repository no longer exists")
        token = None
        from securelens.services.integrations import git_token_for

        token = git_token_for(db, repo)
        report = clone_repository(repo.url, snapshot.git_ref, dest, allowed_hosts=settings.git_allowed_hosts,
                                  timeout=settings.git_clone_timeout_seconds, limits=limits, token=token)
        snapshot.git_commit = report.commit
    else:
        raise IngestError("Snapshot source is not available")
    snapshot.status = SnapshotStatus.READY
    snapshot.file_count = report.files
    snapshot.total_bytes = report.total_bytes
    db.commit()
    return dest


def execute_scan(db: Session, scan_id: uuid.UUID, *, sandbox: bool = True) -> None:
    settings = get_settings()
    scan = db.get(Scan, scan_id)
    if scan is None or scan.status not in (ScanStatus.QUEUED, ScanStatus.RUNNING):
        return
    scan.status = ScanStatus.RUNNING
    scan.started_at = utcnow()
    _progress(db, scan, "fetching source", 10)
    try:
        snapshot = db.get(Snapshot, scan.snapshot_id)
        if snapshot is None:
            raise IngestError("Snapshot not found")
        try:
            root = materialize_snapshot(db, snapshot, settings)
        except IngestError as exc:
            snapshot.status = SnapshotStatus.FAILED
            snapshot.error = str(exc)
            raise
        db.refresh(scan)
        if scan.status == ScanStatus.CANCELLED:
            return
        _progress(db, scan, "analyzing", 30)
        options = scan_options_for(scan, settings)
        repo = db.get(Repository, scan.repository_id) if scan.repository_id else None
        target = snapshot.upload_name or (repo.name if repo else "source")
        if sandbox:
            result = run_isolated(root, options, target, SandboxLimits(timeout_seconds=settings.scan_timeout_seconds,
                                                                       memory_mb=settings.scan_memory_mb))
        else:
            result = engine.analyze(root, options, target=target)
        _progress(db, scan, "dependency intelligence", 70)
        if "dependencies" in options.scanners:
            engine.enrich(result, options, root=root)
        engine.finalize(result)
        db.refresh(scan)
        if scan.status == ScanStatus.CANCELLED:
            return
        _progress(db, scan, "saving results", 85)
        persist_results(db, scan, result)
        scan.status = ScanStatus.COMPLETED
        scan.finished_at = utcnow()
        scan.progress = {"stage": "completed", "percent": 100}
        db.commit()
        _after_completion(db, scan)
    except (IngestError, SandboxError) as exc:
        db.rollback()
        _fail(db, scan_id, str(exc))
    except Exception as exc:
        log.exception("scan %s failed", scan_id)
        db.rollback()
        _fail(db, scan_id, f"internal error ({type(exc).__name__})")


def _fail(db: Session, scan_id: uuid.UUID, message: str) -> None:
    scan = db.get(Scan, scan_id)
    if scan is None:
        return
    scan.status = ScanStatus.FAILED
    scan.error = message[:2000]
    scan.finished_at = utcnow()
    scan.progress = {"stage": "failed", "percent": scan.progress.get("percent", 0) if scan.progress else 0}
    db.commit()


def _after_completion(db: Session, scan: Scan) -> None:
    integration = (scan.config or {}).get("_integration")
    if integration and integration.get("pr_comment"):
        queue.enqueue(db, JobKind.PR_COMMENT, {"scan_id": str(scan.id), **integration})
        db.commit()


# ---------------------------------------------------------- persistence


def _engine_view(row: Finding, occ: FindingOccurrence) -> EngineFinding:
    """Rebuild the engine-level view of a stored finding for retest comparison."""
    return EngineFinding(
        rule_id=row.rule_id, engine=Engine(row.engine), source_kind=SourceKind(row.source_kind),
        vuln_class=row.vuln_class, title=row.title, category=row.category, severity=row.severity,
        confidence=row.confidence,
        location=Location(path=occ.file_path or row.file_path or "", start_line=occ.start_line,
                          end_line=occ.end_line, function=occ.function_name, snippet=occ.snippet),
        scanners=list(occ.scanners or []), fingerprint=row.engine_fingerprint,
    )


def _baseline_for(db: Session, scan: Scan) -> Scan | None:
    if scan.baseline_scan_id:
        return db.get(Scan, scan.baseline_scan_id)
    return db.scalar(select(Scan).where(Scan.project_id == scan.project_id, Scan.repository_id == scan.repository_id,
                                        Scan.status == ScanStatus.COMPLETED, Scan.id != scan.id,
                                        Scan.scope == ScanScope.FULL)
                     .order_by(Scan.finished_at.desc()).limit(1))


def _gate_policy(db: Session, project: Project) -> GatePolicy:
    if project.gate_policy:
        return GatePolicy.from_dict(project.gate_policy)
    org = db.get(Organization, project.organization_id)
    return GatePolicy.from_dict((org.settings or {}).get("gate_policy") if org else None)


def _risk_overrides(db: Session, project: Project) -> dict | None:
    org = db.get(Organization, project.organization_id)
    return (org.settings or {}).get("risk_weights") if org else None


def persist_results(db: Session, scan: Scan, result: ScanResult) -> None:
    project = db.execute(select(Project).where(Project.id == scan.project_id).with_for_update()).scalar_one()
    now = utcnow()
    scope_key = f"repository:{scan.repository_id}"

    for record in result.files:
        db.add(ScanFile(scan_id=scan.id, path=record.path[:1024], language=record.language,
                        size_bytes=record.size_bytes, line_count=record.line_count, sha256=record.sha256,
                        status=record.status, detail=(record.detail or "")[:500] or None))
    seen_deps: set[tuple] = set()
    for dep in result.dependencies:
        key = (dep.ecosystem, dep.name, dep.version, dep.manifest_path)
        if key in seen_deps:
            continue
        seen_deps.add(key)
        db.add(Dependency(scan_id=scan.id, ecosystem=dep.ecosystem, name=dep.name[:300], version=dep.version,
                          version_spec=dep.version_spec, manifest_path=dep.manifest_path[:1024], direct=dep.direct,
                          dev=dep.dev, vuln_status=dep.vuln_status, advisory_ids=dep.advisory_ids, source=dep.source))

    existing = {f.fingerprint: f for f in db.scalars(select(Finding).where(
        Finding.project_id == project.id, Finding.repository_id == scan.repository_id))}

    # Retest comparison happens before rows are written so that an issue whose
    # code changed (fuzzy match) keeps its identity instead of becoming "new".
    baseline = _baseline_for(db, scan)
    report = None
    fuzzy_target: dict[str, Finding] = {}
    if baseline is not None:
        baseline_rows = db.execute(
            select(Finding, FindingOccurrence).join(FindingOccurrence, FindingOccurrence.finding_id == Finding.id)
            .where(FindingOccurrence.scan_id == baseline.id)).all()
        baseline_views = [_engine_view(f, o) for f, o in baseline_rows]
        by_engine_fp = {f.engine_fingerprint: f for f, _ in baseline_rows}
        resolved_history = {f.engine_fingerprint for f in existing.values()
                            if f.status == FindingStatus.RESOLVED and f.engine_fingerprint not in by_engine_fp}
        report = retest_engine.compare(
            baseline_views, result.findings, analyzed_paths=result.analyzed_paths(),
            scanners_ran={s.scanner for s in result.scanners if s.status == "ran"},
            resolved_history=resolved_history, partial=scan.scope == ScanScope.PARTIAL)
        for item in report.items:
            if item.match.value == "FUZZY" and item.baseline and item.current:
                row = by_engine_fp.get(item.baseline.fingerprint)
                if row is not None:
                    fuzzy_target[item.current.fingerprint] = row

    weights = risk_engine.merge_weights(_risk_overrides(db, project))
    observed: dict[str, Finding] = {}
    for ef in result.findings:
        scoped = fp.scoped(scope_key, ef.fingerprint)
        row = fuzzy_target.get(ef.fingerprint) or existing.get(scoped)
        if row is None:
            if ef.engine == Engine.AISEC:
                project.ai_finding_seq += 1
                public_id = f"SL-AI-{project.ai_finding_seq:03d}"
            else:
                project.finding_seq += 1
                public_id = f"SL-{project.finding_seq:03d}"
            row = Finding(project_id=project.id, repository_id=scan.repository_id, public_id=public_id,
                          fingerprint=scoped, engine_fingerprint=ef.fingerprint, status=FindingStatus.OPEN,
                          first_seen_scan_id=scan.id, first_seen_at=now, last_seen_at=now, engine=ef.engine,
                          source_kind=ef.source_kind, rule_id=ef.rule_id, vuln_class=ef.vuln_class, title=ef.title,
                          category=ef.category, severity=ef.severity, confidence=ef.confidence,
                          verification=ef.verification)
            db.add(row)
            existing[scoped] = row
        else:
            if row.fingerprint != scoped and scoped not in existing:
                # Fuzzy match: move the identity to the new code location.
                existing.pop(row.fingerprint, None)
                row.fingerprint = scoped
                row.engine_fingerprint = ef.fingerprint
                existing[scoped] = row
            if row.status == FindingStatus.RESOLVED:
                row.status = FindingStatus.REOPENED
                row.status_reason = f"Reappeared in scan {scan.id}"
                row.status_changed_at = now
                row.resolved_at = None
                row.resolved_by_scan_id = None
        loc = ef.location
        row.rule_id, row.vuln_class = ef.rule_id, ef.vuln_class
        row.title, row.category = ef.title[:300], ef.category[:120]
        row.severity, row.confidence, row.exploitability = ef.severity, ef.confidence, ef.exploitability
        row.cwe, row.owasp, row.references = ef.cwe, ef.owasp, ef.references
        row.file_path = loc.path[:1024] if loc else None
        row.line = loc.start_line if loc else None
        row.description, row.impact = ef.description, ef.impact
        row.recommendation, row.remediation_guidance = ef.recommendation, ef.remediation
        row.last_seen_scan_id, row.last_seen_at = scan.id, now
        row.risk_score = round(risk_engine.finding_risk(
            risk_engine.RiskInput(row.public_id, ef.severity, ef.confidence, ef.exploitability, row.verification,
                                  row.status), weights, project.exposure, project.business_criticality)[0], 3)
        db.flush()
        occurrence = FindingOccurrence(
            finding_id=row.id, scan_id=scan.id, file_path=loc.path[:1024] if loc else None,
            start_line=loc.start_line if loc else None, end_line=loc.end_line if loc else None,
            start_col=loc.start_col if loc else None, function_name=(loc.function or "")[:300] or None if loc else None,
            snippet=loc.snippet if loc else None, severity=ef.severity, confidence=ef.confidence,
            scanners=ef.scanners, correlation=ef.correlation)
        db.add(occurrence)
        db.flush()
        for ev in ef.evidence:
            db.add(Evidence(occurrence_id=occurrence.id, finding_id=row.id, kind=ev.kind, source=ev.source[:64],
                            summary=ev.summary, location=ev.location.model_dump() if ev.location else None,
                            data=ev.data))
            if ev.kind == "secret" and loc is not None:
                db.add(SecretFinding(finding_id=row.id, scan_id=scan.id,
                                     secret_type=ev.data.get("secret_type", "")[:100],
                                     file_path=loc.path[:1024], line=loc.start_line or 0,
                                     masked_value=str(ev.data.get("masked", ""))[:200],
                                     secret_hash=str(ev.data.get("secret_hash", ""))[:64],
                                     entropy=ev.data.get("entropy"), detector=str(ev.data.get("detector", ""))[:64]))
        observed[ef.fingerprint] = row
    db.flush()

    regressions = 0
    new_blocking = 0
    policy = _gate_policy(db, project)
    if baseline is not None and report is not None:
        retest = Retest(project_id=project.id, kind="SCAN", baseline_scan_id=baseline.id, retest_scan_id=scan.id,
                        status="COMPLETED", created_by_id=scan.created_by_id)
        db.add(retest)
        db.flush()
        baseline_by_fp = {f.engine_fingerprint: f for f, _ in db.execute(
            select(Finding, FindingOccurrence).join(FindingOccurrence, FindingOccurrence.finding_id == Finding.id)
            .where(FindingOccurrence.scan_id == baseline.id)).all()}
        stored: set[uuid.UUID] = set()
        for item in report.items:
            if item.baseline is not None:
                row = baseline_by_fp.get(item.baseline.fingerprint)
            else:
                row = observed.get(item.current.fingerprint) if item.current else None
            if row is None or row.id in stored:
                continue
            stored.add(row.id)
            gone = item.result in (RetestResultKind.RESOLVED, RetestResultKind.NOT_REPRODUCED)
            if gone and row.status in ACTIVE_STATUSES:
                row.status = FindingStatus.RESOLVED
                row.resolved_at = now
                row.resolved_by_scan_id = scan.id
                row.status_changed_at = now
                row.status_reason = item.notes
            if item.result == RetestResultKind.REGRESSION:
                regressions += 1
                row.status = FindingStatus.REOPENED
                row.status_reason = "Regression: previously resolved issue reappeared"
            if item.result == RetestResultKind.NEW and item.current is not None and \
                    item.current.severity.value in policy.fail_on:
                new_blocking += 1
            db.add(RetestResult(
                retest_id=retest.id, finding_id=row.id, result=item.result, match_method=item.match,
                before=_snapshot_of(item.baseline), after=_snapshot_of(item.current), notes=item.notes))
        retest.summary = report.summary()
        _verify_remediations(db, scan, report, baseline_by_fp)

    items: list[GateItem] = []
    risk_inputs: list[risk_engine.RiskInput] = []
    for ef in result.findings:
        row = observed[ef.fingerprint]
        items.append(GateItem(row.public_id, row.title, row.severity, row.confidence, row.verification, row.status,
                              f"{row.file_path}:{row.line}" if row.file_path else None))
        risk_inputs.append(risk_engine.RiskInput(row.public_id, row.severity, row.confidence, row.exploitability,
                                                 row.verification, row.status))
    gate = evaluate(items, policy, regressions=regressions)
    breakdown = risk_engine.compute(risk_inputs, exposure=project.exposure,
                                    business_criticality=project.business_criticality,
                                    overrides=_risk_overrides(db, project))
    scan.gate_status = gate.status
    scan.gate_reasons = gate.reasons
    scan.risk_index = breakdown.index
    stats = dict(result.stats)
    stats["scanners"] = [s.model_dump() for s in result.scanners]
    stats["errors"] = result.errors[:50]
    stats["gate"] = gate.as_dict()
    stats["risk"] = {"index": breakdown.index, "total": round(breakdown.total, 3)}
    if report is not None:
        stats["retest"] = report.summary(blocking_new=new_blocking)
    scan.stats = stats
    db.flush()


def _snapshot_of(f: EngineFinding | None) -> dict | None:
    if f is None:
        return None
    loc = f.location
    return {"severity": f.severity.value, "confidence": f.confidence.value, "rule_id": f.rule_id,
            "path": loc.path if loc else None, "line": loc.start_line if loc else None,
            "snippet": loc.snippet if loc else None}


def _verify_remediations(db: Session, scan: Scan, report, baseline_by_fp: dict) -> None:
    results = {}
    for item in report.items:
        if item.baseline is not None:
            row = baseline_by_fp.get(item.baseline.fingerprint)
            if row is not None:
                results[row.id] = item.result
    for rem in db.scalars(select(Remediation).where(Remediation.retest_scan_id == scan.id,
                                                   Remediation.status == RemediationStatus.APPLIED)):
        outcome = results.get(rem.finding_id)
        if outcome == RetestResultKind.RESOLVED:
            rem.status = RemediationStatus.VERIFIED
        elif outcome is not None:
            rem.status = RemediationStatus.NOT_VERIFIED
        rem.validation = {**(rem.validation or {}), "retest_result": outcome.value if outcome else "NOT_TESTED"}


# --------------------------------------------------------------- CLI import


def import_cli_report(db: Session, principal: Principal, project: Project, *, repository_name: str,
                      report: dict, commit: str | None, branch: str | None) -> Scan:
    """Store a CLI JSON report produced in CI. Findings are re-validated through the schema."""
    try:
        result = ScanResult.model_validate(report)
    except ValueError as exc:
        raise AppError("The report is not a valid SecureLens JSON report", code="invalid_report",
                       status_code=422) from exc
    if len(result.findings) > 20000 or len(result.files) > 200000:
        raise AppError("The report is too large", code="payload_too_large", status_code=413)
    repo = _repository_for_upload(db, project, None, repository_name, repository_name)
    # Imported evidence is re-redacted: the server never trusts clients to have masked secrets.
    for f in result.findings:
        engine._redact_finding(f)
        f.evidence = [EngineEvidence(**{**e.model_dump(), "source": f"cli:{e.source}"[:64]}) for e in f.evidence]
    scan = Scan(project_id=project.id, repository_id=repo.id, status=ScanStatus.RUNNING,
                trigger=ScanTrigger.CLI_IMPORT, scope=ScanScope.FULL,
                config={"imported": True, "commit": commit, "branch": branch}, queued_at=utcnow(),
                started_at=utcnow(), created_by_id=principal.user_id,
                api_key_id=principal.api_key.id if principal.api_key else None)
    db.add(scan)
    db.flush()
    persist_results(db, scan, result)
    scan.status = ScanStatus.COMPLETED
    scan.finished_at = utcnow()
    scan.progress = {"stage": "completed", "percent": 100}
    audit.record(db, "scan.import", principal=principal, organization_id=project.organization_id,
                 target_type="scan", target_id=scan.id, details={"findings": len(result.findings), "commit": commit})
    db.commit()
    return scan
