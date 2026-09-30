"""Reports for stored scans: rebuild the scan's ScanResult from the database and render it.

The report shows the scan as it was (the occurrences recorded by that scan),
with each finding's current verification, so a finding triaged as a false
positive after the scan is labelled as such.
"""

from __future__ import annotations

import re
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from securelens.findings.model import DependencyRecord, FileRecord, Location, ScannerRun, ScanResult
from securelens.findings.model import Evidence as EngineEvidence
from securelens.findings.model import Finding as EngineFinding
from securelens.models import Dependency, Finding, FindingOccurrence, Project, Repository, Scan, ScanFile, Snapshot
from securelens.reporting import CONTENT_TYPES, EXTENSIONS, render
from securelens.version import TOOL_NAME, __version__

_STATS_SECTIONS = {"scanners", "errors", "gate", "risk", "retest"}


def _iso(value: datetime | None) -> str:
    return value.isoformat(timespec="seconds") if value else ""


def scan_target(db: Session, scan: Scan) -> str:
    repo = db.get(Repository, scan.repository_id) if scan.repository_id else None
    snapshot = db.get(Snapshot, scan.snapshot_id) if scan.snapshot_id else None
    if repo is not None:
        return repo.name
    return (snapshot.upload_name if snapshot else None) or "source"


def scan_result_from_db(db: Session, scan: Scan) -> ScanResult:
    files = [FileRecord(path=f.path, language=f.language, size_bytes=f.size_bytes, line_count=f.line_count,
                        sha256=f.sha256, status=f.status, detail=f.detail)
             for f in db.scalars(select(ScanFile).where(ScanFile.scan_id == scan.id).order_by(ScanFile.path))]
    dependencies = [DependencyRecord(ecosystem=d.ecosystem, name=d.name, version=d.version,
                                     version_spec=d.version_spec, manifest_path=d.manifest_path, direct=d.direct,
                                     dev=d.dev, vuln_status=d.vuln_status, advisory_ids=list(d.advisory_ids or []),
                                     source=d.source)
                    for d in db.scalars(select(Dependency).where(Dependency.scan_id == scan.id)
                                        .order_by(Dependency.ecosystem, Dependency.name))]
    rows = db.execute(
        select(FindingOccurrence, Finding).join(Finding, Finding.id == FindingOccurrence.finding_id)
        .where(FindingOccurrence.scan_id == scan.id).options(selectinload(FindingOccurrence.evidence))
    ).all()
    findings: list[EngineFinding] = []
    for occ, row in rows:
        evidence = [EngineEvidence(kind=e.kind, source=e.source, summary=e.summary,
                                   location=Location(**e.location) if e.location else None, data=e.data or {})
                    for e in occ.evidence]
        findings.append(EngineFinding(
            rule_id=row.rule_id, engine=row.engine, source_kind=row.source_kind, vuln_class=row.vuln_class,
            title=row.title, category=row.category, severity=occ.severity, confidence=occ.confidence,
            exploitability=row.exploitability, verification=row.verification, cwe=list(row.cwe or []),
            owasp=list(row.owasp or []),
            location=Location(path=occ.file_path, start_line=occ.start_line, end_line=occ.end_line,
                              start_col=occ.start_col, function=occ.function_name, snippet=occ.snippet)
            if occ.file_path else None,
            evidence=evidence, description=row.description, impact=row.impact, recommendation=row.recommendation,
            remediation=row.remediation_guidance, references=list(row.references or []),
            scanners=list(occ.scanners or []), fingerprint=row.engine_fingerprint, correlation=occ.correlation or {},
            public_id=row.public_id, risk_score=row.risk_score,
        ))
    findings.sort(key=EngineFinding.sort_key)
    stats = scan.stats or {}
    return ScanResult(
        tool={"name": TOOL_NAME, "version": __version__},
        target=scan_target(db, scan),
        started_at=_iso(scan.started_at or scan.created_at),
        finished_at=_iso(scan.finished_at),
        files=files,
        dependencies=dependencies,
        findings=findings,
        scanners=[ScannerRun(**s) for s in stats.get("scanners", [])],
        errors=list(stats.get("errors", [])),
        stats={k: v for k, v in stats.items() if k not in _STATS_SECTIONS},
        gate=stats.get("gate"),
        risk=stats.get("risk"),
        history={"retest": stats["retest"]} if stats.get("retest") else {},
    )


def render_scan_report(db: Session, project: Project, scan: Scan, fmt: str) -> tuple[str, str, str]:
    """Return ``(content, content_type, filename)``."""
    result = scan_result_from_db(db, scan)
    snapshot = db.get(Snapshot, scan.snapshot_id) if scan.snapshot_id else None
    commit = snapshot.git_commit if snapshot else (scan.config or {}).get("commit")
    branch = snapshot.git_ref if snapshot else (scan.config or {}).get("branch")
    kwargs = {} if fmt == "sarif" else {
        "title": f"Security scan report — {project.name} / {result.target}", "project": project.name,
        "scan_scope": scan.scope, "commit": commit, "branch": branch}
    content = render(result, fmt, **kwargs)
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", f"{project.slug}-{result.target}")[:80].strip("-") or "scan"
    return content, CONTENT_TYPES[fmt], f"securelens-{slug}-{scan.id.hex[:8]}.{EXTENSIONS[fmt]}"
