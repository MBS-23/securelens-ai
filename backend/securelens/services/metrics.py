"""Dashboard metrics, computed from stored findings and scans (never estimated).

Aggregation by day happens in Python so the same code runs on PostgreSQL and
SQLite; the row counts involved are bounded by the time windows below.
"""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from securelens.enums import ACTIVE_STATUSES, SEVERITY_ORDER, FindingStatus, ScanStatus, Severity
from securelens.models import Finding, Project, Repository, Scan
from securelens.models.base import utcnow

TREND_DAYS = 30
MTTR_DAYS = 90
_ACTIVE = [s.value for s in ACTIVE_STATUSES]
_SEVERITIES = [s.value for s in Severity]


def _severity_counts(db: Session, project_ids: list[uuid.UUID]) -> dict[str, int]:
    rows = db.execute(select(Finding.severity, func.count(Finding.id))
                      .where(Finding.project_id.in_(project_ids), Finding.status.in_(_ACTIVE))
                      .group_by(Finding.severity)).all()
    counts = dict.fromkeys(_SEVERITIES, 0)
    counts.update(dict(rows))
    return counts


def _grouped(db: Session, column, project_ids: list[uuid.UUID], *, active_only: bool = True) -> dict[str, int]:
    query = select(column, func.count(Finding.id)).where(Finding.project_id.in_(project_ids)).group_by(column)
    if active_only:
        query = query.where(Finding.status.in_(_ACTIVE))
    return dict(db.execute(query).all())


def _trend(db: Session, project_ids: list[uuid.UUID]) -> list[dict[str, Any]]:
    today = utcnow().date()
    start = utcnow() - timedelta(days=TREND_DAYS - 1)
    opened = Counter(d.date() for d in db.scalars(
        select(Finding.first_seen_at).where(Finding.project_id.in_(project_ids), Finding.first_seen_at >= start)))
    resolved = Counter(d.date() for d in db.scalars(
        select(Finding.resolved_at).where(Finding.project_id.in_(project_ids), Finding.resolved_at >= start,
                                          Finding.status == FindingStatus.RESOLVED)))
    days = [today - timedelta(days=offset) for offset in range(TREND_DAYS - 1, -1, -1)]
    return [{"date": d.isoformat(), "new": opened.get(d, 0), "resolved": resolved.get(d, 0)} for d in days]


def _mttr_days(db: Session, project_ids: list[uuid.UUID]) -> float | None:
    since = utcnow() - timedelta(days=MTTR_DAYS)
    rows = db.execute(select(Finding.first_seen_at, Finding.resolved_at).where(
        Finding.project_id.in_(project_ids), Finding.status == FindingStatus.RESOLVED,
        Finding.resolved_at >= since)).all()
    if not rows:
        return None
    total = sum((resolved - first).total_seconds() for first, resolved in rows if resolved and first)
    return round(total / len(rows) / 86400, 1)


def _risk_history(db: Session, project_ids: list[uuid.UUID], limit: int = 60) -> list[dict[str, Any]]:
    scans = db.scalars(select(Scan).where(Scan.project_id.in_(project_ids), Scan.status == ScanStatus.COMPLETED,
                                          Scan.risk_index.is_not(None))
                       .order_by(Scan.finished_at.desc()).limit(limit)).all()
    return [{"scan_id": str(s.id), "project_id": str(s.project_id), "finished_at": s.finished_at.isoformat()
             if s.finished_at else None, "risk_index": s.risk_index, "gate_status": s.gate_status}
            for s in reversed(scans)]


def _top_findings(db: Session, project_ids: list[uuid.UUID], names: dict[uuid.UUID, str],
                  limit: int = 10) -> list[dict[str, Any]]:
    rows = db.scalars(select(Finding).where(Finding.project_id.in_(project_ids), Finding.status.in_(_ACTIVE))
                      .order_by(Finding.risk_score.desc(), Finding.public_id).limit(limit)).all()
    return [{"id": str(f.id), "project_id": str(f.project_id), "project_name": names.get(f.project_id),
             "public_id": f.public_id, "title": f.title, "severity": f.severity, "confidence": f.confidence,
             "verification": f.verification, "risk_score": f.risk_score, "file_path": f.file_path, "line": f.line}
            for f in rows]


def _recent_scans(db: Session, project_ids: list[uuid.UUID], names: dict[uuid.UUID, str],
                  limit: int = 10) -> list[dict[str, Any]]:
    scans = db.scalars(select(Scan).where(Scan.project_id.in_(project_ids))
                       .order_by(Scan.created_at.desc()).limit(limit)).all()
    repos = dict(db.execute(select(Repository.id, Repository.name).where(
        Repository.id.in_({s.repository_id for s in scans if s.repository_id}))).all()) if scans else {}
    return [{"id": str(s.id), "project_id": str(s.project_id), "project_name": names.get(s.project_id),
             "repository_name": repos.get(s.repository_id), "status": s.status, "trigger": s.trigger,
             "gate_status": s.gate_status, "risk_index": s.risk_index,
             "findings": (s.stats or {}).get("findings_total"),
             "created_at": s.created_at.isoformat(), "finished_at": s.finished_at.isoformat() if s.finished_at
             else None} for s in scans]


def summary(db: Session, project_ids: list[uuid.UUID]) -> dict[str, Any]:
    """Metrics across the given (already authorised) projects."""
    projects = db.scalars(select(Project).where(Project.id.in_(project_ids)).order_by(Project.name)).all() \
        if project_ids else []
    names = {p.id: p.name for p in projects}
    empty = not project_ids
    latest: dict[uuid.UUID, Scan] = {}
    if not empty:
        for scan in db.scalars(select(Scan).where(Scan.project_id.in_(project_ids),
                                                  Scan.status == ScanStatus.COMPLETED)
                               .order_by(Scan.finished_at.desc())):
            latest.setdefault(scan.project_id, scan)
    per_project = []
    for project in projects:
        scan = latest.get(project.id)
        per_project.append({"id": str(project.id), "name": project.name, "slug": project.slug,
                            "risk_index": scan.risk_index if scan else None,
                            "gate_status": scan.gate_status if scan else None,
                            "last_scan_at": scan.finished_at.isoformat() if scan and scan.finished_at else None,
                            "open_by_severity": _severity_counts(db, [project.id])})
    per_project.sort(key=lambda p: -(p["risk_index"] or 0))
    classes = Counter() if empty else Counter(_grouped(db, Finding.vuln_class, project_ids))
    return {
        "projects": per_project,
        "open_by_severity": dict.fromkeys(_SEVERITIES, 0) if empty else _severity_counts(db, project_ids),
        "open_by_source": {} if empty else _grouped(db, Finding.source_kind, project_ids),
        "by_status": {} if empty else _grouped(db, Finding.status, project_ids, active_only=False),
        "open_by_verification": {} if empty else _grouped(db, Finding.verification, project_ids),
        "top_classes": [{"vuln_class": k, "count": n} for k, n in classes.most_common(10)],
        "trend": [] if empty else _trend(db, project_ids),
        "mttr_days": None if empty else _mttr_days(db, project_ids),
        "risk_history": [] if empty else _risk_history(db, project_ids),
        "top_findings": [] if empty else _top_findings(db, project_ids, names),
        "recent_scans": [] if empty else _recent_scans(db, project_ids, names),
        "generated_at": utcnow().isoformat(timespec="seconds"),
    }


def project_extras(db: Session, project: Project) -> dict[str, Any]:
    """Per-project details for the project overview: languages and most affected files."""
    scan = db.scalar(select(Scan).where(Scan.project_id == project.id, Scan.status == ScanStatus.COMPLETED)
                     .order_by(Scan.finished_at.desc()).limit(1))
    files = db.execute(select(Finding.file_path, Finding.severity).where(
        Finding.project_id == project.id, Finding.status.in_(_ACTIVE), Finding.file_path.is_not(None))).all()
    by_file: dict[str, dict[str, Any]] = {}
    for path, severity in files:
        entry = by_file.setdefault(path, {"path": path, "count": 0, "worst": "INFO"})
        entry["count"] += 1
        if SEVERITY_ORDER[Severity(severity)] > SEVERITY_ORDER[Severity(entry["worst"])]:
            entry["worst"] = severity
    hotspots = sorted(by_file.values(), key=lambda e: (-SEVERITY_ORDER[Severity(e["worst"])], -e["count"]))[:10]
    return {
        "latest_scan_id": str(scan.id) if scan else None,
        "languages": (scan.stats or {}).get("languages", {}) if scan else {},
        "hotspots": hotspots,
    }
