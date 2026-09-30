"""Application Security Engine orchestration.

    analyze()  — inventory + local scanners (no network; safe inside the sandbox)
    enrich()   — dependency vulnerability intelligence (network, outside the sandbox)
    finalize() — correlation, redaction, fingerprints, IDs, statistics
    run_scan() — all three, for the CLI
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

from securelens.enums import Engine
from securelens.findings import fingerprint
from securelens.findings.correlation import correlate
from securelens.findings.model import Finding, ScannerRun, ScanResult
from securelens.scanners.base import ScanContext, ScannerResult, ScanOptions
from securelens.scanners.dependencies import scanner as deps
from securelens.scanners.external import EXTERNAL_SCANNERS
from securelens.scanners.sast.scanner import SastScanner
from securelens.scanners.secrets.masking import redact_text
from securelens.scanners.secrets.scanner import SecretsScanner
from securelens.scanners.workspace import SAST_LANGUAGES, build_inventory
from securelens.version import __version__


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def selected_scanners(options: ScanOptions) -> tuple[list, list[ScannerRun]]:
    scanners: list = []
    notes: list[ScannerRun] = []
    if "sast" in options.scanners:
        scanners.append(SastScanner())
    if "secrets" in options.scanners:
        scanners.append(SecretsScanner())
    if "dependencies" in options.scanners:
        scanners.append(deps.DependencyInventoryScanner())
    for name, mode in options.external.items():
        cls = EXTERNAL_SCANNERS.get(name)
        if cls is None or mode == "off":
            continue
        scanner = cls()
        ok, detail = scanner.available()
        if ok:
            scanners.append(scanner)
        else:
            notes.append(ScannerRun(scanner=name, status="unavailable" if mode == "auto" else "failed", detail=detail))
    return scanners, notes


def analyze(root: Path, options: ScanOptions, target: str | None = None) -> ScanResult:
    started = time.monotonic()
    result = ScanResult(tool={"name": "SecureLens AI", "version": __version__}, target=target or str(root),
                        started_at=_now(), finished_at="")
    files, records, errors = build_inventory(root, options)
    result.files = records
    result.errors.extend(errors)
    base = root if root.is_dir() else root.parent
    ctx = ScanContext(root=base.resolve(), files=files, options=options)
    scanners, notes = selected_scanners(options)
    result.scanners.extend(notes)
    parse_errors: dict[str, str] = {}
    for scanner in scanners:
        try:
            out: ScannerResult = scanner.scan(ctx)
        except Exception as exc:  # one failing scanner must not hide the others' results
            result.scanners.append(ScannerRun(scanner=scanner.name, status="failed", detail=type(exc).__name__))
            result.errors.append(f"{scanner.name} failed: {type(exc).__name__}: {str(exc)[:200]}")
            continue
        result.scanners.append(out.run)
        result.findings.extend(out.findings)
        result.dependencies.extend(out.dependencies)
        result.errors.extend(out.errors)
        parse_errors.update(out.parse_errors)
    for record in result.files:
        if record.path in parse_errors:
            detail = parse_errors[record.path]
            if "prevented" in detail or "failure" in detail:
                record.status = "PARSE_ERROR"
            record.detail = detail
    result.stats["analysis_ms"] = int((time.monotonic() - started) * 1000)
    return result


def enrich(result: ScanResult, options: ScanOptions, root: Path | None = None, source=None) -> None:
    lines: dict[str, list[str]] = {}
    if root is not None:
        base = root if root.is_dir() else root.parent
        for dep in result.dependencies:
            if dep.manifest_path not in lines:
                try:
                    text = (base / dep.manifest_path).read_text("utf-8", errors="replace")
                    lines[dep.manifest_path] = text.splitlines()
                except OSError:
                    lines[dep.manifest_path] = []
    deps.enrich(result, options, source=source, manifest_lines=lines)


def _redact_finding(f: Finding) -> None:
    path = f.location.path if f.location else None
    if f.location and f.location.snippet:
        f.location.snippet = redact_text(f.location.snippet, path)
    for e in f.evidence:
        e.summary = redact_text(e.summary, path) or e.summary
        if e.location and e.location.snippet:
            e.location.snippet = redact_text(e.location.snippet, path)
        for key in ("steps", "sources"):
            for item in e.data.get(key, []) or []:
                if isinstance(item, dict) and item.get("code"):
                    item["code"] = redact_text(item["code"], item.get("path"))


def assign_ids(findings: list[Finding]) -> None:
    app = sorted((f for f in findings if f.engine == Engine.APPSEC), key=Finding.sort_key)
    ai = sorted((f for f in findings if f.engine == Engine.AISEC), key=Finding.sort_key)
    for i, f in enumerate(app, start=1):
        f.public_id = f"SL-{i:03d}"
    for i, f in enumerate(ai, start=1):
        f.public_id = f"SL-AI-{i:03d}"


def finalize(result: ScanResult) -> ScanResult:
    findings = correlate(result.findings)
    for f in findings:
        _redact_finding(f)
        f.fingerprint = fingerprint.compute(f)
    # Two correlated groups can still share a fingerprint (same line text in one function); keep the stronger one.
    unique: dict[str, Finding] = {}
    for f in sorted(findings, key=Finding.sort_key):
        unique.setdefault(f.fingerprint, f)
    result.findings = sorted(unique.values(), key=Finding.sort_key)
    assign_ids(result.findings)
    result.finished_at = _now()
    result.stats.update(compute_stats(result))
    return result


def compute_stats(result: ScanResult) -> dict:
    by_status: dict[str, int] = {}
    languages: dict[str, dict[str, int]] = {}
    for f in result.files:
        by_status[f.status] = by_status.get(f.status, 0) + 1
        if f.status == "ANALYZED" and f.language:
            entry = languages.setdefault(f.language,
                                         {"files": 0, "lines": 0, "sast": int(f.language in SAST_LANGUAGES)})
            entry["files"] += 1
            entry["lines"] += f.line_count
    severity: dict[str, int] = {}
    kinds: dict[str, int] = {}
    for f in result.findings:
        severity[f.severity.value] = severity.get(f.severity.value, 0) + 1
        kinds[f.source_kind.value] = kinds.get(f.source_kind.value, 0) + 1
    dep_status: dict[str, int] = {}
    for d in result.dependencies:
        dep_status[d.vuln_status] = dep_status.get(d.vuln_status, 0) + 1
    return {
        "files_total": len(result.files),
        "files_analyzed": by_status.get("ANALYZED", 0),
        "files_by_status": by_status,
        "languages": languages,
        "lines_analyzed": sum(v["lines"] for v in languages.values()),
        "findings_total": len(result.findings),
        "findings_by_severity": severity,
        "findings_by_source": kinds,
        "dependencies_total": len(result.dependencies),
        "dependencies_by_status": dep_status,
    }


def run_scan(root: Path, options: ScanOptions, target: str | None = None, advisory_source=None) -> ScanResult:
    result = analyze(root, options, target=target)
    if "dependencies" in options.scanners:
        enrich(result, options, root=root, source=advisory_source)
    return finalize(result)
