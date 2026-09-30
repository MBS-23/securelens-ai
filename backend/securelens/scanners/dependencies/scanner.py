"""Dependency security: inventory (offline, sandbox-safe) and advisory enrichment (network)."""

from __future__ import annotations

import time

from securelens.enums import Engine, Exploitability, SourceKind
from securelens.findings import catalog
from securelens.findings.model import DependencyRecord, Evidence, Finding, Location, ScannerRun, ScanResult
from securelens.scanners.base import ScanContext, ScannerResult, ScanOptions
from securelens.scanners.dependencies.advisories import LookupResult, OfflineSource, OSVSource, VulnerabilitySource
from securelens.scanners.dependencies.manifests import merge, parser_for

SCANNER_NAME = "securelens-dependencies"


class DependencyInventoryScanner:
    name = SCANNER_NAME

    def available(self) -> tuple[bool, str | None]:
        return True, None

    def scan(self, ctx: ScanContext) -> ScannerResult:
        started = time.monotonic()
        parsed = []
        errors: list[str] = []
        for source in ctx.files:
            parser = parser_for(source.path)
            if parser is None:
                continue
            try:
                parsed.append(parser(source.path, source.read()))
            except Exception as exc:  # malformed manifests must not stop the scan
                errors.append(f"{source.path}: could not parse manifest ({type(exc).__name__})")
        records = merge(parsed)
        run = ScannerRun(scanner=self.name, status="ran", duration_ms=int((time.monotonic() - started) * 1000),
                         detail=f"{len(records)} dependencies from {len(parsed)} manifest(s)")
        return ScannerResult(run=run, dependencies=records, errors=errors)


def build_source(options: ScanOptions) -> VulnerabilitySource | None:
    if options.vulnerability_source == "offline":
        return OfflineSource(options.offline_db) if options.offline_db else None
    if options.vulnerability_source == "osv":
        return OSVSource(options.osv_url, timeout=options.osv_timeout_seconds)
    return None


def enrich(result: ScanResult, options: ScanOptions, source: VulnerabilitySource | None = None,
           manifest_lines: dict[str, list[str]] | None = None) -> None:
    """Look up advisories for the inventory and append dependency findings to ``result``."""
    started = time.monotonic()
    deps = result.dependencies
    source = source or build_source(options)
    run = ScannerRun(scanner="dependency-advisories", status="skipped")
    if not deps:
        run.detail = "no dependencies found"
        result.scanners.append(run)
        return
    if source is None:
        for dep in deps:
            dep.vuln_status = "NOT_VERIFIED"
        run.detail = "vulnerability lookup disabled; dependencies are NOT VERIFIED"
        result.scanners.append(run)
        return
    lookup: LookupResult = source.lookup(deps)
    findings = []
    for index, dep in enumerate(deps):
        if index in lookup.advisories:
            dep.vuln_status = "VULNERABLE"
            dep.advisory_ids = [a.id for a in lookup.advisories[index]]
            dep.source = lookup.source
            findings.extend(_finding(dep, adv, manifest_lines or {}) for adv in lookup.advisories[index])
        elif index in lookup.verified:
            dep.vuln_status = "NO_KNOWN_VULNERABILITIES"
            dep.source = lookup.source
        else:
            dep.vuln_status = "NOT_VERIFIED"
    result.findings.extend(findings)
    if lookup.error:
        result.errors.append(lookup.error)
        run.status = "failed"
        run.detail = lookup.error
    else:
        unverified = sum(1 for d in deps if d.vuln_status == "NOT_VERIFIED")
        run.status = "ran"
        run.detail = (f"{lookup.source}: {len(lookup.verified)} verified, {unverified} not verified "
                      f"(no exact version)")
    run.findings = len(findings)
    run.duration_ms = int((time.monotonic() - started) * 1000)
    result.scanners.append(run)


def _manifest_line(lines: list[str], name: str) -> int | None:
    lowered = name.lower()
    for i, line in enumerate(lines, start=1):
        if lowered in line.lower():
            return i
    return None


def _finding(dep: DependencyRecord, adv, manifest_lines: dict[str, list[str]]) -> Finding:
    vc = catalog.get("vulnerable_dependency")
    lines = manifest_lines.get(dep.manifest_path, [])
    line = _manifest_line(lines, dep.name) if lines else None
    snippet = lines[line - 1].strip()[:300] if line else None
    fix = f" Fixed in: {', '.join(adv.fixed_versions)}." if adv.fixed_versions else " No fixed version is published."
    cve = [a for a in adv.aliases if a.startswith("CVE-")]
    title = f"{dep.name} {dep.version} — {adv.id}" + (f" ({cve[0]})" if cve else "")
    location = Location(path=dep.manifest_path, start_line=line, end_line=line, snippet=snippet)
    return Finding(
        rule_id=adv.id,
        engine=Engine.APPSEC,
        source_kind=SourceKind.DEPENDENCY,
        vuln_class="vulnerable_dependency",
        title=title,
        category=vc.name,
        severity=adv.severity,
        confidence=__import__("securelens.enums", fromlist=["Confidence"]).Confidence.HIGH,
        exploitability=Exploitability.POSSIBLE,
        cwe=list(vc.cwe),
        owasp=list(vc.owasp),
        location=location,
        evidence=[Evidence(
            kind="dependency",
            source=adv.source,
            summary=f"{dep.ecosystem} package {dep.name}@{dep.version} matches {adv.id}: {adv.summary}",
            location=location,
            data={
                "ecosystem": dep.ecosystem, "name": dep.name, "version": dep.version, "direct": dep.direct,
                "dev": dep.dev, "manifest": dep.manifest_path, "advisory_id": adv.id, "aliases": adv.aliases,
                "summary": adv.summary, "affected_ranges": adv.affected_ranges, "fixed_versions": adv.fixed_versions,
                "severity_source": adv.severity_source, "cvss_vector": adv.cvss_vector, "cvss_score": adv.cvss_score,
                "published": adv.published, "modified": adv.modified, "verification": "VERIFIED",
                "source": adv.source,
            },
        )],
        description=(f"{adv.summary or adv.id}. {dep.name} {dep.version} is inside the affected range "
                     f"({'; '.join(adv.affected_ranges) or 'see advisory'}).{fix}"),
        impact=vc.impact,
        recommendation=(f"Upgrade {dep.name} to {adv.fixed_versions[-1]} or later, then rescan."
                        if adv.fixed_versions else vc.recommendation),
        remediation=vc.remediation,
        references=adv.references or list(vc.references),
        scanners=[SCANNER_NAME],
        tags=["dependency", dep.ecosystem.lower(), "direct" if dep.direct else "transitive"],
    )
