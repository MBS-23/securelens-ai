"""Secret scanner: runs the detector over every text file and emits findings."""

from __future__ import annotations

import time

from securelens.enums import Engine, Exploitability, SourceKind
from securelens.findings import catalog
from securelens.findings.model import Evidence, Finding, Location, ScannerRun
from securelens.scanners.base import ScanContext, ScannerResult
from securelens.scanners.secrets.detector import scan_text
from securelens.scanners.secrets.masking import redact_text, secret_hash

SCANNER_NAME = "securelens-secrets"


class SecretsScanner:
    name = SCANNER_NAME

    def available(self) -> tuple[bool, str | None]:
        return True, None

    def scan(self, ctx: ScanContext) -> ScannerResult:
        started = time.monotonic()
        vc = catalog.get("hardcoded_secret")
        findings: list[Finding] = []
        errors: list[str] = []
        for source in ctx.files:
            try:
                text = source.read()
            except OSError as exc:  # pragma: no cover
                errors.append(f"{source.path}: {exc.strerror}")
                continue
            lines = text.splitlines()
            for match in scan_text(source.path, text):
                raw_line = lines[match.line - 1] if match.line <= len(lines) else ""
                snippet = redact_text(raw_line.strip()[:300], source.path, [match.value]) or ""
                location = Location(path=source.path, start_line=match.line, end_line=match.line,
                                    start_col=match.col, snippet=snippet)
                note = f" ({'; '.join(match.notes)})" if match.notes else ""
                findings.append(Finding(
                    rule_id=f"SL-SECRET-{match.pattern.id.upper()}",
                    engine=Engine.APPSEC,
                    source_kind=SourceKind.SECRET,
                    vuln_class="hardcoded_secret",
                    title=f"Hardcoded {match.pattern.name}",
                    category=vc.name,
                    severity=match.severity,
                    confidence=match.confidence,
                    exploitability=Exploitability.LIKELY,
                    cwe=list(vc.cwe),
                    owasp=list(vc.owasp),
                    location=location,
                    evidence=[Evidence(
                        kind="secret",
                        source=SCANNER_NAME,
                        summary=f"{match.pattern.name} found: {match.masked}{note}",
                        location=location,
                        data={
                            "secret_type": match.pattern.name,
                            "detector": match.pattern.id,
                            "masked": match.masked,
                            "secret_hash": secret_hash(match.value, ctx.options.secret_hash_key),
                            "entropy": match.entropy,
                            "notes": match.notes,
                        },
                    )],
                    description=f"A {match.pattern.name.lower()} is present in {source.path}. {vc.description}",
                    impact=vc.impact,
                    recommendation=vc.recommendation,
                    remediation=vc.secure_pattern(source.language),
                    references=list(vc.references),
                    scanners=[SCANNER_NAME],
                    tags=["secret", match.pattern.id],
                ))
        run = ScannerRun(scanner=self.name, status="ran", findings=len(findings),
                         duration_ms=int((time.monotonic() - started) * 1000))
        return ScannerResult(run=run, findings=findings, errors=errors)
