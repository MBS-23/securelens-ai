"""The report model shared by the HTML, Markdown, SARIF and JSON renderers.

Every report states its scope, methodology, limitations and generation time.
Those sections are derived from what actually ran in this scan (which
scanners, which languages, which files were skipped, whether the advisory
lookup happened), never from boilerplate that claims more than that.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

from securelens.enums import Exploitability
from securelens.findings import explain as explainer
from securelens.findings import risk as risk_engine
from securelens.findings.gate import GateItem, GatePolicy, evaluate
from securelens.findings.model import Finding, ScanResult
from securelens.scanners.workspace import SAST_LANGUAGES
from securelens.version import TOOL_NAME, TOOL_URI, __version__

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SCANNER_LABELS = {
    "securelens-sast": "SecureLens SAST",
    "securelens-secrets": "SecureLens secret detection",
    "securelens-dependencies": "SecureLens dependency inventory",
    "dependency-advisories": "Known-vulnerability lookup",
    "bandit": "Bandit",
    "semgrep": "Semgrep",
    "gitleaks": "Gitleaks",
}

_SKIP_REASONS = {
    "SKIPPED_SIZE": "too large",
    "SKIPPED_BINARY": "binary",
    "SKIPPED_UNSUPPORTED": "unsupported type",
    "PARSE_ERROR": "could not be parsed",
}

ASSURANCE_STATEMENT = (
    "This report reflects the code at the time of the scan. It is not a certification and does not represent "
    "complete security assurance."
)


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def gate_items(findings: list[Finding]) -> list[GateItem]:
    return [GateItem(f.public_id or f.fingerprint[:12], f.title, f.severity.value, f.confidence.value,
                     f.verification.value, "OPEN",
                     f"{f.location.path}:{f.location.start_line}" if f.location else None)
            for f in findings]


def apply_gate_and_risk(result: ScanResult, policy: GatePolicy | None = None, *, regressions: int = 0,
                        new_blocking: int | None = None, exposure: str = "UNKNOWN",
                        business_criticality: str | None = None,
                        risk_overrides: dict[str, Any] | None = None) -> ScanResult:
    """Fill ``result.gate`` and ``result.risk`` (used by the CLI; the server computes its own)."""
    gate = evaluate(gate_items(result.findings), policy or GatePolicy(), regressions=regressions,
                    new_blocking=new_blocking)
    result.gate = gate.as_dict()
    breakdown = risk_engine.compute(
        [risk_engine.RiskInput(f.public_id or f.fingerprint[:12], f.severity.value, f.confidence.value,
                               f.exploitability.value, f.verification.value) for f in result.findings],
        exposure=exposure, business_criticality=business_criticality, overrides=risk_overrides)
    result.risk = {"index": breakdown.index, "total": round(breakdown.total, 3),
                   "methodology": breakdown.methodology}
    return result


# ------------------------------------------------------------------ sections


def scope(result: ScanResult, *, scan_scope: str = "FULL", commit: str | None = None,
          branch: str | None = None) -> dict[str, Any]:
    stats = result.stats or {}
    languages = stats.get("languages") or {}
    return {
        "target": result.target,
        "scope": scan_scope,
        "commit": commit,
        "branch": branch,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "files_total": stats.get("files_total", len(result.files)),
        "files_analyzed": stats.get("files_analyzed", len(result.analyzed_paths())),
        "lines_analyzed": stats.get("lines_analyzed", 0),
        "languages": [{"name": name, "files": v.get("files", 0), "lines": v.get("lines", 0),
                       "sast": bool(v.get("sast"))} for name, v in sorted(languages.items())],
        "scanners": [{"name": s.scanner, "label": SCANNER_LABELS.get(s.scanner, s.scanner), "status": s.status,
                      "detail": s.detail, "findings": s.findings, "duration_ms": s.duration_ms,
                      "languages": s.languages} for s in result.scanners],
        "dependencies_total": len(result.dependencies),
    }


def methodology(result: ScanResult) -> list[dict[str, str]]:
    runs = {s.scanner: s for s in result.scanners}
    items: list[dict[str, str]] = []
    sast = runs.get("securelens-sast")
    if sast is not None and sast.status == "ran":
        languages = ", ".join(sast.languages) if sast.languages else "no supported source files were found"
        items.append({"name": "Static analysis (SAST)", "text": (
            f"Source files were parsed into a language-neutral representation ({languages}) and analysed with "
            "inter-procedural taint tracking. SecureLens follows data from untrusted sources (request data, "
            "files, environment, LLM output) through assignments and function calls to dangerous sinks and "
            "records that path as evidence. Structural rules flag risky constructs that need no data flow, such "
            "as weak cryptography or disabled TLS verification. When the origin of a value could not be traced, "
            "the finding carries lower confidence and 'Possible' in its title.")})
    secrets = runs.get("securelens-secrets")
    if secrets is not None and secrets.status == "ran":
        items.append({"name": "Secret detection", "text": (
            "Text files were checked against provider-specific credential formats and high-entropy values "
            "assigned to secret-like names. Secret values are masked in every output; only a keyed hash is kept "
            "so the same secret can be recognised in later scans.")})
    inventory = runs.get("securelens-dependencies")
    if inventory is not None and inventory.status == "ran":
        items.append({"name": "Dependency inventory", "text": (
            "Package manifests and lock files were parsed to list direct and transitive dependencies"
            + (f" ({inventory.detail})." if inventory.detail else "."))})
    advisories = runs.get("dependency-advisories")
    if advisories is not None:
        if advisories.status == "ran":
            text = (f"Exactly pinned versions were checked against published advisories ({advisories.detail}). "
                    "A version that cannot be resolved exactly is marked NOT VERIFIED, never assumed safe.")
        else:
            text = (f"The known-vulnerability lookup did not run ({advisories.detail or advisories.status}). "
                    "Dependencies are therefore marked NOT VERIFIED.")
        items.append({"name": "Known-vulnerability lookup", "text": text})
    for name in ("bandit", "semgrep", "gitleaks"):
        run = runs.get(name)
        if run is not None and run.status == "ran":
            items.append({"name": f"{SCANNER_LABELS[name]} (third-party)", "text": (
                "Its results were normalised into the SecureLens finding model and correlated with SecureLens's "
                "own findings; reports of the same issue at the same location are merged.")})
    items.append({"name": "Correlation, severity and risk", "text": (
        "Reports of the same issue from different scanners are merged into one finding. Severity (impact if "
        "the issue is real), confidence (strength of the evidence), exploitability and verification are "
        "reported separately. " + risk_engine.METHODOLOGY)})
    return items


def limitations(result: ScanResult, *, scan_scope: str = "FULL") -> list[str]:
    out = [
        "Static analysis examines source code without executing it. It can miss vulnerabilities (false "
        "negatives) and can report code that is not exploitable in practice (false positives). Review findings "
        "before acting on them.",
        "Business-logic flaws, authorization design, runtime configuration, infrastructure and the deployed "
        "environment were not assessed.",
        ASSURANCE_STATEMENT,
    ]
    if scan_scope == "PARTIAL":
        out.append("Partial scan: only the submitted files were analysed. Other files are not covered, and "
                   "earlier findings in them are reported as NOT TESTED.")
    for run in result.scanners:
        if run.status in ("skipped", "unavailable", "failed"):
            label = SCANNER_LABELS.get(run.scanner, run.scanner)
            out.append(f"{label} {run.status}" + (f": {run.detail}" if run.detail else "."))
    skipped = Counter(f.status for f in result.files if f.status in _SKIP_REASONS)
    if skipped:
        parts = ", ".join(f"{n} {_SKIP_REASONS[s]}" for s, n in sorted(skipped.items()))
        out.append(f"{sum(skipped.values())} file(s) were not fully analysed ({parts}).")
    languages = (result.stats or {}).get("languages") or {}
    no_sast = sorted(name for name in languages if name not in SAST_LANGUAGES)
    if no_sast:
        out.append(f"Files in {', '.join(no_sast)} were checked for secrets only; SAST rules for these languages "
                   "are not available yet.")
    unverified = sum(1 for d in result.dependencies if d.vuln_status == "NOT_VERIFIED")
    if unverified:
        out.append(f"{unverified} dependenc{'y' if unverified == 1 else 'ies'} could not be checked for known "
                   "vulnerabilities (no exact version, or no advisory source) and are marked NOT VERIFIED.")
    weak = sum(1 for f in result.findings
               if f.exploitability in (Exploitability.POSSIBLE, Exploitability.THEORETICAL))
    if weak:
        out.append(f"{weak} finding(s) are pattern matches or have an untraced input origin; their "
                   "exploitability is not proven.")
    ai = sum(1 for f in result.findings if f.verification.value == "AI_SUGGESTED")
    if ai:
        out.append(f"{ai} finding(s) are AI-suggested: no deterministic scanner or person has confirmed them.")
    if result.errors:
        out.append(f"{len(result.errors)} analysis error(s) occurred; see the scanner details.")
    return out


def finding_view(f: Finding) -> dict[str, Any]:
    loc = f.location
    explanation = explainer.explain(
        vuln_class=f.vuln_class, title=f.title, severity=f.severity.value, confidence=f.confidence.value,
        exploitability=f.exploitability.value, evidence=[e.model_dump() for e in f.evidence],
        file_path=loc.path if loc else None, line=loc.start_line if loc else None)
    return {
        "id": f.public_id or "",
        "title": f.title,
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "exploitability": f.exploitability.value,
        "verification": f.verification.value,
        "engine": f.engine.value,
        "source_kind": f.source_kind.value,
        "category": f.category,
        "vuln_class": f.vuln_class,
        "rule_id": f.rule_id,
        "cwe": list(f.cwe),
        "owasp": list(f.owasp),
        "path": loc.path if loc else None,
        "line": loc.start_line if loc else None,
        "location": (f"{loc.path}:{loc.start_line}" if loc and loc.start_line else (loc.path if loc else "")),
        "function": loc.function if loc else None,
        "snippet": loc.snippet if loc else None,
        "description": f.description,
        "impact": f.impact,
        "recommendation": f.recommendation,
        "remediation": f.remediation,
        "references": [r for r in f.references if r.startswith(("https://", "http://"))],
        "scanners": list(f.scanners),
        "fingerprint": f.fingerprint,
        "evidence": [{"kind": e.kind, "source": e.source, "summary": e.summary} for e in f.evidence],
        "steps": explanation["steps"],
    }


def summary(result: ScanResult) -> dict[str, Any]:
    severity = Counter(f.severity.value for f in result.findings)
    return {
        "total": len(result.findings),
        "by_severity": {s: severity.get(s, 0) for s in SEVERITIES},
        "by_source": dict(Counter(f.source_kind.value for f in result.findings)),
        "by_verification": dict(Counter(f.verification.value for f in result.findings)),
        "by_exploitability": dict(Counter(f.exploitability.value for f in result.findings)),
        "dependencies": dict(Counter(d.vuln_status for d in result.dependencies)),
    }


def build(result: ScanResult, *, title: str | None = None, project: str | None = None, scan_scope: str = "FULL",
          commit: str | None = None, branch: str | None = None, retest: dict[str, Any] | None = None,
          generated_at: str | None = None) -> dict[str, Any]:
    return {
        "meta": {
            "title": title or f"Security scan report — {result.target}",
            "project": project,
            "tool": TOOL_NAME,
            "tool_version": (result.tool or {}).get("version", __version__),
            "tool_uri": TOOL_URI,
            "generated_at": generated_at or now_iso(),
        },
        "summary": summary(result),
        "gate": result.gate,
        "risk": result.risk,
        "retest": retest if retest is not None else (result.history or {}).get("retest"),
        "scope": scope(result, scan_scope=scan_scope, commit=commit, branch=branch),
        "methodology": methodology(result),
        "limitations": limitations(result, scan_scope=scan_scope),
        "findings": [finding_view(f) for f in result.findings],
        "dependencies": [d.model_dump() for d in result.dependencies],
        "errors": list(result.errors[:50]),
        "risk_methodology": risk_engine.METHODOLOGY,
    }
