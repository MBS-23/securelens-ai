"""Adapters for third-party analyzers: Bandit, Semgrep and Gitleaks.

They run only when installed and enabled; their output is normalised into the
unified finding model and correlated with SecureLens's own findings. A tool
that is not installed is reported as "unavailable", never as a clean result.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from securelens.enums import Confidence, Exploitability, Severity, SourceKind
from securelens.findings import catalog
from securelens.findings.cwe_map import class_for_cwes, normalise_cwe
from securelens.findings.model import Evidence, Finding, Location, ScannerRun
from securelens.scanners.base import ScanContext, ScannerResult
from securelens.scanners.secrets.masking import redact_text

TOOL_TIMEOUT_SECONDS = 600

BANDIT_CLASS = {
    "B102": "code_injection", "B103": "unsafe_file_handling", "B104": "dangerous_api", "B105": "hardcoded_secret",
    "B106": "hardcoded_secret", "B107": "hardcoded_secret", "B108": "unsafe_file_handling", "B201": "dangerous_api",
    "B301": "insecure_deserialization", "B302": "insecure_deserialization", "B303": "weak_cryptography",
    "B304": "weak_cryptography", "B305": "weak_cryptography", "B306": "unsafe_file_handling", "B307": "code_injection",
    "B308": "xss", "B310": "ssrf", "B311": "weak_randomness", "B312": "insecure_tls", "B313": "xxe", "B314": "xxe",
    "B315": "xxe", "B316": "xxe", "B317": "xxe", "B318": "xxe", "B319": "xxe", "B320": "xxe", "B321": "insecure_tls",
    "B323": "insecure_tls", "B324": "weak_cryptography", "B501": "insecure_tls", "B502": "insecure_tls",
    "B503": "insecure_tls", "B504": "insecure_tls", "B505": "weak_cryptography", "B506": "insecure_deserialization",
    "B507": "insecure_tls", "B601": "command_injection", "B602": "command_injection", "B604": "command_injection",
    "B605": "command_injection", "B608": "sql_injection", "B609": "command_injection", "B610": "sql_injection",
    "B611": "sql_injection", "B612": "dangerous_api", "B613": "dangerous_api", "B614": "insecure_deserialization",
    "B615": "ai_supply_chain", "B701": "xss", "B702": "xss", "B703": "xss", "B704": "xss",
}
# Code-quality or import-only checks that add noise without evidence of a vulnerability.
BANDIT_SKIP = "B101,B110,B112,B401,B402,B403,B404,B405,B406,B407,B408,B409,B410,B411,B412,B413,B415,B603,B606,B607"

_SEV = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM, "INFO": Severity.LOW, "CRITICAL": Severity.CRITICAL}
_CONF = {"HIGH": Confidence.HIGH, "MEDIUM": Confidence.MEDIUM, "LOW": Confidence.LOW}


def _minimal_env() -> dict[str, str]:
    keep = {"PATH", "HOME", "LANG", "LC_ALL", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "TMPDIR"}
    return {k: v for k, v in os.environ.items() if k in keep}


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=TOOL_TIMEOUT_SECONDS,
                          env=_minimal_env(), check=False, stdin=subprocess.DEVNULL)


def _finding(*, tool: str, rule_id: str, vuln_class: str, title: str, message: str, severity: Severity,
             confidence: Confidence, path: str, line: int | None, col: int | None, snippet: str | None,
             cwes: list[str], extra: dict, source_kind: SourceKind = SourceKind.SAST) -> Finding:
    vc = catalog.get(vuln_class if catalog.known(vuln_class) else "dangerous_api")
    location = Location(path=path, start_line=line, end_line=line, start_col=col,
                        snippet=redact_text((snippet or "").strip()[:300], path))
    return Finding(
        rule_id=f"{tool}:{rule_id}",
        engine=vc.engine,
        source_kind=source_kind,
        vuln_class=vc.key,
        title=title,
        category=vc.name,
        severity=severity,
        confidence=confidence,
        exploitability=Exploitability.THEORETICAL,
        cwe=list(dict.fromkeys([c for c in cwes if c] + list(vc.cwe))),
        owasp=list(vc.owasp),
        location=location,
        evidence=[Evidence(kind="scanner_output", source=tool, summary=redact_text(message, path) or message,
                           location=location, data=extra)],
        description=f"{message} {vc.description}",
        impact=vc.impact,
        recommendation=vc.recommendation,
        remediation=vc.remediation,
        references=list(vc.references),
        scanners=[tool],
        tags=["external", tool],
    )


def _relative(root: Path, filename: str) -> str:
    try:
        return Path(filename).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return Path(filename).as_posix().lstrip("./")


class BanditScanner:
    name = "bandit"

    def available(self) -> tuple[bool, str | None]:
        return (True, None) if shutil.which("bandit") else (False, "bandit is not installed")

    def scan(self, ctx: ScanContext) -> ScannerResult:
        started = time.monotonic()
        if not ctx.by_language("python"):
            return ScannerResult(run=ScannerRun(scanner=self.name, status="skipped", detail="no Python files"))
        excludes = ",".join(f"*/{p.rstrip('/')}/*" for p in ctx.options.excludes() if p.endswith("/"))
        cmd = [shutil.which("bandit") or "bandit", "-r", ".", "-f", "json", "-q", "-s", BANDIT_SKIP]
        if excludes:
            cmd += ["-x", excludes]
        try:
            proc = _run(cmd, ctx.root)
            data = json.loads(proc.stdout or "{}")
        except (subprocess.TimeoutExpired, ValueError, OSError) as exc:
            return ScannerResult(run=ScannerRun(scanner=self.name, status="failed", detail=type(exc).__name__))
        findings = []
        for item in data.get("results", []):
            test_id = item.get("test_id", "")
            cwe = normalise_cwe((item.get("issue_cwe") or {}).get("id"))
            vuln_class = BANDIT_CLASS.get(test_id) or class_for_cwes([cwe] if cwe else [])
            findings.append(_finding(
                tool=self.name, rule_id=test_id, vuln_class=vuln_class,
                title=f"{item.get('test_name', test_id)} (Bandit {test_id})", message=item.get("issue_text", ""),
                severity=_SEV.get(item.get("issue_severity", "MEDIUM"), Severity.MEDIUM),
                confidence=_CONF.get(item.get("issue_confidence", "MEDIUM"), Confidence.MEDIUM),
                path=_relative(ctx.root, item.get("filename", "")), line=item.get("line_number"),
                col=(item.get("col_offset") or 0) + 1,
                snippet=_bandit_line(item.get("code", ""), item.get("line_number")),
                cwes=[cwe] if cwe else [], extra={"test_id": test_id, "more_info": item.get("more_info")},
            ))
        return ScannerResult(run=ScannerRun(scanner=self.name, status="ran", findings=len(findings),
                                            duration_ms=int((time.monotonic() - started) * 1000),
                                            languages=["python"]), findings=findings)


def _bandit_line(code: str, line: int | None) -> str:
    for raw in (code or "").splitlines():
        number, _, text = raw.partition(" ")
        if number.isdigit() and int(number) == line:
            return text
    return (code or "").splitlines()[0] if code else ""


class SemgrepScanner:
    name = "semgrep"

    def available(self) -> tuple[bool, str | None]:
        return (True, None) if shutil.which("semgrep") else (False, "semgrep is not installed")

    def scan(self, ctx: ScanContext) -> ScannerResult:
        started = time.monotonic()
        config = ctx.options.semgrep_config
        if not config:
            return ScannerResult(run=ScannerRun(scanner=self.name, status="skipped",
                                                detail="no semgrep_config set (local rules or a registry ruleset)"))
        cmd = [shutil.which("semgrep") or "semgrep", "scan", "--json", "--quiet", "--metrics=off",
               "--disable-version-check", "--config", config, "."]
        for pattern in ctx.options.excludes():
            cmd += ["--exclude", pattern.rstrip("/")]
        try:
            proc = _run(cmd, ctx.root)
            data = json.loads(proc.stdout or "{}")
        except (subprocess.TimeoutExpired, ValueError, OSError) as exc:
            return ScannerResult(run=ScannerRun(scanner=self.name, status="failed", detail=type(exc).__name__))
        return ScannerResult(run=ScannerRun(scanner=self.name, status="ran", duration_ms=int(
            (time.monotonic() - started) * 1000)), findings=parse_semgrep(data, ctx.root))


def parse_semgrep(data: dict, root: Path) -> list[Finding]:
    findings = []
    for item in data.get("results", []):
        extra = item.get("extra") or {}
        meta = extra.get("metadata") or {}
        cwes_raw = meta.get("cwe") or []
        cwes = [c for c in (normalise_cwe(x) for x in (cwes_raw if isinstance(cwes_raw, list) else [cwes_raw])) if c]
        confidence = _CONF.get(str(meta.get("confidence", "MEDIUM")).upper(), Confidence.MEDIUM)
        findings.append(_finding(
            tool="semgrep", rule_id=item.get("check_id", "rule"), vuln_class=class_for_cwes(cwes),
            title=item.get("check_id", "semgrep rule").rsplit(".", 1)[-1].replace("-", " "),
            message=extra.get("message", ""), severity=_SEV.get(str(extra.get("severity", "WARNING")).upper(),
                                                                 Severity.MEDIUM),
            confidence=confidence, path=_relative(root, item.get("path", "")),
            line=(item.get("start") or {}).get("line"), col=(item.get("start") or {}).get("col"),
            snippet=extra.get("lines"), cwes=cwes, extra={"check_id": item.get("check_id")},
        ))
    return findings


class GitleaksScanner:
    name = "gitleaks"

    def available(self) -> tuple[bool, str | None]:
        return (True, None) if shutil.which("gitleaks") else (False, "gitleaks is not installed")

    def scan(self, ctx: ScanContext) -> ScannerResult:
        started = time.monotonic()
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "gitleaks.json"
            cmd = [shutil.which("gitleaks") or "gitleaks", "detect", "--no-git", "--redact", "--no-banner",
                   "--source", ".", "--report-format", "json", "--report-path", str(report), "--exit-code", "0"]
            try:
                _run(cmd, ctx.root)
                data = json.loads(report.read_text("utf-8")) if report.exists() else []
            except (subprocess.TimeoutExpired, ValueError, OSError) as exc:
                return ScannerResult(run=ScannerRun(scanner=self.name, status="failed", detail=type(exc).__name__))
        findings = parse_gitleaks(data)
        return ScannerResult(run=ScannerRun(scanner=self.name, status="ran", findings=len(findings),
                                            duration_ms=int((time.monotonic() - started) * 1000)), findings=findings)


def parse_gitleaks(data: list) -> list[Finding]:
    out = []
    for item in data or []:
        path = str(item.get("File", "")).lstrip("./")
        out.append(_finding(
            tool="gitleaks", rule_id=item.get("RuleID", "secret"), vuln_class="hardcoded_secret",
            title=f"Hardcoded secret ({item.get('Description') or item.get('RuleID')})",
            message=f"gitleaks rule {item.get('RuleID')} matched (value redacted by gitleaks)",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM, path=path, line=item.get("StartLine"),
            col=item.get("StartColumn"), snippet=None, cwes=["CWE-798"],
            extra={"rule": item.get("RuleID"), "entropy": item.get("Entropy")}, source_kind=SourceKind.SECRET,
        ))
    return out


EXTERNAL_SCANNERS = {"bandit": BanditScanner, "semgrep": SemgrepScanner, "gitleaks": GitleaksScanner}


def external_scanner_status(enabled: list[str]) -> list[dict]:
    out = []
    for name, cls in EXTERNAL_SCANNERS.items():
        ok, detail = cls().available()
        out.append({"name": name, "enabled": name in enabled, "installed": ok, "detail": detail})
    return out
