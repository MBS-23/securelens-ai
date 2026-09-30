"""The unified finding model shared by both engines, the CLI, reports and the API.

Both the Application Security Engine and the AI Security Engine emit
``Finding`` objects. Severity, confidence and verification are independent
axes: severity is how bad the issue is if real, confidence is how sure the
evidence makes us, verification is how the finding is known.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from securelens.enums import (
    CONFIDENCE_ORDER,
    SEVERITY_ORDER,
    Confidence,
    Engine,
    Exploitability,
    Severity,
    SourceKind,
    Verification,
)

EvidenceKind = Literal[
    "dataflow", "pattern", "code", "secret", "dependency", "scanner_output", "test_input", "model_response",
    "tool_call", "retrieval", "criterion", "correlation",
]


class Location(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    start_line: int | None = None
    end_line: int | None = None
    start_col: int | None = None
    end_col: int | None = None
    function: str | None = None
    snippet: str | None = None


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: EvidenceKind
    source: str = Field(description="Scanner or evaluator that produced this evidence")
    summary: str
    location: Location | None = None
    data: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    engine: Engine
    source_kind: SourceKind
    vuln_class: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    exploitability: Exploitability = Exploitability.POSSIBLE
    verification: Verification = Verification.DETECTED
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    location: Location | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    description: str = ""
    impact: str = ""
    recommendation: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    scanners: list[str] = Field(default_factory=list)
    fingerprint: str = ""
    correlation: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    public_id: str | None = None
    risk_score: float | None = None

    def sort_key(self) -> tuple:
        loc = self.location
        return (-SEVERITY_ORDER[self.severity], -CONFIDENCE_ORDER[self.confidence],
                loc.path if loc else "", loc.start_line or 0 if loc else 0, self.rule_id)


class FileRecord(BaseModel):
    path: str
    language: str | None = None
    size_bytes: int = 0
    line_count: int = 0
    sha256: str | None = None
    status: str
    detail: str | None = None


class DependencyRecord(BaseModel):
    ecosystem: str
    name: str
    version: str | None = None
    version_spec: str | None = None
    manifest_path: str
    direct: bool = True
    dev: bool = False
    vuln_status: str = "NOT_VERIFIED"
    advisory_ids: list[str] = Field(default_factory=list)
    source: str | None = None


class ScannerRun(BaseModel):
    """What each scanner did — so a clean result is distinguishable from 'did not run'."""

    scanner: str
    status: Literal["ran", "skipped", "unavailable", "failed"]
    detail: str | None = None
    findings: int = 0
    duration_ms: int = 0
    languages: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    """Everything one scan produced. This is also the CLI's JSON output format."""

    schema_version: str = "1.0"
    tool: dict[str, str] = Field(default_factory=dict)
    target: str
    started_at: str
    finished_at: str
    files: list[FileRecord] = Field(default_factory=list)
    dependencies: list[DependencyRecord] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    scanners: list[ScannerRun] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    gate: dict[str, Any] | None = None
    risk: dict[str, Any] | None = None
    history: dict[str, Any] = Field(default_factory=dict)

    def analyzed_paths(self) -> set[str]:
        return {f.path for f in self.files if f.status == "ANALYZED"}

    def scanner_ran(self, name: str) -> bool:
        return any(s.scanner == name and s.status == "ran" for s in self.scanners)
