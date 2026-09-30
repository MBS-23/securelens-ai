from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from securelens.enums import FindingStatus, Verification
from securelens.schemas.common import APIModel, ORMModel


class FindingOut(ORMModel):
    id: uuid.UUID
    project_id: uuid.UUID
    repository_id: uuid.UUID | None
    target_id: uuid.UUID | None
    public_id: str
    engine: str
    source_kind: str
    rule_id: str
    vuln_class: str
    title: str
    category: str
    severity: str
    confidence: str
    verification: str
    status: str
    exploitability: str
    cwe: list[Any]
    owasp: list[Any]
    file_path: str | None
    line: int | None
    risk_score: float
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None
    status_reason: str | None


class EvidenceOut(ORMModel):
    id: uuid.UUID
    kind: str
    source: str
    summary: str
    location: dict[str, Any] | None
    data: dict[str, Any]


class OccurrenceOut(ORMModel):
    id: uuid.UUID
    scan_id: uuid.UUID | None
    test_run_id: uuid.UUID | None
    file_path: str | None
    start_line: int | None
    end_line: int | None
    function_name: str | None
    snippet: str | None
    severity: str
    confidence: str
    scanners: list[Any]
    correlation: dict[str, Any]
    created_at: datetime
    evidence: list[EvidenceOut] = []


class RetestHistoryOut(BaseModel):
    retest_id: uuid.UUID
    result: str
    match_method: str
    notes: str | None
    created_at: datetime
    retest_scan_id: uuid.UUID | None
    retest_run_id: uuid.UUID | None


class FindingDetailOut(FindingOut):
    description: str
    impact: str
    recommendation: str
    remediation_guidance: str
    references: list[Any]
    occurrences: list[OccurrenceOut]
    retests: list[RetestHistoryOut]
    explanation: dict[str, Any]
    learning: dict[str, Any] | None = None


class StatusUpdateIn(APIModel):
    status: FindingStatus
    reason: str | None = Field(default=None, max_length=2000)


class VerificationUpdateIn(APIModel):
    verification: Verification
    reason: str | None = Field(default=None, max_length=2000)


class RetestOut(ORMModel):
    id: uuid.UUID
    project_id: uuid.UUID
    kind: str
    baseline_scan_id: uuid.UUID | None
    retest_scan_id: uuid.UUID | None
    baseline_run_id: uuid.UUID | None
    retest_run_id: uuid.UUID | None
    status: str
    summary: dict[str, Any]
    gate_status: str | None
    created_at: datetime


class RetestResultOut(BaseModel):
    finding_id: uuid.UUID
    public_id: str
    title: str
    vuln_class: str
    result: str
    match_method: str
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    notes: str | None


class RetestDetailOut(RetestOut):
    results: list[RetestResultOut]
