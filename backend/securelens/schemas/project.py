from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from securelens.enums import BusinessCriticality, Confidence, Exposure, Severity
from securelens.schemas.common import APIModel, ORMModel


class GatePolicy(APIModel):
    """Security-gate policy. Informational findings never fail a gate unless listed."""

    fail_on: list[Severity] = Field(default_factory=lambda: [Severity.CRITICAL, Severity.HIGH])
    min_confidence: Confidence = Confidence.MEDIUM
    include_ai_suggested: bool = False
    fail_on_regression: bool = True
    max_findings: int | None = Field(default=None, ge=0)

    @field_validator("fail_on")
    @classmethod
    def _dedupe(cls, value: list[Severity]) -> list[Severity]:
        return list(dict.fromkeys(value))


class ProjectCreateIn(APIModel):
    organization_id: uuid.UUID
    name: str = Field(min_length=2, max_length=200)
    description: str = Field(default="", max_length=4000)
    business_criticality: BusinessCriticality | None = None
    exposure: Exposure = Exposure.UNKNOWN
    gate_policy: GatePolicy | None = None


class ProjectUpdateIn(APIModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    business_criticality: BusinessCriticality | None = None
    clear_business_criticality: bool = False
    exposure: Exposure | None = None
    gate_policy: GatePolicy | None = None
    clear_gate_policy: bool = False  # fall back to the organization's default gate


class ProjectOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    slug: str
    description: str
    business_criticality: BusinessCriticality | None
    exposure: Exposure
    gate_policy: dict | None
    created_at: datetime
    updated_at: datetime


class ProjectSummaryOut(ProjectOut):
    open_findings: int = 0
    critical_open: int = 0
    high_open: int = 0
    last_scan_at: datetime | None = None
    last_scan_status: str | None = None
    risk_index: float | None = None


class ProjectMemberIn(APIModel):
    user_id: uuid.UUID


class ProjectMemberOut(BaseModel):
    user_id: uuid.UUID
    email: str
    display_name: str
    added_at: datetime


class RepositoryCreateIn(APIModel):
    name: str = Field(min_length=1, max_length=200)
    source_type: Literal["GIT", "UPLOAD"] = "GIT"
    url: str | None = Field(default=None, max_length=500)
    default_branch: str | None = Field(default=None, max_length=200)


class RepositoryOut(ORMModel):
    id: uuid.UUID
    project_id: uuid.UUID
    name: str
    source_type: str
    url: str | None
    default_branch: str | None
    created_at: datetime
