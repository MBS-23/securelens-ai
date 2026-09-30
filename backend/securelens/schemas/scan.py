from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from securelens.schemas.common import APIModel, ORMModel

ALLOWED_SCANNERS = {"sast", "secrets", "dependencies"}


class ScanConfigIn(APIModel):
    scanners: list[Literal["sast", "secrets", "dependencies"]] = Field(
        default_factory=lambda: ["sast", "secrets", "dependencies"])
    exclude: list[str] = Field(default_factory=list, max_length=100)
    scope: Literal["FULL", "PARTIAL"] = "FULL"
    external: bool = True

    @field_validator("exclude")
    @classmethod
    def _patterns(cls, value: list[str]) -> list[str]:
        out = []
        for pattern in value:
            pattern = pattern.strip()
            if not pattern or len(pattern) > 200 or "\x00" in pattern or pattern.startswith("/") or ".." in pattern:
                raise ValueError("exclude patterns must be relative globs without '..'")
            out.append(pattern)
        return out


class RepositoryScanIn(APIModel):
    repository_id: uuid.UUID
    branch: str | None = Field(default=None, max_length=200)
    config: ScanConfigIn = Field(default_factory=ScanConfigIn)
    baseline_scan_id: uuid.UUID | None = None


class RescanIn(APIModel):
    config: ScanConfigIn | None = None


class ScanOut(ORMModel):
    id: uuid.UUID
    project_id: uuid.UUID
    repository_id: uuid.UUID | None
    snapshot_id: uuid.UUID | None
    status: str
    trigger: str
    scope: str
    baseline_scan_id: uuid.UUID | None
    config: dict[str, Any]
    progress: dict[str, Any]
    stats: dict[str, Any]
    risk_index: float | None
    gate_status: str | None
    gate_reasons: list[Any]
    error: str | None
    queued_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class ScanListOut(ScanOut):
    repository_name: str | None = None


class ScanFileOut(ORMModel):
    path: str
    language: str | None
    size_bytes: int
    line_count: int
    status: str
    detail: str | None


class FileContentOut(BaseModel):
    path: str
    language: str | None
    content: str
    redacted: bool
    findings: list[dict[str, Any]]


class DependencyOut(ORMModel):
    id: uuid.UUID
    ecosystem: str
    name: str
    version: str | None
    version_spec: str | None
    manifest_path: str
    direct: bool
    dev: bool
    vuln_status: str
    advisory_ids: list[Any]
    source: str | None


class CLIImportIn(BaseModel):
    """A SecureLens CLI JSON report uploaded from CI."""

    repository_name: str = Field(default="ci", min_length=1, max_length=200)
    commit: str | None = Field(default=None, max_length=64)
    branch: str | None = Field(default=None, max_length=200)
    report: dict[str, Any]
