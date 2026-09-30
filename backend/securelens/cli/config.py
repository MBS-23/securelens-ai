"""``.securelens.yml`` — the CLI and CI configuration file.

The file is validated strictly: an unknown key or a bad value is an error with
a clear message, never silently ignored (a typo in ``fail_on`` must not turn a
blocking gate into a passing one).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from securelens.enums import Confidence, Severity
from securelens.findings.gate import GatePolicy

CONFIG_NAMES = (".securelens.yml", ".securelens.yaml")
MAX_CONFIG_BYTES = 256 * 1024

DEFAULT_CONFIG_TEXT = """\
# SecureLens AI configuration. Every key is optional; these are the defaults.
version: 1

scan:
  scanners: [sast, secrets, dependencies]
  exclude: []            # extra glob patterns, e.g. ["tests/fixtures/**", "docs/**"]
  external: auto         # auto = also run Bandit / Semgrep / Gitleaks when installed; off = never
  max_file_kb: 1024      # larger files are listed but not analysed

dependencies:
  source: osv            # osv = query api.osv.dev | offline = local OSV advisories | none
  offline_db: null       # directory of OSV JSON advisories, used when source is offline

gate:                    # decides the exit code in CI
  fail_on: [CRITICAL, HIGH]
  min_confidence: MEDIUM
  include_ai_suggested: false
  fail_on_regression: true
  max_findings: null

report:
  formats: [json, sarif, html]
  directory: .securelens/reports
"""


class ConfigError(Exception):
    pass


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScanSection(_Strict):
    scanners: list[Literal["sast", "secrets", "dependencies"]] = Field(
        default_factory=lambda: ["sast", "secrets", "dependencies"])
    exclude: list[str] = Field(default_factory=list)
    external: Literal["auto", "off"] = "auto"
    max_file_kb: int = Field(1024, ge=1, le=102400)

    @field_validator("external", mode="before")
    @classmethod
    def _yaml_booleans(cls, value: object) -> object:
        # YAML 1.1 reads a bare `off` as False and `on` as True.
        if value is False:
            return "off"
        if value is True:
            return "auto"
        return value


class DependencySection(_Strict):
    source: Literal["osv", "offline", "none"] = "osv"
    offline_db: str | None = None


class GateSection(_Strict):
    fail_on: list[Severity] = Field(default_factory=lambda: [Severity.CRITICAL, Severity.HIGH])
    min_confidence: Confidence = Confidence.MEDIUM
    include_ai_suggested: bool = False
    fail_on_regression: bool = True
    max_findings: int | None = Field(default=None, ge=0)

    @field_validator("fail_on", mode="before")
    @classmethod
    def _upper(cls, value: object) -> object:
        if isinstance(value, list):
            return [str(v).upper() for v in value]
        return value

    @field_validator("min_confidence", mode="before")
    @classmethod
    def _upper_conf(cls, value: object) -> object:
        return str(value).upper() if isinstance(value, str) else value


class ReportSection(_Strict):
    formats: list[Literal["json", "sarif", "html", "markdown"]] = Field(
        default_factory=lambda: ["json", "sarif", "html"])
    directory: str = ".securelens/reports"


class ConfigFile(_Strict):
    version: Literal[1] = 1
    scan: ScanSection = Field(default_factory=ScanSection)
    dependencies: DependencySection = Field(default_factory=DependencySection)
    gate: GateSection = Field(default_factory=GateSection)
    report: ReportSection = Field(default_factory=ReportSection)


@dataclass
class LoadedConfig:
    data: ConfigFile
    path: Path | None

    def gate_policy(self) -> GatePolicy:
        g = self.data.gate
        return GatePolicy(fail_on=[s.value for s in g.fail_on], min_confidence=g.min_confidence.value,
                          include_ai_suggested=g.include_ai_suggested, fail_on_regression=g.fail_on_regression,
                          max_findings=g.max_findings)


def find_config(root: Path) -> Path | None:
    for base in ([root] if root.is_dir() else [root.parent]) + [Path.cwd()]:
        for name in CONFIG_NAMES:
            candidate = base / name
            if candidate.is_file():
                return candidate
    return None


def load(explicit: str | None, root: Path) -> LoadedConfig:
    path = Path(explicit) if explicit else find_config(root)
    if path is None:
        return LoadedConfig(ConfigFile(), None)
    if not path.is_file():
        raise ConfigError(f"configuration file not found: {path}")
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise ConfigError(f"{path} is larger than {MAX_CONFIG_BYTES // 1024} KB")
    try:
        raw = yaml.safe_load(path.read_text("utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML ({exc.__class__.__name__})") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: the top level must be a mapping")
    try:
        return LoadedConfig(ConfigFile.model_validate(raw), path)
    except ValidationError as exc:
        problems = "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:10])
        raise ConfigError(f"{path}: {problems}") from exc
