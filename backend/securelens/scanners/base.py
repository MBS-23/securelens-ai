"""Scanner plugin interface and scan options.

A scanner is anything with a ``name``, an ``available()`` check and a
``scan(context)`` method returning standardized findings. Built-in scanners
and adapters for third-party tools implement the same protocol, so new
analyzers plug in without touching the engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from securelens.findings.model import DependencyRecord, Finding, ScannerRun

DEFAULT_EXCLUDES = [
    ".git/", ".hg/", ".svn/", "node_modules/", "bower_components/", "vendor/", ".venv/", "venv/", "env/",
    "__pycache__/", ".mypy_cache/", ".pytest_cache/", ".ruff_cache/", ".tox/", "dist/", "build/", ".next/",
    ".nuxt/", "coverage/", "target/", "site-packages/", ".idea/", ".vscode/", ".securelens/", "*.min.js",
    "*.min.css", "*.map", "*.bundle.js",
]


@dataclass
class ScanOptions:
    scanners: set[str] = field(default_factory=lambda: {"sast", "secrets", "dependencies"})
    external: dict[str, str] = field(default_factory=lambda: {"bandit": "auto", "semgrep": "auto", "gitleaks": "auto"})
    exclude: list[str] = field(default_factory=list)
    use_default_excludes: bool = True
    max_file_kb: int = 1024
    max_files: int = 20000
    vulnerability_source: str = "osv"  # osv | offline | none
    offline_db: Path | None = None
    osv_url: str = "https://api.osv.dev"
    osv_timeout_seconds: float = 20.0
    time_budget_seconds: float = 600.0
    # Keyed hash for secret fingerprints; the secret value is never stored.
    secret_hash_key: bytes = b"securelens-default-secret-hash-key"
    semgrep_config: str | None = None

    def excludes(self) -> list[str]:
        return (DEFAULT_EXCLUDES if self.use_default_excludes else []) + list(self.exclude)


@dataclass
class SourceFile:
    path: str  # repository-relative, POSIX separators
    abs_path: Path
    language: str | None
    size: int
    sha256: str
    line_count: int
    text: str | None = None

    def read(self) -> str:
        if self.text is None:
            self.text = self.abs_path.read_bytes().decode("utf-8", errors="replace")
        return self.text


@dataclass
class ScanContext:
    root: Path
    files: list[SourceFile]
    options: ScanOptions

    def by_language(self, *languages: str) -> list[SourceFile]:
        wanted = set(languages)
        return [f for f in self.files if f.language in wanted]


@dataclass
class ScannerResult:
    run: ScannerRun
    findings: list[Finding] = field(default_factory=list)
    dependencies: list[DependencyRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    parse_errors: dict[str, str] = field(default_factory=dict)


@runtime_checkable
class Scanner(Protocol):
    name: str

    def available(self) -> tuple[bool, str | None]: ...

    def scan(self, ctx: ScanContext) -> ScannerResult: ...
