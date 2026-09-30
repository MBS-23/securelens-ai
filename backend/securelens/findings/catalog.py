"""Access to the vulnerability catalog (``catalog.yml``)."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources

import yaml

from securelens.enums import Engine, Severity


@dataclass(frozen=True)
class VulnClass:
    key: str
    name: str
    engine: Engine
    cwe: tuple[str, ...]
    owasp: tuple[str, ...]
    severity: Severity
    description: str
    impact: str
    recommendation: str
    remediation: str
    examples: dict[str, dict[str, str]] = field(default_factory=dict)
    references: tuple[str, ...] = ()

    @property
    def category(self) -> str:
        return "AI Security" if self.engine == Engine.AISEC else "Application Security"

    def secure_pattern(self, language: str | None) -> str:
        lang = {"typescript": "javascript", "tsx": "javascript"}.get(language or "", language or "")
        example = self.examples.get(lang) or next(iter(self.examples.values()), None)
        if not example:
            return self.remediation
        return (f"{self.remediation}\n\nVulnerable:\n    {example.get('vulnerable', '')}\n\n"
                f"Secure:\n    {example.get('secure', '')}")


@lru_cache(maxsize=1)
def catalog() -> dict[str, VulnClass]:
    raw = yaml.safe_load(resources.files("securelens.findings").joinpath("catalog.yml").read_text("utf-8"))
    out: dict[str, VulnClass] = {}
    for key, entry in raw.items():
        out[key] = VulnClass(
            key=key,
            name=entry["name"],
            engine=Engine(entry.get("engine", "APPSEC")),
            cwe=tuple(entry.get("cwe", [])),
            owasp=tuple(entry.get("owasp", [])),
            severity=Severity(entry.get("severity", "MEDIUM")),
            description=" ".join(entry.get("description", "").split()),
            impact=" ".join(entry.get("impact", "").split()),
            recommendation=" ".join(entry.get("recommendation", "").split()),
            remediation=entry.get("remediation", ""),
            examples=entry.get("examples", {}) or {},
            references=tuple(entry.get("references", [])),
        )
    return out


def get(key: str) -> VulnClass:
    entries = catalog()
    if key not in entries:
        raise KeyError(f"unknown vulnerability class: {key}")
    return entries[key]


def known(key: str) -> bool:
    return key in catalog()
