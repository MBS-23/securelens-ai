"""Stable finding fingerprints.

A fingerprint identifies "the same issue" across scans so that a rescan can
say RESOLVED, STILL_OPEN or REGRESSION. It deliberately excludes line numbers
(which shift when unrelated code changes) and uses the normalised text of the
affected line plus the enclosing function instead.
"""

from __future__ import annotations

import hashlib
import re

from securelens.findings.model import Finding

_WS = re.compile(r"\s+")


def normalise_code(text: str | None) -> str:
    if not text:
        return ""
    return _WS.sub(" ", text.strip())[:500]


def _digest(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8", errors="replace")).hexdigest()


def compute(finding: Finding) -> str:
    kind = finding.source_kind.value
    loc = finding.location
    if kind == "SECRET":
        secret_hash = next((e.data.get("secret_hash", "") for e in finding.evidence if e.kind == "secret"), "")
        return _digest("secret", finding.vuln_class, loc.path if loc else "", secret_hash)
    if kind == "DEPENDENCY":
        dep = next((e.data for e in finding.evidence if e.kind == "dependency"), {})
        return _digest("dependency", dep.get("ecosystem", ""), dep.get("name", "").lower(),
                       dep.get("advisory_id", finding.rule_id))
    if kind == "LLM_TEST":
        scope = finding.correlation.get("target_scope", "")
        return _digest("llm", scope, finding.rule_id)
    return _digest(
        finding.engine.value,
        finding.vuln_class,
        loc.path if loc else "",
        loc.function or "" if loc else "",
        normalise_code(loc.snippet if loc else ""),
    )


def scoped(scope: str, engine_fingerprint: str) -> str:
    """Server-side fingerprint: the engine fingerprint scoped to a repository or AI target."""
    return _digest(scope, engine_fingerprint)
