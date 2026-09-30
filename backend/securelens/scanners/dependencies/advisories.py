"""Vulnerability intelligence for dependencies.

Two sources implement the same interface:

* ``OSVSource`` — the public OSV.dev API (aggregates GitHub Security Advisories,
  PyPA, npm and more);
* ``OfflineSource`` — a directory of OSV-format JSON records, for air-gapped
  environments and reproducible CI.

Nothing is invented: a dependency without an exact version, or looked up while
no source is reachable, is reported as NOT_VERIFIED.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import httpx

from securelens.enums import Severity
from securelens.findings.model import DependencyRecord
from securelens.scanners.dependencies.versions import (
    LABEL_SEVERITY,
    cvss3_base_score,
    describe_ranges,
    is_affected,
    severity_from_score,
)

log = logging.getLogger(__name__)
MAX_ADVISORY_DETAIL_FETCHES = 500


@dataclass
class Advisory:
    id: str
    aliases: list[str]
    summary: str
    details: str
    severity: Severity
    severity_source: str
    cvss_vector: str | None
    cvss_score: float | None
    affected_ranges: list[str]
    fixed_versions: list[str]
    references: list[str]
    published: str | None
    modified: str | None
    source: str


@dataclass
class LookupResult:
    source: str
    advisories: dict[int, list[Advisory]] = field(default_factory=dict)  # index into the deps list
    verified: set[int] = field(default_factory=set)
    error: str | None = None


class VulnerabilitySource(Protocol):
    name: str

    def lookup(self, deps: list[DependencyRecord]) -> LookupResult: ...


def advisory_from_osv(record: dict, dep: DependencyRecord, source: str) -> Advisory | None:
    affected_entries = [a for a in record.get("affected") or []
                        if (a.get("package") or {}).get("ecosystem") == dep.ecosystem
                        and _same_name(dep.ecosystem, (a.get("package") or {}).get("name", ""), dep.name)]
    if not affected_entries:
        return None
    ranges: list[str] = []
    fixed: list[str] = []
    for entry in affected_entries:
        r, f = describe_ranges(entry)
        ranges.extend(r)
        fixed.extend(f)
    severity, severity_source, vector, score = _severity(record, affected_entries)
    return Advisory(
        id=record.get("id", "UNKNOWN"),
        aliases=list(record.get("aliases") or []),
        summary=(record.get("summary") or record.get("details") or "").strip().split("\n", 1)[0][:300],
        details=(record.get("details") or "")[:4000],
        severity=severity,
        severity_source=severity_source,
        cvss_vector=vector,
        cvss_score=score,
        affected_ranges=list(dict.fromkeys(ranges)),
        fixed_versions=list(dict.fromkeys(fixed)),
        references=[r.get("url") for r in (record.get("references") or []) if r.get("url")][:10],
        published=record.get("published"),
        modified=record.get("modified"),
        source=source,
    )


def _same_name(ecosystem: str, a: str, b: str) -> bool:
    if ecosystem == "PyPI":
        import re

        norm = lambda s: re.sub(r"[-_.]+", "-", s).lower()  # noqa: E731
        return norm(a) == norm(b)
    return a.lower() == b.lower()


def _severity(record: dict, affected: list[dict]) -> tuple[Severity, str, str | None, float | None]:
    for entry in record.get("severity") or []:
        vector = entry.get("score", "")
        score = cvss3_base_score(vector) if entry.get("type") in {"CVSS_V3", "CVSS_V31"} else None
        if score is not None:
            return severity_from_score(score), "CVSS v3 base score", vector, score
    labels = [str((record.get("database_specific") or {}).get("severity", ""))]
    labels += [str((a.get("database_specific") or {}).get("severity", "")) for a in affected]
    labels += [str((a.get("ecosystem_specific") or {}).get("severity", "")) for a in affected]
    for label in labels:
        if label.upper() in LABEL_SEVERITY:
            return LABEL_SEVERITY[label.upper()], "advisory severity label", None, None
    return Severity.MEDIUM, "not provided by the source (defaulted to MEDIUM)", None, None


class OSVSource:
    name = "OSV.dev"

    def __init__(self, base_url: str = "https://api.osv.dev", timeout: float = 20.0,
                 client: httpx.Client | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = client

    def lookup(self, deps: list[DependencyRecord]) -> LookupResult:
        result = LookupResult(source=self.name)
        queryable = [(i, d) for i, d in enumerate(deps) if d.version]
        if not queryable:
            return result
        client = self._client or httpx.Client(timeout=self.timeout, follow_redirects=False)
        try:
            ids_by_index: dict[int, list[str]] = {}
            for start in range(0, len(queryable), 500):
                chunk = queryable[start:start + 500]
                body = {"queries": [{"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
                                    for _, d in chunk]}
                response = client.post(f"{self.base_url}/v1/querybatch", json=body)
                response.raise_for_status()
                for (index, _dep), item in zip(chunk, response.json().get("results", []), strict=False):
                    result.verified.add(index)
                    ids = [v.get("id") for v in (item or {}).get("vulns") or [] if v.get("id")]
                    if ids:
                        ids_by_index[index] = ids
            details: dict[str, dict] = {}
            for ids in ids_by_index.values():
                for vid in ids:
                    if vid in details or len(details) >= MAX_ADVISORY_DETAIL_FETCHES:
                        continue
                    response = client.get(f"{self.base_url}/v1/vulns/{vid}")
                    response.raise_for_status()
                    details[vid] = response.json()
            for index, ids in ids_by_index.items():
                advisories = []
                for vid in ids:
                    record = details.get(vid)
                    if record is None:
                        continue
                    adv = advisory_from_osv(record, deps[index], self.name)
                    if adv is not None:
                        advisories.append(adv)
                if advisories:
                    result.advisories[index] = advisories
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("OSV lookup failed: %s", exc)
            result.error = f"OSV.dev lookup failed ({type(exc).__name__}); affected dependencies are NOT VERIFIED"
            result.verified = set()
            result.advisories = {}
        finally:
            if self._client is None:
                client.close()
        return result


class OfflineSource:
    """Reads OSV-format JSON files (one advisory per file, or a JSON list)."""

    name = "offline advisory database"

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self._index: dict[tuple[str, str], list[dict]] | None = None

    def _load(self) -> dict[tuple[str, str], list[dict]]:
        if self._index is not None:
            return self._index
        index: dict[tuple[str, str], list[dict]] = {}
        for path in sorted(self.directory.rglob("*.json")):
            try:
                data = json.loads(path.read_text("utf-8"))
            except (OSError, ValueError):
                continue
            for record in data if isinstance(data, list) else [data]:
                for affected in record.get("affected") or []:
                    pkg = affected.get("package") or {}
                    key = (pkg.get("ecosystem", ""), pkg.get("name", "").lower())
                    index.setdefault(key, []).append(record)
        self._index = index
        return index

    def lookup(self, deps: list[DependencyRecord]) -> LookupResult:
        result = LookupResult(source=self.name)
        if not self.directory.is_dir():
            result.error = f"offline advisory database not found at {self.directory}"
            return result
        index = self._load()
        for i, dep in enumerate(deps):
            if not dep.version:
                continue
            result.verified.add(i)
            name = dep.name.lower()
            candidates = index.get((dep.ecosystem, name), [])
            if dep.ecosystem == "PyPI":
                import re

                alt = re.sub(r"[-_.]+", "-", name)
                candidates = candidates or index.get((dep.ecosystem, alt), [])
            advisories = []
            seen: set[str] = set()
            for record in candidates:
                if record.get("id") in seen or record.get("withdrawn"):
                    continue
                entries = [a for a in record.get("affected") or []
                           if (a.get("package") or {}).get("ecosystem") == dep.ecosystem
                           and _same_name(dep.ecosystem, (a.get("package") or {}).get("name", ""), dep.name)]
                if any(is_affected(dep.ecosystem, dep.version, e) for e in entries):
                    adv = advisory_from_osv(record, dep, self.name)
                    if adv is not None:
                        advisories.append(adv)
                        seen.add(adv.id)
            if advisories:
                result.advisories[i] = advisories
        return result
