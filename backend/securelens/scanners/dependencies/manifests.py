"""Dependency manifest and lockfile parsers (Python, Node.js, PHP).

Lockfiles give exact resolved versions (including transitive packages);
manifests give declared ranges. When both exist in a directory the lockfile
versions are used and the manifest decides which packages are direct.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field

import yaml

from securelens.findings.model import DependencyRecord

_PEP508 = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*?)\s*(;.*)?$")
_EXACT = re.compile(r"^={2,3}\s*([A-Za-z0-9.+!_-]+)$")
_NPM_EXACT = re.compile(r"^v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$")
_DEV_GROUPS = {"dev", "test", "tests", "testing", "lint", "docs", "doc", "typing", "develop"}


@dataclass
class ParsedManifest:
    path: str
    ecosystem: str
    kind: str  # manifest | lockfile
    records: list[DependencyRecord] = field(default_factory=list)
    direct_names: set[str] = field(default_factory=set)


def _norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _pep508(spec: str, path: str, dev: bool = False) -> DependencyRecord | None:
    spec = spec.strip()
    if not spec or spec.startswith(("#", "-", "git+", "http://", "https://", "file:")) or "://" in spec:
        return None
    m = _PEP508.match(spec)
    if not m:
        return None
    name, _extras, constraint, _marker = m.groups()
    constraint = (constraint or "").strip().strip("()")
    exact = _EXACT.match(constraint)
    return DependencyRecord(ecosystem="PyPI", name=_norm_py(name), version=exact.group(1) if exact else None,
                            version_spec=constraint or None, manifest_path=path, direct=True, dev=dev)


def parse_requirements(path: str, text: str) -> ParsedManifest:
    out = ParsedManifest(path=path, ecosystem="PyPI", kind="manifest")
    dev = bool(re.search(r"(dev|test|lint|docs)", path.rsplit("/", 1)[-1], re.I))
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        rec = _pep508(line, path, dev)
        if rec:
            out.records.append(rec)
            out.direct_names.add(rec.name)
    return out


def parse_pyproject(path: str, text: str) -> ParsedManifest:
    out = ParsedManifest(path=path, ecosystem="PyPI", kind="manifest")
    data = tomllib.loads(text)
    project = data.get("project", {})
    for spec in project.get("dependencies", []) or []:
        if (rec := _pep508(spec, path)) is not None:
            out.records.append(rec)
    for group, specs in (project.get("optional-dependencies", {}) or {}).items():
        for spec in specs or []:
            if (rec := _pep508(spec, path, dev=group.lower() in _DEV_GROUPS)) is not None:
                out.records.append(rec)
    for specs in (data.get("dependency-groups", {}) or {}).values():
        for spec in specs or []:
            if isinstance(spec, str) and (rec := _pep508(spec, path, dev=True)) is not None:
                out.records.append(rec)
    poetry = data.get("tool", {}).get("poetry", {})
    sections: list[tuple[dict, bool]] = [(poetry.get("dependencies", {}) or {}, False),
                                         (poetry.get("dev-dependencies", {}) or {}, True)]
    for group, body in (poetry.get("group", {}) or {}).items():
        sections.append(((body or {}).get("dependencies", {}) or {}, group.lower() in _DEV_GROUPS or group != "main"))
    for deps, dev in sections:
        for name, spec in deps.items():
            if name.lower() == "python":
                continue
            constraint = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else None)
            version = None
            if constraint and re.fullmatch(r"=?=?\s*\d[\w.+!-]*", constraint.strip()):
                version = constraint.strip().lstrip("=").strip()
            out.records.append(DependencyRecord(ecosystem="PyPI", name=_norm_py(name), version=version,
                                                version_spec=constraint, manifest_path=path, direct=True, dev=dev))
    out.direct_names = {r.name for r in out.records}
    return out


def parse_pipfile_lock(path: str, text: str) -> ParsedManifest:
    out = ParsedManifest(path=path, ecosystem="PyPI", kind="lockfile")
    data = json.loads(text)
    for section, dev in (("default", False), ("develop", True)):
        for name, info in (data.get(section) or {}).items():
            version = str((info or {}).get("version", "")).lstrip("=") or None
            out.records.append(DependencyRecord(ecosystem="PyPI", name=_norm_py(name), version=version,
                                                manifest_path=path, direct=False, dev=dev))
    return out


def parse_poetry_lock(path: str, text: str) -> ParsedManifest:
    out = ParsedManifest(path=path, ecosystem="PyPI", kind="lockfile")
    data = tomllib.loads(text)
    for pkg in data.get("package", []) or []:
        out.records.append(DependencyRecord(ecosystem="PyPI", name=_norm_py(pkg.get("name", "")),
                                            version=pkg.get("version"), manifest_path=path, direct=False,
                                            dev=pkg.get("category") == "dev"))
    return out


def parse_uv_lock(path: str, text: str) -> ParsedManifest:
    out = ParsedManifest(path=path, ecosystem="PyPI", kind="lockfile")
    data = tomllib.loads(text)
    for pkg in data.get("package", []) or []:
        if (pkg.get("source") or {}).get("editable") or (pkg.get("source") or {}).get("virtual"):
            continue
        out.records.append(DependencyRecord(ecosystem="PyPI", name=_norm_py(pkg.get("name", "")),
                                            version=pkg.get("version"), manifest_path=path, direct=False))
    return out


def parse_package_json(path: str, text: str) -> ParsedManifest:
    out = ParsedManifest(path=path, ecosystem="npm", kind="manifest")
    data = json.loads(text)
    for section, dev in (("dependencies", False), ("devDependencies", True), ("optionalDependencies", False),
                         ("peerDependencies", False)):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec)
            exact = _NPM_EXACT.match(spec.strip())
            out.records.append(DependencyRecord(ecosystem="npm", name=name, version=exact.group(1) if exact else None,
                                                version_spec=spec, manifest_path=path, direct=True, dev=dev))
    out.direct_names = {r.name for r in out.records}
    return out


def parse_package_lock(path: str, text: str) -> ParsedManifest:
    out = ParsedManifest(path=path, ecosystem="npm", kind="lockfile")
    data = json.loads(text)
    packages = data.get("packages")
    if isinstance(packages, dict) and packages:
        root = packages.get("", {})
        direct = set((root.get("dependencies") or {}).keys()) | set((root.get("devDependencies") or {}).keys())
        for key, info in packages.items():
            if not key or (not key.startswith("node_modules/") and "/node_modules/" not in key):
                continue
            name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
            if info.get("link"):
                continue
            out.records.append(DependencyRecord(ecosystem="npm", name=name, version=info.get("version"),
                                                manifest_path=path,
                                                direct=name in direct and key.count("node_modules/") == 1,
                                                dev=bool(info.get("dev"))))
        out.direct_names = direct
        return out

    def walk(deps: dict, depth: int) -> None:
        for name, info in (deps or {}).items():
            out.records.append(DependencyRecord(ecosystem="npm", name=name, version=(info or {}).get("version"),
                                                manifest_path=path, direct=depth == 0,
                                                dev=bool((info or {}).get("dev"))))
            walk((info or {}).get("dependencies") or {}, depth + 1)

    walk(data.get("dependencies") or {}, 0)
    return out


_YARN_HEADER = re.compile(r'^"?((?:@[^@/"\s]+/)?[^@"\s]+)@[^,"\s]+')


def parse_yarn_lock(path: str, text: str) -> ParsedManifest:
    out = ParsedManifest(path=path, ecosystem="npm", kind="lockfile")
    current: str | None = None
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if not line.startswith(" "):
            m = _YARN_HEADER.match(line.strip())
            current = m.group(1) if m else None
        elif current and line.strip().startswith("version"):
            version = line.strip().split(None, 1)[1].strip().strip('"').strip(":").strip()
            out.records.append(DependencyRecord(ecosystem="npm", name=current, version=version, manifest_path=path,
                                                direct=False))
            current = None
    return out


def parse_pnpm_lock(path: str, text: str) -> ParsedManifest:
    out = ParsedManifest(path=path, ecosystem="npm", kind="lockfile")
    data = yaml.safe_load(text) or {}
    for key in (data.get("packages") or {}):
        spec = str(key).lstrip("/")
        spec = spec.split("(", 1)[0]
        if "@" not in spec[1:]:
            continue
        name, _, version = spec.rpartition("@")
        out.records.append(DependencyRecord(ecosystem="npm", name=name, version=version, manifest_path=path,
                                            direct=False))
    return out


def parse_composer_json(path: str, text: str) -> ParsedManifest:
    out = ParsedManifest(path=path, ecosystem="Packagist", kind="manifest")
    data = json.loads(text)
    for section, dev in (("require", False), ("require-dev", True)):
        for name, spec in (data.get(section) or {}).items():
            if name == "php" or name.startswith(("ext-", "lib-")) or "/" not in name:
                continue
            spec = str(spec)
            exact = re.fullmatch(r"v?(\d+\.\d+(?:\.\d+)*)", spec.strip())
            out.records.append(DependencyRecord(ecosystem="Packagist", name=name.lower(),
                                                version=exact.group(1) if exact else None, version_spec=spec,
                                                manifest_path=path, direct=True, dev=dev))
    out.direct_names = {r.name for r in out.records}
    return out


def parse_composer_lock(path: str, text: str) -> ParsedManifest:
    out = ParsedManifest(path=path, ecosystem="Packagist", kind="lockfile")
    data = json.loads(text)
    for section, dev in (("packages", False), ("packages-dev", True)):
        for pkg in data.get(section) or []:
            version = str(pkg.get("version", "")).lstrip("v") or None
            out.records.append(DependencyRecord(ecosystem="Packagist", name=str(pkg.get("name", "")).lower(),
                                                version=version, manifest_path=path, direct=False, dev=dev))
    return out


PARSERS: list[tuple[re.Pattern[str], Callable[[str, str], ParsedManifest]]] = [
    (re.compile(r"(^|/)requirements[^/]*\.(txt|in)$"), parse_requirements),
    (re.compile(r"(^|/)pyproject\.toml$"), parse_pyproject),
    (re.compile(r"(^|/)Pipfile\.lock$"), parse_pipfile_lock),
    (re.compile(r"(^|/)poetry\.lock$"), parse_poetry_lock),
    (re.compile(r"(^|/)uv\.lock$"), parse_uv_lock),
    (re.compile(r"(^|/)package\.json$"), parse_package_json),
    (re.compile(r"(^|/)(package-lock|npm-shrinkwrap)\.json$"), parse_package_lock),
    (re.compile(r"(^|/)yarn\.lock$"), parse_yarn_lock),
    (re.compile(r"(^|/)pnpm-lock\.yaml$"), parse_pnpm_lock),
    (re.compile(r"(^|/)composer\.json$"), parse_composer_json),
    (re.compile(r"(^|/)composer\.lock$"), parse_composer_lock),
]


def parser_for(path: str) -> Callable[[str, str], ParsedManifest] | None:
    for pattern, parser in PARSERS:
        if pattern.search(path):
            return parser
    return None


def merge(manifests: list[ParsedManifest]) -> list[DependencyRecord]:
    """Combine manifests: lockfile versions win; manifests mark direct dependencies."""
    by_dir: dict[tuple[str, str], list[ParsedManifest]] = {}
    for m in manifests:
        directory = m.path.rsplit("/", 1)[0] if "/" in m.path else ""
        by_dir.setdefault((directory, m.ecosystem), []).append(m)
    records: list[DependencyRecord] = []
    for group in by_dir.values():
        locks = [m for m in group if m.kind == "lockfile"]
        manifests_ = [m for m in group if m.kind == "manifest"]
        direct = set().union(*(m.direct_names for m in manifests_)) if manifests_ else set()
        if locks:
            seen: set[tuple[str, str | None]] = set()
            for lock in locks:
                for rec in lock.records:
                    key = (rec.name, rec.version)
                    if key in seen or not rec.name:
                        continue
                    seen.add(key)
                    if direct:
                        rec.direct = rec.direct or rec.name in direct
                    records.append(rec)
        else:
            for m in manifests_:
                records.extend(r for r in m.records if r.name)
    return records
