"""Version comparison per ecosystem, OSV range evaluation and CVSS v3 scoring."""

from __future__ import annotations

import math
import re
from functools import cmp_to_key

from packaging.version import InvalidVersion, Version

from securelens.enums import Severity

_SEMVER = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:[-+.]?(.*))?$")


def _semver_key(version: str) -> tuple:
    m = _SEMVER.match(version.strip())
    if not m:
        return ((0, 0, 0, 0), (1, version))
    nums = tuple(int(x) if x else 0 for x in m.groups()[:4])
    pre = m.group(5) or ""
    pre = pre.split("+", 1)[0]
    if not pre:
        return (nums, (1,))
    parts = []
    for piece in re.split(r"[.-]", pre):
        parts.append((0, int(piece), "") if piece.isdigit() else (1, 0, piece))
    return (nums, (0, tuple(parts)))


def compare(ecosystem: str, a: str, b: str) -> int:
    if a == b:
        return 0
    if ecosystem == "PyPI":
        try:
            va, vb = Version(a), Version(b)
            return (va > vb) - (va < vb)
        except InvalidVersion:
            pass
    ka, kb = _semver_key(a), _semver_key(b)
    return (ka > kb) - (ka < kb)


def is_affected(ecosystem: str, version: str, affected: dict) -> bool:
    """Evaluate one OSV ``affected`` entry for a version."""
    if version in (affected.get("versions") or []):
        return True
    for rng in affected.get("ranges") or []:
        if rng.get("type") not in {"ECOSYSTEM", "SEMVER"}:
            continue
        events = rng.get("events") or []

        def key(event: dict) -> tuple:
            value = next(iter(event.values()))
            return (0,) if value == "0" else (1, cmp_to_key(lambda x, y: compare(ecosystem, x, y))(value))

        try:
            ordered = sorted(events, key=key)
        except TypeError:  # pragma: no cover - malformed data
            ordered = events
        affected_now = False
        for event in ordered:
            if "introduced" in event:
                intro = event["introduced"]
                if intro == "0" or compare(ecosystem, version, intro) >= 0:
                    affected_now = True
            elif "fixed" in event:
                if compare(ecosystem, version, event["fixed"]) >= 0:
                    affected_now = False
            elif "last_affected" in event:
                if compare(ecosystem, version, event["last_affected"]) > 0:
                    affected_now = False
            elif "limit" in event and compare(ecosystem, version, event["limit"]) >= 0:
                affected_now = False
        if affected_now:
            return True
    return False


def describe_ranges(affected: dict) -> tuple[list[str], list[str]]:
    """Human-readable affected ranges and the list of fixed versions."""
    ranges: list[str] = []
    fixed: list[str] = []
    for rng in affected.get("ranges") or []:
        if rng.get("type") not in {"ECOSYSTEM", "SEMVER"}:
            continue
        intro = None
        for event in rng.get("events") or []:
            if "introduced" in event:
                intro = event["introduced"]
            elif "fixed" in event:
                fixed.append(event["fixed"])
                ranges.append(f">={intro or '0'}, <{event['fixed']}")
                intro = None
            elif "last_affected" in event:
                ranges.append(f">={intro or '0'}, <={event['last_affected']}")
                intro = None
        if intro is not None:
            ranges.append(f">={intro}")
    return ranges, fixed


# ------------------------------------------------------------------ CVSS v3

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(value: float) -> float:
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """CVSS v3.0/v3.1 base score from a vector string, per the FIRST specification."""
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
        scope_changed = metrics["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[metrics["PR"]]
        iss = 1 - ((1 - _W["CIA"][metrics["C"]]) * (1 - _W["CIA"][metrics["I"]]) * (1 - _W["CIA"][metrics["A"]]))
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        exploitability = 8.22 * _W["AV"][metrics["AV"]] * _W["AC"][metrics["AC"]] * pr * _W["UI"][metrics["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def severity_from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


LABEL_SEVERITY = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM,
                  "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
