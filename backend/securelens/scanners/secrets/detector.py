"""Line-oriented secret detection with false-positive reduction."""

from __future__ import annotations

import re
from dataclasses import dataclass

from securelens.enums import Confidence, Severity
from securelens.scanners.secrets.masking import mask_secret, shannon_entropy
from securelens.scanners.secrets.patterns import ENV_FILE_RE, PATTERNS, TEST_PATH_RE, SecretPattern

MAX_LINE_LENGTH = 4000

_PLACEHOLDER_HINTS = (
    "example", "sample", "dummy", "placeholder", "changeme", "change_me", "change-me", "your_", "your-", "yourkey",
    "xxxx", "****", "redacted", "todo", "fixme", "insert", "replace", "<", ">", "${", "{{", "}}", "%s", "%(", "…",
    "fake", "notreal", "not_real", "not-a-real", "lorem", "abcdef", "123456", "000000", "test_key", "testkey",
)
_ENV_REFERENCE = re.compile(r"^\$\{?[A-Z_][A-Z0-9_]*\}?$|^%[A-Z_][A-Z0-9_]*%$|^process\.env|^os\.environ|^getenv")
_CODE_LIKE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$|\(\)$|^[A-Za-z_]+\(")
_CONFIDENCE_DOWN = {Confidence.CONFIRMED: Confidence.HIGH, Confidence.HIGH: Confidence.MEDIUM,
                    Confidence.MEDIUM: Confidence.LOW, Confidence.LOW: Confidence.LOW}


@dataclass
class SecretMatch:
    pattern: SecretPattern
    value: str
    line: int
    col: int
    masked: str
    entropy: float
    severity: Severity
    confidence: Confidence
    notes: list[str]


def _looks_placeholder(value: str) -> bool:
    lowered = value.lower()
    if any(h in lowered for h in _PLACEHOLDER_HINTS):
        return True
    if len(set(value)) <= 3:
        return True
    if _ENV_REFERENCE.match(value) or _CODE_LIKE.search(value):
        return True
    return lowered in {"password", "secret", "changeit", "none", "null", "true", "false", "undefined", "admin"}


def scan_text(path: str, text: str) -> list[SecretMatch]:
    is_env = bool(ENV_FILE_RE.search(path))
    is_test = bool(TEST_PATH_RE.search(path))
    found: list[SecretMatch] = []
    seen: set[tuple[int, str]] = set()
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > MAX_LINE_LENGTH:
            line = line[:MAX_LINE_LENGTH]
        stripped = line.strip()
        if not stripped:
            continue
        for pattern in PATTERNS:
            if pattern.env_file_only and not is_env:
                continue
            if not any(k in line for k in pattern.keywords):
                continue
            for match in pattern.regex.finditer(line):
                value = match.group(pattern.group)
                if not value or (lineno, value) in seen:
                    continue
                notes: list[str] = []
                confidence = pattern.confidence
                severity = pattern.severity
                entropy = shannon_entropy(value)
                if pattern.min_entropy and entropy < pattern.min_entropy:
                    continue
                if pattern.id == "private-key":
                    if "PUBLIC" in line:
                        continue
                elif pattern.generic:
                    if _looks_placeholder(value):
                        continue
                    if not any(c.isdigit() for c in value) and not any(not c.isalnum() for c in value):
                        # A single dictionary-like word is rarely a real secret.
                        confidence = Confidence.LOW
                elif "EXAMPLE" in value.upper() or _looks_placeholder(value):
                    confidence = Confidence.LOW
                    notes.append("matches the provider's documented example or a placeholder")
                if pattern.id == "connection-string" and _looks_placeholder(value):
                    continue
                if is_test:
                    confidence = _CONFIDENCE_DOWN[confidence]
                    notes.append("located in a test, fixture or example path")
                seen.add((lineno, value))
                found.append(SecretMatch(pattern=pattern, value=value, line=lineno, col=match.start(pattern.group) + 1,
                                         masked=mask_secret(value), entropy=round(entropy, 2), severity=severity,
                                         confidence=confidence, notes=notes))
    return _dedupe_overlaps(found)


def _dedupe_overlaps(matches: list[SecretMatch]) -> list[SecretMatch]:
    """A specific provider match wins over a generic match on the same value."""
    by_value: dict[tuple[int, str], SecretMatch] = {}
    for m in matches:
        key = (m.line, m.value)
        current = by_value.get(key)
        if current is None or (current.pattern.generic and not m.pattern.generic):
            by_value[key] = m
    # Generic matches whose value contains a provider match on the same line are redundant.
    specific = [m for m in by_value.values() if not m.pattern.generic]
    out = []
    for m in by_value.values():
        if m.pattern.generic and any(s.line == m.line and s.value in m.value for s in specific):
            continue
        out.append(m)
    return sorted(out, key=lambda m: (m.line, m.col))
