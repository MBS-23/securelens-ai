"""Secret masking and text redaction.

Complete secrets are never displayed, stored or logged. Everything that leaves
the engines — code snippets, evidence, file contents in the code viewer,
context sent to an AI provider — goes through ``redact_text`` first.
"""

from __future__ import annotations

import hashlib
import hmac
import math
from collections import Counter

from securelens.scanners.secrets.patterns import ENV_FILE_RE, PATTERNS


def mask_secret(value: str) -> str:
    """``AKIA123456789EXAMPLE`` -> ``AKIA************MPLE``."""
    if value.startswith("-----BEGIN"):
        return value if value.endswith("-----") else value[:40] + "… [redacted]"
    n = len(value)
    if n >= 12:
        return value[:4] + "*" * min(n - 8, 12) + value[-4:]
    if n >= 8:
        return value[:2] + "*" * (n - 4) + value[-2:]
    return "*" * max(n, 4)


def secret_hash(value: str, key: bytes) -> str:
    """Keyed, truncated digest so the same secret can be recognised again without storing it."""
    return hmac.new(key, value.encode("utf-8", errors="replace"), hashlib.sha256).hexdigest()[:32]


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def redact_text(text: str | None, path: str | None = None, extra_values: list[str] | None = None) -> str | None:
    """Mask anything that matches a secret pattern (plus explicitly known values)."""
    if not text:
        return text
    is_env = bool(path and ENV_FILE_RE.search(path))
    out = text
    replacements: dict[str, str] = {}
    for value in extra_values or []:
        if value and len(value) >= 4:
            replacements[value] = mask_secret(value)
    for pattern in PATTERNS:
        if pattern.env_file_only and not is_env:
            continue
        if not any(k in out for k in pattern.keywords):
            continue
        for match in pattern.regex.finditer(out):
            value = match.group(pattern.group)
            if not value or value in replacements:
                continue
            if pattern.generic and shannon_entropy(value) < pattern.min_entropy:
                continue
            if pattern.id == "private-key":
                continue
            replacements[value] = mask_secret(value)
    for value in sorted(replacements, key=len, reverse=True):
        out = out.replace(value, replacements[value])
    if "PRIVATE KEY-----" in out:
        out = _redact_pem_bodies(out)
    return out


def _redact_pem_bodies(text: str) -> str:
    lines = text.split("\n")
    inside = False
    for i, line in enumerate(lines):
        if "-----BEGIN" in line and "PRIVATE KEY" in line:
            inside = True
            continue
        if "-----END" in line and "PRIVATE KEY" in line:
            inside = False
            continue
        if inside and line.strip():
            lines[i] = "[redacted private key material]"
    return "\n".join(lines)
