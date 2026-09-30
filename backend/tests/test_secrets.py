"""Secret detection: true positives, false positives, masking, and that raw secrets never leak.

Credential-shaped values are generated at runtime so none are stored in the repository.
"""

from __future__ import annotations

import json
import random
import string
from pathlib import Path

import pytest

from securelens.scanners.base import ScanOptions
from securelens.scanners.engine import run_scan
from securelens.scanners.secrets.detector import scan_text
from securelens.scanners.secrets.masking import mask_secret, redact_text

RNG = random.Random(1337)


def rand(chars: str, n: int) -> str:
    return "".join(RNG.choice(chars) for _ in range(n))


UPPER_DIGITS = string.ascii_uppercase + string.digits
ALNUM = string.ascii_letters + string.digits


def generated_secrets() -> dict[str, str]:
    return {
        "aws-access-key-id": "AKIA" + rand(UPPER_DIGITS.replace("E", ""), 16),
        "github-token": "ghp" + "_" + rand(ALNUM, 36),
        "stripe-live-key": "sk_" + "live_" + rand(ALNUM, 28),
        "google-api-key": "AIza" + rand(ALNUM + "-_", 35),
        "slack-token": "xox" + "b-" + rand(string.digits, 12) + "-" + rand(ALNUM, 24),
        "npm-token": "npm" + "_" + rand(ALNUM, 36),
        "sendgrid-api-key": "SG." + rand(ALNUM, 22) + "." + rand(ALNUM, 43),
        "huggingface-token": "hf" + "_" + rand(ALNUM, 36),
        "anthropic-api-key": "sk-" + "ant-api03-" + rand(ALNUM, 90),
    }


def test_mask_matches_spec_example() -> None:
    assert mask_secret("AKIA123456789EXAMPLE") == "AKIA************MPLE"
    assert mask_secret("short") == "*****"
    assert mask_secret("12345678").startswith("12") and mask_secret("12345678").endswith("78")


@pytest.mark.parametrize("detector", list(generated_secrets()))
def test_provider_patterns_detected(detector: str) -> None:
    value = generated_secrets()[detector]
    matches = scan_text("src/config.py", f'TOKEN = "{value}"\n')
    ids = {m.pattern.id for m in matches}
    assert detector in ids, (detector, ids)
    match = next(m for m in matches if m.pattern.id == detector)
    assert value not in match.masked
    assert match.masked[:4] == value[:4]


def test_private_key_and_connection_string() -> None:
    pem = "-----BEGIN " + "RSA PRIVATE KEY-----\n" + rand(ALNUM, 64) + "\n-----END " + "RSA PRIVATE KEY-----\n"
    assert any(m.pattern.id == "private-key" for m in scan_text("deploy/id_rsa", pem))
    password = rand(ALNUM, 18)
    conn = f'DATABASE_URL = "postgres://app:{password}@db.internal:5432/shop"'
    matches = scan_text("settings.py", conn)
    assert any(m.pattern.id == "connection-string" and m.value == password for m in matches)


def test_generic_high_entropy_credential() -> None:
    value = rand(ALNUM, 12) + "9$" + rand(ALNUM, 12)
    matches = scan_text("app/settings.py", f'api_key = "{value}"')
    assert any(m.pattern.id == "generic-credential" for m in matches)


def test_env_file_credentials() -> None:
    value = rand(ALNUM, 20)
    matches = scan_text(".env.production", f"DB_PASSWORD={value}\nDEBUG=true\n")
    assert any(m.pattern.id == "env-credential" and m.value == value for m in matches)
    # The same line in a normal source file is not an env assignment.
    assert not any(m.pattern.id == "env-credential" for m in scan_text("notes.md", f"DB_PASSWORD={value}"))


@pytest.mark.parametrize("line", [
    'password = "changeme"',
    'password = "password"',
    'api_key = os.environ["API_KEY"]',
    'token = "${TOKEN}"',
    'secret = "<your-secret-here>"',
    'client_secret = "xxxxxxxxxxxxxxxx"',
    'api_key = get_api_key()',
    'password = "aaaaaaaaaaaa"',
])
def test_false_positives_suppressed(line: str) -> None:
    assert not [m for m in scan_text("app.py", line) if m.pattern.generic], line


def test_documentation_example_is_low_confidence() -> None:
    matches = scan_text("config.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
    assert matches and all(m.confidence.value == "LOW" for m in matches)


def test_test_paths_downgrade_confidence() -> None:
    value = generated_secrets()["github-token"]
    prod = scan_text("src/deploy.py", f'T = "{value}"')[0]
    test = scan_text("tests/test_deploy.py", f'T = "{value}"')[0]
    assert prod.confidence.value == "HIGH"
    assert test.confidence.value == "MEDIUM"


def test_redact_text_masks_everything() -> None:
    secrets_ = generated_secrets()
    text = "\n".join(f"{k} = '{v}'" for k, v in secrets_.items())
    redacted = redact_text(text, "x.py")
    for value in secrets_.values():
        assert value not in redacted


def test_scan_output_never_contains_raw_secret(tmp_path: Path) -> None:
    secrets_ = generated_secrets()
    (tmp_path / "config.py").write_text("\n".join(f'{k.upper().replace("-", "_")} = "{v}"' for k, v in secrets_.items()))
    (tmp_path / "app.py").write_text(f'app.secret_key = "{rand(ALNUM, 24)}"\n')
    result = run_scan(tmp_path, ScanOptions(external={}, vulnerability_source="none"))
    blob = json.dumps(result.model_dump(mode="json"))
    for value in secrets_.values():
        assert value not in blob
    assert sum(1 for f in result.findings if f.vuln_class == "hardcoded_secret") >= len(secrets_)
    for f in result.findings:
        if f.source_kind.value == "SECRET":
            data = next(e.data for e in f.evidence if e.kind == "secret")
            assert "*" in data["masked"] and len(data["secret_hash"]) == 32


def test_binary_and_large_files_skipped(tmp_path: Path) -> None:
    value = generated_secrets()["github-token"]
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01" + value.encode() + b"\x00" * 10)
    (tmp_path / "huge.py").write_text(f'T = "{value}"\n' + "#" * (1100 * 1024))
    result = run_scan(tmp_path, ScanOptions(external={}, vulnerability_source="none", max_file_kb=1024))
    statuses = {f.path: f.status for f in result.files}
    assert statuses["blob.bin"] == "SKIPPED_BINARY"
    assert statuses["huge.py"] == "SKIPPED_SIZE"
    assert not result.findings
