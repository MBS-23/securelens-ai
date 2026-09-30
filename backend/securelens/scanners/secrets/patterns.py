"""Secret detection patterns.

Provider patterns match documented token formats (high precision). Generic
patterns look for credential-like assignments and require entropy, so a
variable called ``password`` holding ``"password"`` is not reported.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from securelens.enums import Confidence, Severity


@dataclass(frozen=True)
class SecretPattern:
    id: str
    name: str
    regex: re.Pattern[str]
    group: int  # capture group that holds the secret value
    severity: Severity
    confidence: Confidence
    keywords: tuple[str, ...]  # cheap pre-filter; at least one must appear in the line
    min_entropy: float = 0.0
    generic: bool = False
    env_file_only: bool = False


def _p(id_: str, name: str, pattern: str, group: int, severity: Severity, confidence: Confidence,
       keywords: tuple[str, ...], min_entropy: float = 0.0, generic: bool = False, flags: int = 0,
       env_file_only: bool = False) -> SecretPattern:
    return SecretPattern(id_, name, re.compile(pattern, flags), group, severity, confidence, keywords, min_entropy,
                         generic, env_file_only)


H, M, L = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW
CRIT, HIGH, MED, LOW = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW

PATTERNS: list[SecretPattern] = [
    _p("private-key", "Private key", r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)",
       1, CRIT, H, ("PRIVATE KEY",)),
    _p("aws-access-key-id", "AWS access key ID", r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b", 1, HIGH, H,
       ("AKIA", "ASIA", "ABIA", "ACCA")),
    _p("aws-secret-access-key", "AWS secret access key",
       r"(?i)aws.{0,25}(?:secret|private).{0,25}?['\"=:\s]+([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", 1, CRIT, M,
       ("aws", "AWS"), min_entropy=3.5),
    _p("github-token", "GitHub token", r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b", 1, HIGH, H, ("ghp_", "gho_", "ghu_", "ghs_", "ghr_")),
    _p("github-fine-grained-pat", "GitHub fine-grained token", r"\b(github_pat_[A-Za-z0-9_]{22,255})\b", 1, HIGH, H,
       ("github_pat_",)),
    _p("gitlab-pat", "GitLab personal access token", r"\b(glpat-[A-Za-z0-9\-_]{20,})\b", 1, HIGH, H, ("glpat-",)),
    _p("slack-token", "Slack token", r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b", 1, HIGH, H, ("xox",)),
    _p("slack-webhook", "Slack webhook URL",
       r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)", 1, MED, H, ("hooks.slack.com",)),
    _p("stripe-live-key", "Stripe live secret key", r"\b((?:sk|rk)_live_[0-9a-zA-Z]{20,})\b", 1, CRIT, H, ("_live_",)),
    _p("stripe-test-key", "Stripe test secret key", r"\b((?:sk|rk)_test_[0-9a-zA-Z]{20,})\b", 1, LOW, M, ("_test_",)),
    _p("google-api-key", "Google API key", r"\b(AIza[0-9A-Za-z\-_]{35})\b", 1, HIGH, H, ("AIza",)),
    _p("openai-api-key", "OpenAI API key", r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,})\b", 1, HIGH, H, ("sk-",)),
    _p("openai-legacy-key", "OpenAI API key", r"\b(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})\b", 1, HIGH, H, ("T3BlbkFJ",)),
    _p("anthropic-api-key", "Anthropic API key", r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,})\b", 1, HIGH, H,
       ("sk-ant-",)),
    _p("huggingface-token", "Hugging Face token", r"\b(hf_[A-Za-z0-9]{34,})\b", 1, HIGH, H, ("hf_",)),
    _p("sendgrid-api-key", "SendGrid API key", r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b", 1, HIGH, H, ("SG.",)),
    _p("twilio-api-key", "Twilio API key", r"\b(SK[0-9a-fA-F]{32})\b", 1, HIGH, M, ("SK",), min_entropy=3.0),
    _p("mailgun-api-key", "Mailgun API key", r"\b(key-[0-9a-zA-Z]{32})\b", 1, HIGH, M, ("key-",), min_entropy=3.2),
    _p("npm-token", "npm access token", r"\b(npm_[A-Za-z0-9]{36})\b", 1, HIGH, H, ("npm_",)),
    _p("pypi-token", "PyPI API token", r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\b", 1, HIGH, H, ("pypi-",)),
    _p("shopify-token", "Shopify access token", r"\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b", 1, HIGH, H, ("shp",)),
    _p("digitalocean-token", "DigitalOcean token", r"\b(dop_v1_[a-f0-9]{64})\b", 1, HIGH, H, ("dop_v1_",)),
    _p("vault-token", "HashiCorp Vault token", r"\b(hvs\.[A-Za-z0-9_-]{90,})\b", 1, HIGH, H, ("hvs.",)),
    _p("telegram-bot-token", "Telegram bot token", r"\b(\d{8,10}:AA[A-Za-z0-9_-]{33})\b", 1, MED, M, (":AA",)),
    _p("discord-webhook", "Discord webhook URL",
       r"(https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{30,})", 1, MED, H, ("discord",)),
    _p("azure-storage-key", "Azure storage account key", r"(?i)AccountKey=([A-Za-z0-9+/=]{86,88})", 1, CRIT, H,
       ("AccountKey",)),
    _p("jwt", "JSON Web Token", r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b", 1, MED, M,
       ("eyJ",)),
    _p("connection-string", "Database connection string with password",
       r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver)://"
       r"[^\s:/@'\"]+:([^\s@'\"/]{3,})@[^\s'\"]+", 1, HIGH, H, ("://",)),
    _p("generic-credential", "Hardcoded credential",
       r"(?i)\b[A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|"
       r"access[_-]?token|private[_-]?key|client[_-]?secret|signing[_-]?key|encryption[_-]?key)[A-Za-z0-9_.\-]*"
       r"['\"]?\s*(?:=|:|=>|:=)\s*(['\"])([^'\"\s]{8,200})\1", 2, HIGH, M,
       ("pass", "pwd", "secret", "key", "token", "PASS", "SECRET", "KEY", "TOKEN", "Pass", "Secret", "Key", "Token"),
       min_entropy=3.0, generic=True),
    _p("env-credential", "Credential in environment file",
       r"^\s*(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|"
       r"CLIENT_SECRET|CREDENTIALS?)[A-Z0-9_]*\s*=\s*['\"]?([^'\"\s#]{8,200})", 1, HIGH, M,
       ("PASS", "SECRET", "TOKEN", "KEY", "CREDENTIAL"), min_entropy=2.8, generic=True, env_file_only=True),
]

ENV_FILE_RE = re.compile(r"(^|/)(\.env(\.[A-Za-z0-9_-]+)?|[^/]+\.env|\.npmrc|\.pypirc|\.netrc|[^/]+\.(properties|ini|cfg|conf))$")
TEST_PATH_RE = re.compile(r"(^|/)(tests?|spec|specs|__tests__|fixtures?|mocks?|examples?|samples?|docs?)(/|$)|"
                          r"\.(test|spec)\.[a-z]+$|_test\.(py|go)$|test_[^/]*\.py$", re.IGNORECASE)
