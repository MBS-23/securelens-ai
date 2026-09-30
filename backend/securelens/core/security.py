"""Security primitives: password hashing and policy, opaque tokens, CSRF, keyed hashes.

* Passwords: Argon2id (argon2-cffi defaults, rehashed when parameters change).
* Session tokens and API keys: 256-bit random values; only SHA-256 digests are
  stored, so a database leak does not yield usable credentials.
* CSRF: double-submit token bound to the session with an HMAC, verified in
  constant time.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from securelens.core.config import get_settings

_hasher = PasswordHasher()
# Verifying against a real hash when the account does not exist keeps login
# timing uniform, so response time does not reveal which emails are registered.
_DUMMY_HASH = _hasher.hash("securelens-timing-equaliser-not-a-real-password")

PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128

# A compact deny-list of passwords that satisfy the length rule but appear in
# public breach corpora. Length + deny-list follows NIST SP 800-63B; composition
# rules are deliberately not used.
_COMMON_PASSWORDS = frozenset(
    {
        "password1234", "password12345", "password123456", "passwordpassword", "123456789012",
        "1234567890123", "12345678901234", "qwertyuiop12", "qwertyuiop123", "qwertyuiopasdf",
        "iloveyou1234", "administrator", "administrator1", "welcome12345", "letmein12345",
        "changeme1234", "changemenow1", "trustno1trustno1", "football1234", "baseball1234",
        "superman1234", "princess1234", "sunshine1234", "whatever1234", "starwars1234",
        "monkey123456", "dragon123456", "master123456", "abc123456789", "abcdefghijkl",
        "aaaaaaaaaaaa", "111111111111", "000000000000", "qazwsxedcrfv", "1q2w3e4r5t6y",
        "zaq12wsxcde3", "passw0rd1234", "p@ssw0rd1234", "p@ssword1234", "securelens123",
        "securelensai1", "correcthorsebatterystaple",
    }
)


class PasswordPolicyError(ValueError):
    pass


def validate_password(password: str, *, email: str | None = None) -> None:
    if len(password) < PASSWORD_MIN_LENGTH:
        raise PasswordPolicyError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters long")
    if len(password) > PASSWORD_MAX_LENGTH:
        raise PasswordPolicyError(f"Password must be at most {PASSWORD_MAX_LENGTH} characters long")
    lowered = password.lower()
    if lowered in _COMMON_PASSWORDS:
        raise PasswordPolicyError("Password appears in lists of commonly used passwords")
    if len(set(password)) < 5:
        raise PasswordPolicyError("Password is too repetitive")
    if email:
        local = email.split("@", 1)[0].lower()
        if len(local) >= 4 and local in lowered:
            raise PasswordPolicyError("Password must not contain your email name")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def sha256_hex(value: str | bytes) -> str:
    data = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def keyed_hash(value: str, purpose: str) -> str:
    """HMAC-SHA256 keyed with the application secret, domain-separated by purpose."""
    key = get_settings().secret_key.get_secret_value().encode()
    return hmac.new(key, f"{purpose}:{value}".encode(), hashlib.sha256).hexdigest()


def csrf_token_for(session_token_hash: str) -> str:
    raw = hmac.new(
        get_settings().secret_key.get_secret_value().encode(),
        f"csrf:{session_token_hash}".encode(),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


API_KEY_PREFIX = "slk_"
_API_KEY_RE = re.compile(r"^slk_[A-Za-z0-9_-]{8}_[A-Za-z0-9_-]{32,}$")


def generate_api_key() -> tuple[str, str, str]:
    """Return (full_key, display_prefix, sha256). The full key is shown once."""
    ident = secrets.token_urlsafe(6)[:8].replace("-", "x").replace("_", "y")
    full = f"{API_KEY_PREFIX}{ident}_{secrets.token_urlsafe(32)}"
    return full, f"{API_KEY_PREFIX}{ident}", sha256_hex(full)


def looks_like_api_key(value: str) -> bool:
    return bool(_API_KEY_RE.match(value))
