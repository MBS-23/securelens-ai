"""Server configuration.

Every setting is read from the environment with the ``SECURELENS_`` prefix.
Secrets (the application key, the AI provider key, integration tokens) are
never stored in the database — they live in the environment or a secret
manager that populates it.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_INSECURE_DEV_KEY = "dev-only-insecure-key-change-me-0123456789abcdef"


CsvList = Annotated[list[str], NoDecode]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SECURELENS_", extra="ignore")

    environment: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite:///./data/securelens.db"
    secret_key: SecretStr = SecretStr(_INSECURE_DEV_KEY)
    storage_dir: Path = Path("./data/storage")

    # --- HTTP / sessions -------------------------------------------------
    cookie_secure: bool = False
    session_ttl_minutes: int = Field(480, ge=5, le=7 * 24 * 60)
    session_idle_minutes: int = Field(60, ge=5, le=24 * 60)
    cors_origins: CsvList = []
    trusted_proxy_hops: int = Field(0, ge=0, le=5)
    bootstrap_token: SecretStr | None = None

    # --- abuse limits ------------------------------------------------------
    rate_limit_per_minute: int = Field(600, ge=10)
    login_rate_limit_per_minute: int = Field(10, ge=1)
    login_max_failures: int = Field(5, ge=1)
    login_lockout_minutes: int = Field(15, ge=1)

    # --- ingestion limits ----------------------------------------------------
    max_upload_mb: int = Field(50, ge=1, le=2048)
    max_extracted_mb: int = Field(250, ge=1, le=8192)
    max_files: int = Field(20000, ge=10)
    max_file_kb: int = Field(1024, ge=1)
    max_compression_ratio: int = Field(200, ge=10)
    git_allowed_hosts: CsvList = ["github.com", "gitlab.com", "bitbucket.org"]
    git_clone_timeout_seconds: int = Field(180, ge=10)

    # --- worker / sandbox ----------------------------------------------------
    scan_timeout_seconds: int = Field(900, ge=10)
    scan_memory_mb: int = Field(2048, ge=256)
    worker_poll_seconds: float = Field(2.0, gt=0)
    job_max_attempts: int = Field(2, ge=1, le=10)

    # --- AI provider ---------------------------------------------------------
    ai_provider: Literal["none", "openai", "anthropic"] = "none"
    ai_model: str | None = None
    ai_base_url: str | None = None
    ai_api_key: SecretStr | None = None
    ai_timeout_seconds: int = Field(60, ge=5, le=600)
    ai_max_output_tokens: int = Field(2000, ge=256, le=16000)

    # --- AI security targets (SSRF policy) ---------------------------------
    ai_target_allowlist: CsvList = []
    ai_target_allow_http: bool = False
    ai_target_timeout_seconds: int = Field(30, ge=1, le=300)
    ai_target_max_response_kb: int = Field(256, ge=1, le=10240)

    # --- dependency intelligence ------------------------------------------
    osv_enabled: bool = True
    osv_api_url: str = "https://api.osv.dev"
    advisory_db_dir: Path | None = None

    # --- external analyzers ---------------------------------------------------
    external_scanners: CsvList = ["bandit", "semgrep", "gitleaks"]

    # --- GitHub integration ---------------------------------------------------
    public_base_url: str | None = None

    @field_validator("cors_origins", "git_allowed_hosts", "ai_target_allowlist", "external_scanners", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @model_validator(mode="after")
    def _production_guards(self) -> Settings:
        if self.environment == "production":
            key = self.secret_key.get_secret_value()
            if key == _INSECURE_DEV_KEY or len(key) < 32:
                raise ValueError("SECURELENS_SECRET_KEY must be set to a random value of at least 32 characters")
            if not self.cookie_secure:
                raise ValueError("SECURELENS_COOKIE_SECURE must be true in production")
        return self

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def uses_insecure_default_key(self) -> bool:
        return self.secret_key.get_secret_value() == _INSECURE_DEV_KEY

    def ensure_dirs(self) -> None:
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        if self.is_sqlite and ":memory:" not in self.database_url:
            db_path = self.database_url.split("///", 1)[-1]
            if db_path:
                Path(db_path).parent.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()
