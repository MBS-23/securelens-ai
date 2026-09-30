"""AI provider abstraction.

    none       AI features are off. Everything deterministic keeps working, and the
               UI shows AI actions as unavailable rather than pretending.
    openai     Any OpenAI-compatible Chat Completions endpoint. Point
               SECURELENS_AI_BASE_URL at a local server to keep code on-premises.
    anthropic  The Anthropic Messages API.

The model is always configured explicitly (SECURELENS_AI_MODEL); there is no
built-in default. The API key comes from the environment and never reaches
the database, logs or responses. Provider output is untrusted input: callers
validate it against a schema, and nothing here makes a security decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from securelens.core.config import Settings, get_settings

OPENAI_DEFAULT_BASE = "https://api.openai.com/v1"
ANTHROPIC_DEFAULT_BASE = "https://api.anthropic.com"
ANTHROPIC_VERSION = "2023-06-01"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class AIProviderError(Exception):
    """The provider call failed; the message is safe to show (it never contains the key)."""


class AIUnavailable(AIProviderError):
    """AI is disabled or not fully configured."""


@dataclass
class AIResponse:
    text: str
    model: str
    input_tokens: int | None = None
    output_tokens: int | None = None


class Provider(Protocol):
    name: str
    model: str

    def complete(self, *, system: str, messages: list[dict[str, str]], max_tokens: int,
                 temperature: float = 0.0, json_mode: bool = False) -> AIResponse: ...


def _post(url: str, *, headers: dict[str, str], body: dict[str, Any], timeout: float) -> dict[str, Any]:
    try:
        response = httpx.post(url, headers=headers, json=body, timeout=timeout)
    except httpx.TimeoutException as exc:
        raise AIProviderError("the AI provider did not respond in time") from exc
    except httpx.HTTPError as exc:
        raise AIProviderError(f"could not reach the AI provider ({type(exc).__name__})") from exc
    if response.status_code in (401, 403):
        raise AIProviderError("the AI provider rejected the credentials")
    if response.status_code == 429:
        raise AIProviderError("the AI provider is rate limiting requests; try again later")
    if response.status_code >= 400:
        raise AIProviderError(f"the AI provider returned HTTP {response.status_code}")
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise AIProviderError("the AI provider response was too large")
    try:
        data = response.json()
    except ValueError as exc:
        raise AIProviderError("the AI provider returned a response that is not JSON") from exc
    if not isinstance(data, dict):
        raise AIProviderError("the AI provider returned an unexpected response")
    return data


class OpenAICompatibleProvider:
    name = "openai"

    def __init__(self, *, base_url: str, api_key: str | None, model: str, timeout: float) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def complete(self, *, system: str, messages: list[dict[str, str]], max_tokens: int,
                 temperature: float = 0.0, json_mode: bool = False) -> AIResponse:
        body: dict[str, Any] = {"model": self.model, "max_tokens": max_tokens, "temperature": temperature,
                                "messages": [{"role": "system", "content": system}, *messages]}
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        data = _post(f"{self.base_url}/chat/completions", headers=headers, body=body, timeout=self.timeout)
        try:
            text = data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise AIProviderError("the AI provider returned an unexpected response") from exc
        usage = data.get("usage") or {}
        return AIResponse(text=str(text), model=str(data.get("model") or self.model),
                          input_tokens=usage.get("prompt_tokens"), output_tokens=usage.get("completion_tokens"))


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, *, base_url: str, api_key: str, model: str, timeout: float) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def complete(self, *, system: str, messages: list[dict[str, str]], max_tokens: int,
                 temperature: float = 0.0, json_mode: bool = False) -> AIResponse:
        body = {"model": self.model, "system": system, "messages": messages, "max_tokens": max_tokens,
                "temperature": temperature}
        headers = {"x-api-key": self.api_key, "anthropic-version": ANTHROPIC_VERSION}
        data = _post(f"{self.base_url}/v1/messages", headers=headers, body=body, timeout=self.timeout)
        try:
            text = "".join(block.get("text", "") for block in data["content"] if block.get("type") == "text")
        except (KeyError, TypeError, AttributeError) as exc:
            raise AIProviderError("the AI provider returned an unexpected response") from exc
        usage = data.get("usage") or {}
        return AIResponse(text=text, model=str(data.get("model") or self.model),
                          input_tokens=usage.get("input_tokens"), output_tokens=usage.get("output_tokens"))


def _missing(settings: Settings) -> str | None:
    if settings.ai_provider == "none":
        return "AI features are disabled (SECURELENS_AI_PROVIDER=none)"
    if not settings.ai_model:
        return "SECURELENS_AI_MODEL is not set"
    if settings.ai_provider == "anthropic" and not settings.ai_api_key:
        return "SECURELENS_AI_API_KEY is not set"
    if settings.ai_provider == "openai" and not settings.ai_api_key and not settings.ai_base_url:
        return "SECURELENS_AI_API_KEY is not set (or point SECURELENS_AI_BASE_URL at a local server)"
    return None


def get_provider(settings: Settings | None = None) -> Provider:
    settings = settings or get_settings()
    problem = _missing(settings)
    if problem:
        raise AIUnavailable(problem)
    key = settings.ai_api_key.get_secret_value() if settings.ai_api_key else None
    assert settings.ai_model is not None
    if settings.ai_provider == "anthropic":
        assert key is not None
        return AnthropicProvider(base_url=settings.ai_base_url or ANTHROPIC_DEFAULT_BASE, api_key=key,
                                 model=settings.ai_model, timeout=settings.ai_timeout_seconds)
    return OpenAICompatibleProvider(base_url=settings.ai_base_url or OPENAI_DEFAULT_BASE, api_key=key,
                                    model=settings.ai_model, timeout=settings.ai_timeout_seconds)


def provider_status(settings: Settings | None = None) -> dict[str, Any]:
    """What the UI shows about AI: never the key, only whether it is configured."""
    settings = settings or get_settings()
    problem = _missing(settings)
    base = settings.ai_base_url or (ANTHROPIC_DEFAULT_BASE if settings.ai_provider == "anthropic"
                                    else OPENAI_DEFAULT_BASE)
    return {
        "provider": settings.ai_provider,
        "available": problem is None,
        "model": settings.ai_model if settings.ai_provider != "none" else None,
        "endpoint_host": (urlsplit(base).hostname if settings.ai_provider != "none" else None),
        "detail": problem or "configured; AI output is advisory and validated before it is shown",
    }
