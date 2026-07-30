"""Provider + model discovery and credential helpers for the interactive TUI.

These helpers back the ``/provider`` and ``/model`` slash commands: they list
the LLM providers and chat-capable models that LiteLLM knows about, detect
whether a provider's credentials are configured, and persist an API key for a
provider so subsequent calls authenticate.
"""

from __future__ import annotations

import asyncio
import configparser
import contextlib
import importlib.util
import io
import json
import logging
import os
import shutil
import threading
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from time import monotonic
from typing import Any, cast
from urllib.parse import urlparse, urlsplit, urlunsplit

import requests


logger = logging.getLogger(__name__)


# Providers we surface first in the picker (curated / most common), plus
# OpenRouter which aggregates many models behind a single key.
PREFERRED_PROVIDERS: tuple[str, ...] = (
    "openai",
    "chatgpt",
    "anthropic",
    "gemini",
    "vertex_ai",
    "deepseek",
    "dashscope",
    "moonshot",
    "openrouter",
    "xai",
    "groq",
    "mistral",
    "perplexity",
    "bedrock",
    "azure",
    "ollama",
)

# Model "modes" that make sense for an agent (text in/out). Anything else
# (image/audio/embedding/rerank/...) is filtered out of the model picker.
_CHAT_MODES: frozenset[str | None] = frozenset({None, "chat", "responses", "completion"})

# Provider -> primary API-key env var. This is deliberately explicit: guessing
# an env name for a dynamically discovered provider makes the TUI claim that a
# credential is usable when LiteLLM may expect OAuth, IAM, or multiple fields.
_PROVIDER_API_KEY_ENV: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "dashscope": "DASHSCOPE_API_KEY",
    "moonshot": "MOONSHOT_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "xai": "XAI_API_KEY",
    "groq": "GROQ_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "perplexity": "PERPLEXITYAI_API_KEY",
    "cohere": "COHERE_API_KEY",
    "together_ai": "TOGETHERAI_API_KEY",
    "fireworks_ai": "FIREWORKS_AI_API_KEY",
    "deepinfra": "DEEPINFRA_API_KEY",
    "cerebras": "CEREBRAS_API_KEY",
    "azure": "AZURE_API_KEY",
    "novita": "NOVITA_API_KEY",
}
_PROVIDER_API_KEY_ALIASES: dict[str, tuple[str, ...]] = {
    "fireworks_ai": ("FIREWORKS_API_KEY",),
    "gemini": ("GOOGLE_API_KEY",),
    "perplexity": ("PERPLEXITY_API_KEY",),
}
_LEGACY_API_KEY_ENV = "LLM_API_KEY"
_legacy_key_warnings: set[str] = set()
_invalid_provider_credentials: dict[str, str] = {}
_PROVIDER_REQUIRED_ENV: dict[str, tuple[str, ...]] = {
    "azure": ("AZURE_API_BASE", "AZURE_API_VERSION"),
}

_GOOGLE_EXTERNAL_AUTH_PROVIDERS: frozenset[str] = frozenset({"vertex_ai", "vertex_ai_beta"})
_AWS_EXTERNAL_AUTH_PROVIDERS: frozenset[str] = frozenset(
    {
        "amazon_nova",
        "bedrock",
        "bedrock_mantle",
        "sagemaker",
        "sagemaker_chat",
        "sagemaker_nova",
    }
)
_EXTERNAL_AUTH_PROVIDERS = _GOOGLE_EXTERNAL_AUTH_PROVIDERS | _AWS_EXTERNAL_AUTH_PROVIDERS
_LOCAL_PROVIDERS: frozenset[str] = frozenset({"ollama", "ollama_chat", "vllm"})
_HIDDEN_PROVIDER_ALIASES: frozenset[str] = frozenset({"ollama_chat"})
# LiteLLM starts interactive OAuth/device flows while resolving these providers.
# Picker status must remain passive; the actual model preflight owns login behavior.
_NON_PASSIVE_REQUIREMENT_PROVIDERS: frozenset[str] = frozenset(
    {"chatgpt", "cursor", "github", "github_copilot"}
)
CUSTOM_PROVIDER_KINDS: tuple[str, ...] = ("openai", "llama_cpp", "vllm")
CUSTOM_PROVIDER_ADD = "__add_custom__"
_OLLAMA_DEFAULT_BASE = "http://localhost:11434"
_OLLAMA_TIMEOUT = (0.5, 1.5)
_CUSTOM_MODEL_TIMEOUT = (0.25, 0.75)
_CUSTOM_MODEL_CACHE_TTL = 60.0
_CUSTOM_MODEL_FAILURE_COOLDOWN = 30.0
_CUSTOM_MODEL_LIMIT = 2_000
_CUSTOM_MODEL_ID_LIMIT = 512
_custom_model_cache: dict[str, tuple[float, tuple[str, ...]]] = {}
_custom_model_failures: dict[str, tuple[float, str]] = {}
_litellm_requirement_lock = threading.Lock()
_CHATGPT_STABLE_MODEL = "chatgpt/gpt-5.4"


@dataclass(frozen=True)
class CustomProvider:
    id: str
    name: str
    api_base: str
    api_key: str | None = field(default=None, repr=False)
    kind: str = "openai"
    disabled: bool = False

    @property
    def transport(self) -> str:
        return "hosted_vllm" if self.kind == "vllm" else "openai"


class ProviderAuthState(StrEnum):
    CONFIGURED = "configured"
    MISSING = "missing"
    INVALID = "invalid"
    EXTERNAL = "external"
    LOCAL = "local"
    UNAVAILABLE = "unavailable"
    UNSUPPORTED = "unsupported"


class ProviderCredentialSource(StrEnum):
    ENV = "env"
    CONFIG = "config"
    CUSTOM = "custom"
    EXTERNAL = "external"
    LOCAL = "local"
    SUBSCRIPTION = "subscription"
    AMBIENT = "ambient"


class ProviderDisabledError(RuntimeError):
    """Raised before a disabled custom-provider route can resolve or connect."""


@dataclass(frozen=True)
class ProviderAuthStatus:
    state: ProviderAuthState
    detail: str

    @property
    def ready(self) -> bool:
        return self.state in {
            ProviderAuthState.CONFIGURED,
            ProviderAuthState.EXTERNAL,
            ProviderAuthState.LOCAL,
        }


@dataclass(frozen=True)
class ProviderModelGroup:
    provider: str
    label: str
    models: tuple[str, ...]
    allow_manual: bool = False
    error: str | None = None


def provider_for_model(model_name: str | None) -> str | None:
    """Return the credential provider for a routed model name."""
    name = (model_name or "").strip().lower()
    if not name:
        return None
    for prefix in ("litellm/", "any-llm/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    return name.split("/", 1)[0] if "/" in name else "openai"


def list_custom_providers() -> list[CustomProvider]:
    """Load all valid custom OpenAI-compatible endpoint definitions."""
    from strix.config.loader import read_custom_provider_records

    providers: list[CustomProvider] = []
    seen_ids: set[str] = set()
    for record in read_custom_provider_records():
        provider_id = record.get("id", "").strip().lower()
        name = record.get("name", "").strip()
        api_base = record.get("api_base", "").strip()
        kind = record.get("kind", "openai").strip().lower()
        if (
            not provider_id.startswith("custom-")
            or not name
            or not api_base
            or provider_id in seen_ids
        ):
            continue
        seen_ids.add(provider_id)
        if kind not in CUSTOM_PROVIDER_KINDS:
            kind = "openai"
        providers.append(
            CustomProvider(
                id=provider_id,
                name=name,
                api_base=api_base,
                api_key=record.get("api_key") or None,
                kind=kind,
                disabled=record.get("disabled", "").lower() == "true",
            )
        )
    return providers


def custom_provider(provider: str) -> CustomProvider | None:
    normalized = provider.strip().lower()
    return next((item for item in list_custom_providers() if item.id == normalized), None)


def require_provider_enabled(provider: str) -> CustomProvider | None:
    """Return a custom provider, rejecting disabled routes before resolution."""
    item = custom_provider(provider)
    if item is not None and item.disabled:
        raise ProviderDisabledError(f"Custom provider '{item.name}' is disconnected")
    return item


def provider_display_name(provider: str) -> str:
    item = custom_provider(provider)
    if item:
        return item.name
    if provider.strip().lower() == "chatgpt":
        return "ChatGPT subscription"
    return provider


def provider_credential_source(  # noqa: PLR0911 - source precedence is explicit
    provider: str,
) -> ProviderCredentialSource | None:
    """Return the active provider configuration source without exposing credentials."""
    from strix.config.loader import read_config_env

    normalized = provider.strip().lower()
    if item := custom_provider(normalized):
        return None if item.disabled else ProviderCredentialSource.CUSTOM
    if normalized == "chatgpt":
        from strix.config import codex

        return ProviderCredentialSource.SUBSCRIPTION if codex.is_authenticated() else None
    key_names = provider_api_key_env_names(normalized)
    process_env = {key.upper(): value for key, value in os.environ.items() if value}
    if any(name.upper() in process_env for name in key_names):
        return ProviderCredentialSource.ENV
    config_env = {key.upper(): value for key, value in read_config_env().items() if value}
    if any(name.upper() in config_env for name in key_names):
        return ProviderCredentialSource.CONFIG
    effective_model = _effective_model()
    if provider_for_model(effective_model) == normalized and _process_environment_value(
        _LEGACY_API_KEY_ENV
    ):
        return ProviderCredentialSource.ENV
    if provider_for_model(config_env.get("STRIX_LLM")) == normalized and config_env.get(
        _LEGACY_API_KEY_ENV
    ):
        return ProviderCredentialSource.CONFIG
    if normalized in _EXTERNAL_AUTH_PROVIDERS:
        return ProviderCredentialSource.EXTERNAL
    if normalized in _LOCAL_PROVIDERS:
        return ProviderCredentialSource.LOCAL
    if provider_auth_status(normalized).ready:
        return ProviderCredentialSource.AMBIENT
    return None


def provider_can_disconnect(provider: str) -> bool:
    return provider_credential_source(provider) in {
        ProviderCredentialSource.CONFIG,
        ProviderCredentialSource.CUSTOM,
    }


def _exception_chain_messages(exc: BaseException) -> tuple[str, ...]:
    messages: list[str] = []
    seen: set[int] = set()
    stack = [exc]
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        messages.append(type(current).__name__)
        messages.append(str(current))
        status_code = getattr(current, "status_code", None)
        if status_code is not None:
            messages.append(f"HTTP {status_code}")
        response = getattr(current, "response", None)
        response_status = getattr(response, "status_code", None)
        if response_status is not None:
            messages.append(f"HTTP {response_status}")
        if current.__cause__ is not None:
            stack.append(current.__cause__)
        if current.__context__ is not None:
            stack.append(current.__context__)
    return tuple(messages)


def provider_authentication_error(exc: BaseException) -> bool:
    """Return whether an exception definitively indicates rejected credentials."""
    joined = " ".join(_exception_chain_messages(exc)).lower()
    markers = (
        "http 401",
        "error code: 401",
        "status code: 401",
        "401 unauthorized",
        "authenticationerror",
        "authentication error",
        "invalid api key",
        "incorrect api key",
        "invalid x-api-key",
        "invalid authentication",
        "invalid bearer token",
    )
    return any(marker in joined for marker in markers)


def _invalid_credential_detail(provider: str) -> str:
    source = provider_credential_source(provider)
    env_key = provider_api_key_env(provider) or "provider credentials"
    if source == "env":
        return f"{env_key} was rejected; update it in the environment and restart Strix"
    if source == "custom":
        return "the endpoint rejected its API key; disconnect and re-add the provider"
    if source == ProviderCredentialSource.SUBSCRIPTION:
        return "the ChatGPT sign-in was rejected; run `strix auth login chatgpt` again"
    if source == ProviderCredentialSource.EXTERNAL:
        return "the cloud credential chain was rejected; refresh credentials and restart Strix"
    return f"{env_key} was rejected; select this provider to replace it"


def mark_provider_credentials_invalid(provider: str) -> None:
    normalized = provider.strip().lower()
    _invalid_provider_credentials[normalized] = _invalid_credential_detail(normalized)


def clear_provider_credentials_invalid(provider: str) -> None:
    _invalid_provider_credentials.pop(provider.strip().lower(), None)


def provider_authentication_error_message(model: str, exc: BaseException) -> str | None:
    """Record a definite auth failure and return an actionable user message."""
    if not provider_authentication_error(exc):
        return None
    provider = provider_for_model(model) or "openai"
    mark_provider_credentials_invalid(provider)
    detail = _invalid_credential_detail(provider)
    return f"{provider_display_name(provider)} authentication failed: {detail}"


def set_custom_provider_enabled(provider: str, *, enabled: bool) -> None:
    """Soft-disable or reconnect a persisted custom provider definition."""
    from strix.config.loader import mutate_custom_provider_records

    normalized = provider.strip().lower()

    def mutate(records: list[dict[str, str]]) -> None:
        for record in records:
            if record.get("id", "").strip().lower() != normalized:
                continue
            if enabled:
                record.pop("disabled", None)
            else:
                record["disabled"] = "true"
            return
        raise ValueError(f"Unknown custom provider: {provider}")

    mutate_custom_provider_records(mutate)
    if not enabled:
        _custom_model_cache.pop(normalized, None)
        _custom_model_failures.pop(normalized, None)


def disconnect_provider(provider: str) -> None:
    """Disconnect a TUI-managed credential or soft-disable a custom provider."""
    from strix.config.loader import read_config_env, update_config_env

    normalized = provider.strip().lower()
    if item := custom_provider(normalized):
        if item.disabled:
            return
        set_custom_provider_enabled(normalized, enabled=False)
        clear_provider_credentials_invalid(normalized)
        return
    if provider_credential_source(normalized) != "config":
        raise ValueError(f"Provider '{provider}' is not managed by Strix configuration")
    updates = dict.fromkeys(provider_api_key_env_names(normalized))
    config_env = {key.upper(): value for key, value in read_config_env().items() if value}
    if provider_for_model(config_env.get("STRIX_LLM")) == normalized:
        updates[_LEGACY_API_KEY_ENV] = None
    update_config_env(updates)
    clear_provider_credentials_invalid(normalized)


def save_custom_provider(
    name: str,
    api_base: str,
    api_key: str | None = None,
    kind: str = "openai",
) -> CustomProvider:
    """Validate and persist a new named OpenAI-compatible provider."""
    from strix.config.loader import mutate_custom_provider_records

    clean_name = name.strip()
    clean_base = api_base.strip().rstrip("/")
    clean_kind = kind.strip().lower()
    if not clean_name:
        raise ValueError("name must be a non-empty string")
    if any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in clean_name):
        raise ValueError("name must not contain terminal control characters")
    parsed = urlparse(clean_base)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("api_base must be an absolute HTTP(S) URL")
    if clean_kind not in CUSTOM_PROVIDER_KINDS:
        choices = ", ".join(CUSTOM_PROVIDER_KINDS)
        raise ValueError(f"kind must be one of: {choices}")
    if clean_kind in {"llama_cpp", "vllm"} and parsed.path in {"", "/"}:
        clean_base += "/v1"

    provider = CustomProvider(
        id=f"custom-{uuid.uuid4().hex[:12]}",
        name=clean_name,
        api_base=clean_base,
        api_key=(api_key or "").strip() or None,
        kind=clean_kind,
    )
    record = {
        "id": provider.id,
        "name": provider.name,
        "api_base": provider.api_base,
        "kind": provider.kind,
    }
    if provider.api_key:
        record["api_key"] = provider.api_key
    mutate_custom_provider_records(lambda records: records.append(record))
    return provider


def _full_model_name(provider: str, name: str) -> str:
    """Return the ``provider/model`` form LiteLLM/Strix expects."""
    if "/" in name and name.split("/", 1)[0] == provider:
        return name
    return f"{provider}/{name}"


def _model_cost_entry(provider: str, raw_name: str) -> dict[str, object] | None:
    import litellm

    entry = litellm.model_cost.get(raw_name)
    if entry is None:
        entry = litellm.model_cost.get(_full_model_name(provider, raw_name))
    return entry


def list_providers() -> list[str]:
    """Return LiteLLM chat/catalog providers, the active route, and custom providers.

    Preferred providers are listed first (in ``PREFERRED_PROVIDERS`` order),
    then the remainder alphabetically.
    """
    import litellm

    custom_ids = [provider.id for provider in list_custom_providers()]
    chat_providers = {
        str(getattr(provider, "value", provider))
        for provider in getattr(litellm, "LITELLM_CHAT_PROVIDERS", ())
    }
    catalog_providers = {
        provider
        for provider, models in litellm.models_by_provider.items()
        if models and (provider == "ollama" or _catalog_chat_models(provider))
    }
    available = chat_providers | catalog_providers | {"chatgpt"}
    if selected_provider := provider_for_model(_effective_model()):
        available.add(selected_provider)
    available -= _HIDDEN_PROVIDER_ALIASES | set(custom_ids)
    ordered = [p for p in PREFERRED_PROVIDERS if p in available]
    rest = sorted(available - set(ordered))
    return ordered + rest + custom_ids


def provider_chat_models(provider: str) -> list[str]:
    """Return the chat-capable models for *provider* as ``provider/model`` names."""
    if item := require_provider_enabled(provider):
        return _discover_custom_models(item)[0]

    if provider.strip().lower() == "chatgpt":
        models = [_CHATGPT_STABLE_MODEL]
        selected = _effective_model()
        if (
            selected is not None
            and provider_for_model(selected) == "chatgpt"
            and selected not in models
        ):
            models.append(selected)
        return models

    if provider in {"ollama", "ollama_chat"}:
        return _discover_ollama_models()[0]

    return _catalog_chat_models(provider)


def _catalog_chat_models(provider: str) -> list[str]:
    """Return chat models from LiteLLM's static catalog."""

    import litellm

    raws = litellm.models_by_provider.get(provider) or []
    models: set[str] = set()
    for raw in raws:
        entry = _model_cost_entry(provider, raw)
        mode = entry.get("mode") if entry else None
        if mode in _CHAT_MODES:
            models.add(_full_model_name(provider, raw))
    return sorted(models)


def _discover_custom_models(  # noqa: PLR0912 - success, cache, and failure paths differ
    item: CustomProvider,
) -> tuple[list[str], str | None]:
    require_provider_enabled(item.id)
    now = monotonic()
    cached_entry = _custom_model_cache.get(item.id)
    cached = list(cached_entry[1]) if cached_entry else []
    if cached_entry and now - cached_entry[0] < _CUSTOM_MODEL_CACHE_TTL:
        return cached, None
    if failure := _custom_model_failures.get(item.id):
        retry_at, detail = failure
        if now < retry_at:
            return cached, detail

    headers = {"Authorization": f"Bearer {item.api_key}"} if item.api_key else {}
    try:
        response = requests.get(
            f"{item.api_base.rstrip('/')}/models",
            headers=headers,
            timeout=_CUSTOM_MODEL_TIMEOUT,
        )
        response.raise_for_status()
        payload = cast("object", response.json())
    except requests.Timeout:
        logger.info("Model discovery timed out for custom provider %s", item.id)
        detail = "Model discovery timed out; enter a model ID manually"
        if cached:
            detail = "Model discovery timed out; showing cached models"
        _custom_model_failures[item.id] = (now + _CUSTOM_MODEL_FAILURE_COOLDOWN, detail)
        return cached, detail
    except (requests.RequestException, ValueError) as exc:
        logger.info("Could not discover models for custom provider %s: %s", item.id, exc)
        detail = "Endpoint unavailable; enter a model ID manually"
        if provider_authentication_error(exc):
            mark_provider_credentials_invalid(item.id)
            detail = _invalid_credential_detail(item.id)
        if cached:
            detail = f"{detail}; showing cached models"
        _custom_model_failures[item.id] = (now + _CUSTOM_MODEL_FAILURE_COOLDOWN, detail)
        return cached, detail
    data: list[object] = []
    if isinstance(payload, dict):
        raw_data = cast("dict[object, object]", payload).get("data")
        if isinstance(raw_data, list):
            data = cast("list[object]", raw_data)
    model_ids: set[str] = set()
    for entry in data[:_CUSTOM_MODEL_LIMIT]:
        if not isinstance(entry, dict):
            continue
        model_id = cast("dict[object, object]", entry).get("id")
        if isinstance(model_id, str):
            clean_id = model_id.strip()
            if (
                clean_id
                and len(clean_id) <= _CUSTOM_MODEL_ID_LIMIT
                and all(
                    ord(character) >= 32 and not 127 <= ord(character) <= 159
                    for character in clean_id
                )
            ):
                model_ids.add(clean_id)
    models = [f"{item.id}/{model_id}" for model_id in sorted(model_ids)]
    _custom_model_cache[item.id] = (now, tuple(models))
    _custom_model_failures.pop(item.id, None)
    return models, None


def _ollama_base() -> str:
    from strix.config.loader import read_config_env

    process_env = {key.upper(): value for key, value in os.environ.items() if value}
    config_env = {key.upper(): value for key, value in read_config_env().items() if value}
    effective_model = _effective_model()
    if provider_for_model(effective_model) in {"ollama", "ollama_chat"} and (
        base := process_env.get("LLM_API_BASE")
    ):
        return base.rstrip("/")
    if base := process_env.get("OLLAMA_API_BASE"):
        return base.rstrip("/")
    if provider_for_model(config_env.get("STRIX_LLM")) in {"ollama", "ollama_chat"} and (
        base := config_env.get("LLM_API_BASE")
    ):
        return base.rstrip("/")
    return config_env.get("OLLAMA_API_BASE", _OLLAMA_DEFAULT_BASE).rstrip("/")


def normalize_ollama_api_base(base: str) -> str:
    """Return the native Ollama API root used by discovery and inference."""
    parsed = urlsplit(base)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Ollama endpoint '{base}' is not a valid HTTP(S) URL")
    if parsed.query or parsed.fragment:
        raise ValueError("Ollama endpoint must not contain a query string or fragment")
    path = parsed.path.rstrip("/")
    if path.endswith("/api/tags"):
        path = path.removesuffix("/api/tags")
    elif path.endswith(("/v1", "/api")):
        path = path.rsplit("/", 1)[0]
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _ollama_tags_url(base: str) -> tuple[str | None, str | None]:
    try:
        root = normalize_ollama_api_base(base)
    except ValueError as exc:
        return None, str(exc)
    return f"{root}/api/tags", None


def _discover_ollama_models() -> tuple[list[str], str | None]:
    base = _ollama_base()
    tags_url, url_error = _ollama_tags_url(base)
    if url_error or tags_url is None:
        return [], url_error
    key = os.environ.get("OLLAMA_API_KEY", "").strip()
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    try:
        response = requests.get(
            tags_url,
            headers=headers,
            timeout=_OLLAMA_TIMEOUT,
        )
        response.raise_for_status()
        payload = cast("object", response.json())
    except (requests.RequestException, ValueError):
        if base == _OLLAMA_DEFAULT_BASE and shutil.which("ollama") is None:
            return [], "Ollama is not installed or its server is not running"
        return [], f"Ollama endpoint at {base} is not reachable"

    if not isinstance(payload, dict):
        return [], f"Ollama endpoint at {base} returned an invalid response"
    raw_models = cast("dict[object, object]", payload).get("models")
    if not isinstance(raw_models, list):
        return [], f"Ollama endpoint at {base} returned an invalid response"
    model_ids: set[str] = set()
    for entry in cast("list[object]", raw_models):
        if not isinstance(entry, dict):
            continue
        record = cast("dict[object, object]", entry)
        model_id = record.get("model") or record.get("name")
        if isinstance(model_id, str):
            clean_id = model_id.strip()
            if (
                clean_id
                and len(clean_id) <= _CUSTOM_MODEL_ID_LIMIT
                and all(
                    ord(character) >= 32 and not 127 <= ord(character) <= 159
                    for character in clean_id
                )
            ):
                model_ids.add(clean_id)
    return [f"ollama/{model_id}" for model_id in sorted(model_ids)], None


def _normalize_litellm_route(model: str) -> str:
    route = model.strip()
    for prefix in ("litellm/", "any-llm/"):
        if route.lower().startswith(prefix):
            return route[len(prefix) :]
    return route


def _representative_model(provider: str, selected_model: str | None = None) -> str | None:
    if selected_model and provider_for_model(selected_model) == provider:
        return _normalize_litellm_route(selected_model)
    models = _catalog_chat_models(provider)
    return models[0] if models else None


def _litellm_environment_requirements(
    provider: str,
    selected_model: str | None = None,
) -> tuple[tuple[str, ...] | None, str | None]:
    """Return LiteLLM's reported requirements, or an inspection error.

    Only real catalog routes or an explicitly selected route are inspected. A
    made-up model can cause provider-specific login flows, so it is never used
    to infer credential names.
    """
    if provider in _NON_PASSIVE_REQUIREMENT_PROVIDERS:
        return (), None
    model = _representative_model(provider, selected_model)
    if model is None:
        return None, "select a model route to inspect its environment requirements"
    try:
        import litellm

        # Some LiteLLM provider resolvers print setup guidance directly. Picker
        # status is passive, so capture that output and report through our status.
        with (
            _litellm_requirement_lock,
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            report: object = litellm.validate_environment(model=model)
    except (Exception, SystemExit) as exc:  # noqa: BLE001 - third-party provider inspection
        logger.info("Could not inspect LiteLLM requirements for %s", model, exc_info=True)
        return None, f"could not inspect LiteLLM requirements: {exc}"
    if not isinstance(report, dict):
        return None, "LiteLLM returned an invalid environment-requirement report"
    raw_missing = cast("dict[str, Any]", report).get("missing_keys", [])
    if not isinstance(raw_missing, (list, tuple, set)):
        return None, "LiteLLM returned an invalid environment-requirement report"
    missing = tuple(
        dict.fromkeys(
            value.strip()
            for value in cast("list[object] | tuple[object, ...] | set[object]", raw_missing)
            if isinstance(value, str) and value.strip()
        )
    )
    return missing, None


def _dynamic_api_key_env(provider: str, model: str | None = None) -> str | None:
    requirements, _error = _litellm_environment_requirements(provider, model)
    if requirements is None or len(requirements) != 1:
        return None
    candidate = requirements[0]
    return candidate if candidate.endswith("_API_KEY") else None


def provider_api_key_env(provider: str, *, model: str | None = None) -> str | None:
    """Return the ``*_API_KEY`` env var *provider* uses.

    Long-tail providers are mapped only when LiteLLM reports exactly one clear
    ``*_API_KEY`` requirement. No variable name is inferred from the provider.
    """
    normalized = provider.lower()
    if env_key := _PROVIDER_API_KEY_ENV.get(normalized):
        return env_key
    if normalized in _EXTERNAL_AUTH_PROVIDERS | _LOCAL_PROVIDERS or normalized == "chatgpt":
        return None
    selected_model = model
    if selected_model is None:
        selected_model = _selected_model_for_provider(normalized)
    return _dynamic_api_key_env(normalized, selected_model)


def provider_api_key_env_names(provider: str, *, model: str | None = None) -> tuple[str, ...]:
    """Return canonical and supported alias variables for a provider key."""
    normalized = provider.lower()
    env_key = provider_api_key_env(normalized, model=model)
    return (env_key, *_PROVIDER_API_KEY_ALIASES.get(normalized, ())) if env_key else ()


def resolve_provider_api_key(
    provider: str,
    *,
    primary_model: str | None = None,
    model: str | None = None,
) -> str | None:
    """Resolve a provider key, with a model-bound legacy fallback."""
    from strix.config.loader import load_settings, read_config_env, resolve_env_value

    normalized = provider.lower()
    if item := require_provider_enabled(normalized):
        return item.api_key
    key_names = provider_api_key_env_names(normalized, model=model or primary_model)
    if key_names and (api_key := resolve_env_value(*key_names)):
        return api_key

    configured_model = primary_model
    if configured_model is None:
        configured_model = load_settings().llm.model
        key_names = provider_api_key_env_names(normalized, model=model or configured_model)
        if key_names and (api_key := resolve_env_value(*key_names)):
            return api_key
    api_key = None
    if provider_for_model(configured_model) == normalized:
        api_key = _process_environment_value(_LEGACY_API_KEY_ENV)
    config_env = {key.upper(): value for key, value in read_config_env().items() if value}
    if api_key is None and provider_for_model(config_env.get("STRIX_LLM")) == normalized:
        api_key = config_env.get(_LEGACY_API_KEY_ENV)
    if api_key:
        if normalized not in _legacy_key_warnings:
            replacement = provider_api_key_env(normalized, model=configured_model)
            logger.warning(
                "%s is deprecated; use %s for model provider %s when available",
                _LEGACY_API_KEY_ENV,
                replacement or "a provider-specific credential",
                normalized,
            )
            _legacy_key_warnings.add(normalized)
        return api_key
    return None


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def _effective_model() -> str | None:
    from strix.config.loader import load_settings

    return load_settings().llm.model


def _selected_model_for_provider(provider: str) -> str | None:
    model = _effective_model()
    return model if provider_for_model(model) == provider else None


def _process_environment_value(name: str) -> str | None:
    target = name.upper()
    return next(
        (value for key, value in os.environ.items() if key.upper() == target and value),
        None,
    )


def _json_object_file(path: Path) -> bool:
    try:
        payload: object = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    return isinstance(payload, dict)


def _vertex_credentials_detected() -> bool:
    explicit = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
    if explicit and _json_object_file(Path(explicit).expanduser()):
        return True

    raw_credentials = os.environ.get("VERTEXAI_CREDENTIALS", "").strip()
    if raw_credentials:
        try:
            payload: object = json.loads(raw_credentials)
        except json.JSONDecodeError:
            return _json_object_file(Path(raw_credentials).expanduser())
        return isinstance(payload, dict)

    cloud_config = os.environ.get("CLOUDSDK_CONFIG", "").strip()
    adc_path = (
        Path(cloud_config).expanduser() if cloud_config else Path.home() / ".config" / "gcloud"
    ) / "application_default_credentials.json"
    return _json_object_file(adc_path)


def _aws_profile_detected() -> bool:
    profile = (
        os.environ.get("AWS_PROFILE", "").strip()
        or os.environ.get("AWS_DEFAULT_PROFILE", "").strip()
        or "default"
    )
    credentials_path = Path(
        os.environ.get("AWS_SHARED_CREDENTIALS_FILE", "~/.aws/credentials")
    ).expanduser()
    config_path = Path(os.environ.get("AWS_CONFIG_FILE", "~/.aws/config")).expanduser()
    for path, section, is_config in (
        (credentials_path, profile, False),
        (config_path, profile if profile == "default" else f"profile {profile}", True),
    ):
        parser = configparser.RawConfigParser()
        try:
            parser.read(path, encoding="utf-8")
        except (configparser.Error, OSError):
            continue
        if not parser.has_section(section):
            continue
        values = {key: value.strip() for key, value in parser.items(section) if value.strip()}
        if values.get("aws_access_key_id") and values.get("aws_secret_access_key"):
            return True
        if not is_config:
            continue
        if values.get("credential_process") or values.get("sso_session"):
            return True
        if values.get("sso_start_url") and values.get("sso_account_id"):
            return True
        if values.get("role_arn") and any(
            values.get(name)
            for name in ("source_profile", "credential_source", "web_identity_token_file")
        ):
            return True
    return False


def _aws_credentials_detected(*, allow_bedrock_token: bool) -> bool:
    access_key = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
    if access_key and secret_key:
        return True
    if allow_bedrock_token and os.environ.get("AWS_BEARER_TOKEN_BEDROCK", "").strip():
        return True
    token_file = os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE", "").strip()
    role_arn = os.environ.get("AWS_ROLE_ARN", "").strip()
    if token_file and role_arn and Path(token_file).expanduser().is_file():
        return True
    if os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "").strip():
        return True
    if os.environ.get("AWS_CONTAINER_CREDENTIALS_FULL_URI", "").strip():
        return True
    return _aws_profile_detected()


def _external_auth_status(provider: str) -> ProviderAuthStatus:  # noqa: PLR0911
    selected = _selected_model_for_provider(provider) is not None
    if provider in _GOOGLE_EXTERNAL_AUTH_PROVIDERS:
        if not _module_available("google.auth"):
            detail = 'needs google-auth; install with pipx install "strix-agent[vertex]"'
            if selected:
                detail = f"selected model uses Google ADC but {detail}"
            return ProviderAuthStatus(ProviderAuthState.MISSING, detail)
        if _vertex_credentials_detected():
            return ProviderAuthStatus(
                ProviderAuthState.EXTERNAL,
                "Google ADC detected; project access not verified",
            )
        if selected:
            return ProviderAuthStatus(
                ProviderAuthState.EXTERNAL,
                "selected model uses ambient Google credentials; not verified",
            )
        return ProviderAuthStatus(
            ProviderAuthState.MISSING,
            "Google credentials were not detected locally; configure ADC or set "
            "STRIX_LLM explicitly to use ambient metadata credentials",
        )

    if not (_module_available("boto3") and _module_available("botocore")):
        detail = 'needs boto3; install with pipx install "strix-agent[bedrock]"'
        if selected:
            detail = f"selected model uses AWS credentials but {detail}"
        return ProviderAuthStatus(ProviderAuthState.MISSING, detail)
    if _aws_credentials_detected(allow_bedrock_token=provider == "bedrock"):
        qualifier = "model" if provider == "bedrock" else "endpoint"
        return ProviderAuthStatus(
            ProviderAuthState.EXTERNAL,
            f"AWS credentials detected; region, {qualifier}, and permissions not verified",
        )
    if selected:
        return ProviderAuthStatus(
            ProviderAuthState.EXTERNAL,
            "selected model uses ambient AWS credentials; not verified",
        )
    return ProviderAuthStatus(
        ProviderAuthState.MISSING,
        "AWS credentials were not detected locally; configure AWS credentials or set "
        "STRIX_LLM explicitly to use ambient instance credentials",
    )


def provider_auth_status(  # noqa: PLR0911,PLR0912 - auth strategies intentionally branch
    provider: str,
) -> ProviderAuthStatus:
    """Describe how a provider authenticates and whether a key is available."""
    from strix.config.loader import resolve_env_value

    normalized = provider.lower()
    if detail := _invalid_provider_credentials.get(normalized):
        return ProviderAuthStatus(ProviderAuthState.INVALID, detail)
    if item := custom_provider(normalized):
        if item.disabled:
            return ProviderAuthStatus(
                ProviderAuthState.MISSING,
                "disconnected; select to reconnect",
            )
        return ProviderAuthStatus(
            ProviderAuthState.CONFIGURED,
            f"{item.kind.replace('_', '.')} endpoint at {item.api_base}",
        )
    if normalized == "chatgpt":
        from strix.config import codex

        if codex.is_authenticated():
            return ProviderAuthStatus(
                ProviderAuthState.CONFIGURED,
                "signed in with Codex authentication",
            )
        return ProviderAuthStatus(
            ProviderAuthState.MISSING,
            "sign in with `strix auth login chatgpt` (no API key required)",
        )
    if normalized in _EXTERNAL_AUTH_PROVIDERS:
        return _external_auth_status(normalized)
    if normalized in {"ollama", "ollama_chat"}:
        models, error = _discover_ollama_models()
        if error:
            return ProviderAuthStatus(ProviderAuthState.UNAVAILABLE, error)
        detail = (
            f"Ollama is running with {len(models)} installed model(s)"
            if models
            else "Ollama is running, but no models are installed"
        )
        return ProviderAuthStatus(ProviderAuthState.LOCAL, detail)
    if normalized in _LOCAL_PROVIDERS:
        return ProviderAuthStatus(
            ProviderAuthState.LOCAL,
            "uses a local endpoint; not verified",
        )
    selected_model = _selected_model_for_provider(normalized)
    env_key = _PROVIDER_API_KEY_ENV.get(normalized)
    if env_key is None:
        if selected_model and resolve_provider_api_key(
            normalized,
            primary_model=selected_model,
        ):
            return ProviderAuthStatus(
                ProviderAuthState.CONFIGURED,
                "explicit route has model-bound credentials; preflight will verify them",
            )
        requirements, inspection_error = _litellm_environment_requirements(
            normalized,
            selected_model,
        )
        if requirements is None:
            if selected_model:
                return ProviderAuthStatus(
                    ProviderAuthState.EXTERNAL,
                    "explicit route delegates authentication to LiteLLM/AnyLLM; not verified",
                )
            return ProviderAuthStatus(
                ProviderAuthState.UNSUPPORTED,
                inspection_error or "environment requirements could not be inspected",
            )
        if not requirements:
            return ProviderAuthStatus(
                ProviderAuthState.EXTERNAL,
                "LiteLLM reports no missing environment requirements; route not verified",
            )
        dynamic_key = (
            requirements[0]
            if len(requirements) == 1 and requirements[0].endswith("_API_KEY")
            else None
        )
        if dynamic_key is None:
            if selected_model:
                return ProviderAuthStatus(
                    ProviderAuthState.EXTERNAL,
                    "explicit route delegates authentication to LiteLLM/AnyLLM; not verified",
                )
            return ProviderAuthStatus(
                ProviderAuthState.MISSING,
                f"LiteLLM requires {', '.join(requirements)}",
            )
        if resolve_provider_api_key(normalized, primary_model=selected_model):
            return ProviderAuthStatus(
                ProviderAuthState.CONFIGURED,
                f"{dynamic_key} is available",
            )
        return ProviderAuthStatus(
            ProviderAuthState.MISSING,
            f"needs {dynamic_key}",
        )
    missing_requirements = [
        name for name in _PROVIDER_REQUIRED_ENV.get(normalized, ()) if not resolve_env_value(name)
    ]
    if missing_requirements:
        return ProviderAuthStatus(
            ProviderAuthState.MISSING,
            f"needs {', '.join(missing_requirements)}",
        )
    if resolve_provider_api_key(normalized):
        return ProviderAuthStatus(ProviderAuthState.CONFIGURED, f"{env_key} is available")
    return ProviderAuthStatus(ProviderAuthState.MISSING, f"needs {env_key}")


def is_provider_configured(provider: str) -> bool:
    """Return whether setup can proceed for *provider*.

    External and local auth are allowed but remain explicitly unverified in the
    richer :func:`provider_auth_status` result used by the picker.
    """
    return provider_auth_status(provider).ready


async def configured_provider_model_groups(
    current_model: str | None = None,
) -> list[ProviderModelGroup]:
    """Discover models for every configured provider without serial endpoint waits."""
    selected = (current_model if current_model is not None else _effective_model() or "").strip()

    async def load_group(  # noqa: PLR0911,PLR0912 - discovery strategies intentionally branch
        provider: str,
    ) -> ProviderModelGroup | None:
        item = custom_provider(provider)
        if item:
            if item.disabled or not provider_auth_status(provider).ready:
                return None
            try:
                models, error = await asyncio.to_thread(_discover_custom_models, item)
            except Exception as exc:  # noqa: BLE001 - isolate one endpoint from the picker
                logger.info("Could not load models for custom provider %s", provider, exc_info=True)
                models, error = [], str(exc)
            if selected.startswith(f"{provider}/") and selected not in models:
                models.append(selected)
                models.sort()
            return ProviderModelGroup(
                provider=provider,
                label=item.name,
                models=tuple(models),
                allow_manual=True,
                error=error,
            )

        if provider == "chatgpt":
            if not provider_auth_status(provider).ready:
                return None
            models = [_CHATGPT_STABLE_MODEL]
            if provider_for_model(selected) == provider and selected not in models:
                models.append(selected)
            return ProviderModelGroup(
                provider=provider,
                label=provider_display_name(provider),
                models=tuple(models),
                allow_manual=True,
            )

        if provider == "ollama":
            try:
                models, error = await asyncio.to_thread(_discover_ollama_models)
            except Exception:  # noqa: BLE001 - keep other configured providers usable
                logger.info("Could not load Ollama models", exc_info=True)
                return None
            if error:
                return None
            if selected and provider_for_model(selected) == provider and selected not in models:
                models.append(selected)
                models.sort()
            return ProviderModelGroup(
                provider=provider,
                label=provider_display_name(provider),
                models=tuple(models),
                allow_manual=True,
            )

        status = await asyncio.to_thread(provider_auth_status, provider)
        if not status.ready:
            return None
        try:
            models = await asyncio.to_thread(_catalog_chat_models, provider)
        except Exception as exc:  # noqa: BLE001 - isolate one catalog from the picker
            logger.info("Could not load models for provider %s", provider, exc_info=True)
            return ProviderModelGroup(
                provider=provider,
                label=provider_display_name(provider),
                models=(),
                allow_manual=True,
                error=str(exc),
            )
        if selected and provider_for_model(selected) == provider and selected not in models:
            models.append(selected)
            models.sort()
        return ProviderModelGroup(
            provider=provider,
            label=provider_display_name(provider),
            models=tuple(models),
            allow_manual=True,
        )

    groups = await asyncio.gather(*(load_group(provider) for provider in list_providers()))
    available = [group for group in groups if group is not None]
    return [group for group in available if group.provider != "openrouter"] + [
        group for group in available if group.provider == "openrouter"
    ]


def persist_selected_model(model: str) -> None:
    """Persist one model without carrying generic credentials or endpoints across providers."""
    from strix.config.loader import read_config_env, resolve_env_value, update_config_env

    clean_model = model.strip()
    if not clean_model:
        raise ValueError("model must be a non-empty string")
    routed_model = clean_model
    for prefix in ("litellm/", "any-llm/"):
        if routed_model.lower().startswith(prefix):
            routed_model = routed_model[len(prefix) :]
            break
    if not routed_model or ("/" in routed_model and not routed_model.split("/", 1)[1].strip()):
        raise ValueError("model ID must be a non-empty string")
    previous_model = (resolve_env_value("STRIX_LLM") or "").strip()
    previous_provider = provider_for_model(previous_model)
    selected_provider = provider_for_model(clean_model)
    changing_provider = previous_provider != selected_provider
    if (
        previous_provider is not None
        and changing_provider
        and _process_environment_value(_LEGACY_API_KEY_ENV)
    ):
        replacement = provider_api_key_env(previous_provider, model=previous_model)
        action = (
            f"move it to {replacement}"
            if replacement
            else f"configure provider-specific credentials for '{previous_provider}'"
        )
        raise ValueError(
            f"{_LEGACY_API_KEY_ENV} is set in the environment for the current provider "
            f"'{previous_provider}'; {action}, then unset {_LEGACY_API_KEY_ENV} before "
            "switching providers"
        )
    if changing_provider and any(
        key.upper() == "LLM_API_BASE" and value for key, value in os.environ.items()
    ):
        raise ValueError(
            "LLM_API_BASE is set in the environment for the current provider; "
            "unset it before switching providers"
        )
    updates: dict[str, str | None] = {"STRIX_LLM": clean_model}
    config_env = {key.upper(): value for key, value in read_config_env().items()}
    legacy_model = (config_env.get("STRIX_LLM") or previous_model).strip()
    legacy_provider = provider_for_model(legacy_model)
    if (
        config_env.get(_LEGACY_API_KEY_ENV)
        and legacy_provider is not None
        and legacy_provider != selected_provider
    ):
        raise ValueError(
            f"{_LEGACY_API_KEY_ENV} is stored for the current provider '{legacy_provider}'; "
            "save a provider-specific key or disconnect that provider before switching"
        )
    if changing_provider and config_env.get("LLM_API_BASE") is not None:
        updates["LLM_API_BASE"] = None
    update_config_env(updates)
    os.environ["STRIX_LLM"] = clean_model


def set_provider_api_key(provider: str, api_key: str) -> None:
    """Persist an API key for a provider with explicit key-based auth."""
    from strix.config.loader import update_config_env

    require_provider_enabled(provider)
    env_key = provider_api_key_env(provider)
    if env_key is None:
        raise ValueError(f"Provider '{provider}' does not use a TUI-managed API key")
    update_config_env({env_key: api_key.strip()})
    clear_provider_credentials_invalid(provider)
    logger.info("Stored API key for provider %s under %s", provider, env_key)
