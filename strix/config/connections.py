from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from typing import Any

from strix.config import codex
from strix.config.loader import (
    load_settings,
    read_config_document,
    reload_settings,
    write_config_document,
)


logger = logging.getLogger(__name__)

CHATGPT = "chatgpt"
CUSTOM = "custom"
_RECENT_LIMIT = 10
_CATALOG_TIMEOUT_S = 4.0
_KEYLESS_PLACEHOLDER = "not-needed"
_API_KEY_ALIASES = ("LLM_API_KEY",)
_API_BASE_ALIASES = (
    "LLM_API_BASE",
    "OPENAI_API_BASE",
    "OPENAI_BASE_URL",
    "LITELLM_BASE_URL",
    "OLLAMA_API_BASE",
)
_SNAPSHOT_SUFFIX = re.compile(r"(-\d{8}|-\d{4}-\d{2}-\d{2}|@\d{8})$")
_SKIPPED_MODEL_PARTS = (
    "audio",
    "realtime",
    "image",
    "tts",
    "embedding",
    "search-preview",
    "computer-use",
    "transcribe",
    "moderation",
)
EFFORTS = ("none", "minimal", "low", "medium", "high", "xhigh", "max")
SETTING_ALIASES = {
    "effort": "STRIX_REASONING_EFFORT",
    "exa": "EXA_API_KEY",
    "perplexity": "PERPLEXITY_API_KEY",
}


@dataclass(frozen=True)
class Provider:
    id: str
    name: str
    group: str = "providers"
    env_keys: tuple[str, ...] = ()
    prefix: str | None = None
    needs_base: bool = False
    default_base: str | None = None
    key_optional: bool = False
    live_catalog: str | None = None

    @property
    def model_prefix(self) -> str:
        return self.prefix if self.prefix is not None else self.id


@dataclass(frozen=True)
class Credentials:
    api_key: str | None = None
    api_base: str | None = None
    source: str = "stored"


PROVIDERS: tuple[Provider, ...] = (
    Provider(
        "vercel_ai_gateway",
        "Vercel AI Gateway",
        "popular",
        ("VERCEL_AI_GATEWAY_API_KEY", "AI_GATEWAY_API_KEY"),
        live_catalog="https://ai-gateway.vercel.sh/v1/models",
    ),
    Provider(
        "openrouter",
        "OpenRouter",
        "popular",
        ("OPENROUTER_API_KEY",),
        live_catalog="https://openrouter.ai/api/v1/models",
    ),
    Provider("anthropic", "Anthropic", "popular", ("ANTHROPIC_API_KEY",)),
    Provider("openai", "OpenAI", "popular", ("OPENAI_API_KEY",)),
    Provider(CHATGPT, "ChatGPT", "hidden"),
    Provider("gemini", "Google", "popular", ("GEMINI_API_KEY", "GOOGLE_API_KEY")),
    Provider("cerebras", "Cerebras", env_keys=("CEREBRAS_API_KEY",)),
    Provider("deepinfra", "DeepInfra", env_keys=("DEEPINFRA_API_KEY",)),
    Provider("deepseek", "DeepSeek", env_keys=("DEEPSEEK_API_KEY",)),
    Provider("fireworks_ai", "Fireworks AI", env_keys=("FIREWORKS_AI_API_KEY",)),
    Provider("groq", "Groq", env_keys=("GROQ_API_KEY",)),
    Provider("hyperbolic", "Hyperbolic", env_keys=("HYPERBOLIC_API_KEY",)),
    Provider("mistral", "Mistral", env_keys=("MISTRAL_API_KEY",)),
    Provider("moonshot", "Moonshot AI", env_keys=("MOONSHOT_API_KEY",)),
    Provider("nebius", "Nebius", env_keys=("NEBIUS_API_KEY",)),
    Provider("novita", "Novita AI", env_keys=("NOVITA_API_KEY",)),
    Provider("nvidia_nim", "NVIDIA NIM", env_keys=("NVIDIA_NIM_API_KEY",)),
    Provider("perplexity", "Perplexity", env_keys=("PERPLEXITYAI_API_KEY",)),
    Provider("together_ai", "Together AI", env_keys=("TOGETHERAI_API_KEY",)),
    Provider("xai", "xAI", env_keys=("XAI_API_KEY",)),
    Provider("zai", "Z.AI", env_keys=("ZAI_API_KEY",)),
    Provider(
        "ollama",
        "Ollama",
        "local",
        needs_base=True,
        default_base="http://localhost:11434",
        key_optional=True,
    ),
    Provider(
        "lm_studio",
        "LM Studio",
        "local",
        prefix="openai",
        needs_base=True,
        default_base="http://localhost:1234/v1",
        key_optional=True,
    ),
    Provider(
        CUSTOM,
        "OpenAI-compatible",
        "local",
        prefix="openai",
        needs_base=True,
        key_optional=True,
    ),
)
_BY_ID = {provider.id: provider for provider in PROVIDERS}
_SEARCH_SERVICES = (("exa", "Exa"), ("perplexity", "Perplexity"))

_shell_env: dict[str, str] | None = None
_live_catalogs: dict[str, list[str]] = {}


def _shell() -> dict[str, str]:
    global _shell_env  # noqa: PLW0603
    if _shell_env is None:
        _shell_env = dict(os.environ)
    return _shell_env


def get_provider(provider_id: str) -> Provider:
    provider = _BY_ID.get(provider_id)
    if provider is None:
        raise ValueError(f"Unknown provider: {provider_id}")
    return provider


def infer_provider(model: str) -> str | None:
    name = model.strip()
    if not name:
        return None
    if codex.subscription_model(name):
        return CHATGPT
    if "/" not in name:
        return "openai"
    head = name.split("/", 1)[0].lower()
    if head in _BY_ID and head != CUSTOM:
        return head
    return None


def _stored_providers(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    stored = document.get("providers")
    if not isinstance(stored, dict):
        return {}
    return {str(k): v for k, v in stored.items() if isinstance(v, dict)}


def _model_state(document: dict[str, Any]) -> dict[str, Any]:
    state = document.get("models")
    return state if isinstance(state, dict) else {}


def _entries(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    entries = []
    for item in value:
        if not isinstance(item, dict):
            continue
        provider, model = item.get("provider"), item.get("model")
        if isinstance(provider, str) and isinstance(model, str) and provider and model:
            entries.append({"provider": provider, "model": model})
    return entries


def current_selection() -> dict[str, str] | None:
    model = (load_settings().llm.model or "").strip()
    if not model:
        return None
    current = _entries([_model_state(read_config_document()).get("current")])
    if current and current[0]["model"] == model:
        return current[0]
    return {"provider": infer_provider(model) or "", "model": model}


def credentials(provider_id: str) -> Credentials | None:
    provider = get_provider(provider_id)
    if provider.id == CHATGPT:
        return Credentials(source="subscription") if codex.is_authenticated() else None
    stored = _stored_providers(read_config_document()).get(provider.id)
    if stored is not None:
        key, base = stored.get("api_key"), stored.get("api_base")
        return Credentials(
            api_key=key if isinstance(key, str) and key else None,
            api_base=base if isinstance(base, str) and base else None,
        )
    shell = _shell()
    for env_key in provider.env_keys:
        if shell.get(env_key):
            return Credentials(api_key=shell[env_key], source="environment")
    if provider.id == "ollama" and shell.get("OLLAMA_API_BASE"):
        return Credentials(api_base=shell["OLLAMA_API_BASE"], source="environment")
    llm = load_settings().llm
    current = current_selection()
    if current and current["provider"] == provider.id and (llm.api_key or llm.api_base):
        return Credentials(api_key=llm.api_key, api_base=llm.api_base, source="environment")
    return None


def connect(provider_id: str, *, api_key: str | None = None, api_base: str | None = None) -> None:
    provider = get_provider(provider_id)
    if provider.id == CHATGPT:
        raise ValueError("ChatGPT connects by signing in")
    key = (api_key or "").strip()
    base = (api_base or "").strip() or (provider.default_base or "")
    if not key and not provider.key_optional:
        raise ValueError("API key is required")
    if provider.needs_base and not base:
        raise ValueError("Base URL is required")
    if base and not base.startswith(("http://", "https://")):
        raise ValueError("Base URL must start with http:// or https://")
    document = read_config_document()
    stored = _stored_providers(document)
    stored[provider.id] = {"api_key": key or None, "api_base": base or None}
    document["providers"] = stored
    write_config_document(document)
    _live_catalogs.pop(provider.id, None)


def disconnect(provider_id: str) -> None:
    """Remove a provider's saved connection, and the saved model when it runs on that provider.

    The OpenAI entry covers both of its methods, so it also signs out of ChatGPT.
    """
    provider = get_provider(provider_id)
    removed = {provider.id}
    if provider.id in (CHATGPT, "openai"):
        codex.logout()
    if provider.id == "openai":
        removed.add(CHATGPT)
    document = read_config_document()
    stored = _stored_providers(document)
    stored.pop(provider.id, None)
    document["providers"] = stored
    current = current_selection()
    selected = current is not None and current["provider"] in removed
    if selected:
        block = document.get("env")
        block = {str(k).upper(): v for k, v in block.items()} if isinstance(block, dict) else {}
        shell = _shell()
        for alias in ("STRIX_LLM", *_API_KEY_ALIASES, *_API_BASE_ALIASES):
            block.pop(alias, None)
            if alias in shell:
                os.environ[alias] = shell[alias]
            else:
                os.environ.pop(alias, None)
        document["env"] = block
        _model_state(document).pop("current", None)
    write_config_document(document)
    _live_catalogs.pop(provider.id, None)
    if selected:
        reload_settings()
        from strix.config.models import reset_sdk_model_defaults

        reset_sdk_model_defaults()


def _keep_legacy_connection(
    document: dict[str, Any],
    block: dict[str, Any],
    previous: dict[str, str] | None,
    next_provider: str,
) -> None:
    """Save a connection that exists only in the ``env`` block before a switch overwrites it."""
    provider_id = previous["provider"] if previous else ""
    if provider_id in ("", CHATGPT, next_provider) or provider_id not in _BY_ID:
        return
    stored = _stored_providers(document)
    if provider_id in stored:
        return
    key = next((block[alias] for alias in _API_KEY_ALIASES if block.get(alias)), None)
    base = next((block[alias] for alias in _API_BASE_ALIASES if block.get(alias)), None)
    if not key and not base:
        return
    stored[provider_id] = {"api_key": key, "api_base": base}
    document["providers"] = stored


def select_model(provider_id: str, model: str) -> None:
    provider = get_provider(provider_id)
    name = model.strip()
    if not name:
        raise ValueError("Model is required")
    _shell()  # snapshot the launch environment before this call rewrites it
    creds = credentials(provider.id)
    if creds is None:
        raise ValueError(f"{provider.name} is not connected")
    api_key = creds.api_key
    if not api_key and provider.model_prefix == "openai":
        # The OpenAI client refuses to start without a key, even for a keyless server.
        api_key = _KEYLESS_PLACEHOLDER
    values = {
        "STRIX_LLM": name,
        "LLM_API_KEY": api_key,
        "LLM_API_BASE": creds.api_base,
    }
    previous = current_selection()
    document = read_config_document()
    block = document.get("env")
    block = {str(k).upper(): v for k, v in block.items()} if isinstance(block, dict) else {}
    _keep_legacy_connection(document, block, previous, provider.id)
    for alias in (*_API_KEY_ALIASES, *_API_BASE_ALIASES):
        block.pop(alias, None)
        os.environ.pop(alias, None)
    for alias, value in values.items():
        if value:
            block[alias] = value
            os.environ[alias] = value
    document["env"] = block
    entry = {"provider": provider.id, "model": name}
    state = _model_state(document)
    recent = [item for item in _entries(state.get("recent")) if item != entry]
    state["recent"] = [entry, *recent][:_RECENT_LIMIT]
    state["current"] = entry
    document["models"] = state
    write_config_document(document)
    reload_settings()
    from strix.config.models import reset_sdk_model_defaults

    reset_sdk_model_defaults()


def toggle_favorite(provider_id: str, model: str) -> bool:
    entry = {"provider": get_provider(provider_id).id, "model": model.strip()}
    document = read_config_document()
    state = _model_state(document)
    favorites = _entries(state.get("favorite"))
    added = entry not in favorites
    state["favorite"] = (
        [*favorites, entry] if added else [item for item in favorites if item != entry]
    )
    document["models"] = state
    write_config_document(document)
    return added


def set_setting(name: str, value: str | None) -> None:
    alias = SETTING_ALIASES.get(name)
    if alias is None:
        raise ValueError(f"Unknown setting: {name}")
    text = (value or "").strip()
    if name == "effort" and text not in EFFORTS:
        raise ValueError(f"Effort must be one of: {', '.join(EFFORTS)}")
    _shell()
    document = read_config_document()
    block = document.get("env")
    block = {str(k).upper(): v for k, v in block.items()} if isinstance(block, dict) else {}
    if text:
        block[alias] = text
        os.environ[alias] = text
    else:
        block.pop(alias, None)
        os.environ.pop(alias, None)
    document["env"] = block
    write_config_document(document)
    reload_settings()


def _usable(model: str) -> bool:
    name = model.lower()
    if name.startswith("ft:") or _SNAPSHOT_SUFFIX.search(name):
        return False
    return not any(part in name for part in _SKIPPED_MODEL_PARTS)


def _version_key(model: str) -> list[tuple[int, int | str]]:
    return [
        (1, int(part)) if part.isdigit() else (0, part)
        for part in re.split(r"(\d+)", model.lower())
    ]


def _catalog_models(provider: Provider) -> list[str]:
    import litellm

    prefix = f"{provider.model_prefix}/"
    models = []
    for key, entry in litellm.model_cost.items():
        if entry.get("litellm_provider") != provider.id:
            continue
        if entry.get("mode") not in ("chat", "responses"):
            continue
        if not entry.get("supports_function_calling") or not _usable(key):
            continue
        models.append(key if key.startswith(prefix) else prefix + key)
    return sorted(set(models), key=_version_key, reverse=True)


def _get_json(url: str, api_key: str | None = None) -> Any:
    import httpx

    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    response = httpx.get(url, headers=headers, timeout=_CATALOG_TIMEOUT_S)
    response.raise_for_status()
    return response.json()


def _live_models(provider: Provider, creds: Credentials) -> list[str]:
    prefix = f"{provider.model_prefix}/"
    if provider.live_catalog:
        rows = _get_json(provider.live_catalog).get("data") or []
        usable = [
            row
            for row in rows
            if isinstance(row, dict)
            and isinstance(row.get("id"), str)
            and "tools" in (row.get("supported_parameters") or [])
        ]
        usable.sort(key=lambda row: row.get("created") or 0, reverse=True)
        return [prefix + row["id"] for row in usable]
    base = (creds.api_base or "").rstrip("/")
    if provider.id == "ollama":
        rows = _get_json(f"{base}/api/tags").get("models") or []
        return [prefix + row["name"] for row in rows if isinstance(row, dict) and row.get("name")]
    rows = _get_json(f"{base}/models", creds.api_key).get("data") or []
    return [prefix + row["id"] for row in rows if isinstance(row, dict) and row.get("id")]


def provider_models(provider_id: str) -> list[str]:
    provider = get_provider(provider_id)
    creds = credentials(provider.id)
    if creds is None:
        return []
    if provider.live_catalog or provider.needs_base:
        cached = _live_catalogs.get(provider.id)
        if cached is not None:
            return cached
        try:
            models = _live_models(provider, creds)
        except Exception:  # noqa: BLE001
            logger.debug("live model catalog unavailable for %s", provider.id, exc_info=True)
            models = []
        if models:
            _live_catalogs[provider.id] = models
            return models
        if provider.needs_base:
            return []
    return _catalog_models(provider)


def model_picker() -> dict[str, Any]:
    state = _model_state(read_config_document())
    providers = []
    for provider in PROVIDERS:
        if credentials(provider.id) is None:
            continue
        providers.append(
            {
                "id": provider.id,
                "name": provider.name,
                "prefix": provider.model_prefix,
                "models": provider_models(provider.id),
            }
        )
    return {
        "current": current_selection(),
        "recent": _entries(state.get("recent")),
        "favorite": _entries(state.get("favorite")),
        "providers": providers,
        "effort": load_settings().llm.reasoning_effort,
    }


def provider_directory() -> dict[str, Any]:
    integrations = load_settings().integrations
    groups: dict[str, list[dict[str, Any]]] = {"popular": [], "providers": [], "local": []}
    for provider in PROVIDERS:
        if provider.group not in groups:
            continue
        methods = [{"id": "api_key", "label": "API key"}]
        connected = credentials(provider.id) is not None
        if provider.id == "openai":
            methods.insert(0, {"id": CHATGPT, "label": "Sign in with ChatGPT"})
            connected = connected or credentials(CHATGPT) is not None
        groups[provider.group].append(
            {
                "id": provider.id,
                "name": provider.name,
                "connected": connected,
                "methods": methods,
                "needs_base": provider.needs_base,
                "default_base": provider.default_base or "",
                "key_optional": provider.key_optional,
            }
        )
    search = [
        {
            "id": service,
            "name": name,
            "connected": bool(getattr(integrations, f"{service}_api_key", None)),
        }
        for service, name in _SEARCH_SERVICES
    ]
    return {**groups, "search": search}
