import contextlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError


STRIX_API_BASE = "https://models.strix.ai/api/v1"


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _get_nested(config: dict[str, Any], path: str) -> Any:
    current: Any = config
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _set_nested(config: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    current = config
    for part in parts[:-1]:
        next_value = current.get(part)
        if not isinstance(next_value, dict):
            next_value = {}
            current[part] = next_value
        current = next_value
    current[parts[-1]] = value


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


class LLMSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    model: str | None = None
    api_key: str | None = None
    api_base: str | None = None
    openai_compatible_provider: str | None = None
    openai_api_base: str | None = None
    litellm_base_url: str | None = None
    ollama_api_base: str | None = None
    reasoning_effort: str = "high"
    max_retries: int = 5
    memory_compressor_timeout: int = 30
    timeout: int = 300


class FeatureSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    perplexity_api_key: str | None = None
    disable_browser: bool = False


class RuntimeSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    image: str = "ghcr.io/usestrix/strix-sandbox:0.1.13"
    backend: str = "docker"
    sandbox_execution_timeout: int = 120
    sandbox_connect_timeout: int = 10
    sandbox_mode: bool = False
    docker_host: str | None = None
    caido_api_token: str | None = None


class TelemetrySettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    enabled: bool = True
    otel_enabled: bool | None = None
    posthog_enabled: bool | None = None
    traceloop_base_url: str | None = None
    traceloop_api_key: str | None = None
    traceloop_headers: str | None = None


class APISettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    host: str = "127.0.0.1"
    port: int = 8787
    auth_token: str | None = None
    max_concurrent_tasks: int = 1
    enable_docs: bool = True
    stream_poll_interval_ms: int = 500


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    llm: LLMSettings = Field(default_factory=LLMSettings)
    features: FeatureSettings = Field(default_factory=FeatureSettings)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    telemetry: TelemetrySettings = Field(default_factory=TelemetrySettings)
    api: APISettings = Field(default_factory=APISettings)


class Config:
    """Structured configuration manager backed by JSON files only."""

    _config_file_override: Path | None = None
    _cached_config: AppConfig | None = None

    _LEGACY_ENV_TO_PATH = {
        "STRIX_LLM": "llm.model",
        "LLM_API_KEY": "llm.api_key",
        "LLM_API_BASE": "llm.api_base",
        "STRIX_OPENAI_COMPATIBLE_PROVIDER": "llm.openai_compatible_provider",
        "OPENAI_API_BASE": "llm.openai_api_base",
        "LITELLM_BASE_URL": "llm.litellm_base_url",
        "OLLAMA_API_BASE": "llm.ollama_api_base",
        "STRIX_REASONING_EFFORT": "llm.reasoning_effort",
        "STRIX_LLM_MAX_RETRIES": "llm.max_retries",
        "STRIX_MEMORY_COMPRESSOR_TIMEOUT": "llm.memory_compressor_timeout",
        "LLM_TIMEOUT": "llm.timeout",
        "PERPLEXITY_API_KEY": "features.perplexity_api_key",
        "STRIX_DISABLE_BROWSER": "features.disable_browser",
        "STRIX_IMAGE": "runtime.image",
        "STRIX_RUNTIME_BACKEND": "runtime.backend",
        "STRIX_SANDBOX_EXECUTION_TIMEOUT": "runtime.sandbox_execution_timeout",
        "STRIX_SANDBOX_CONNECT_TIMEOUT": "runtime.sandbox_connect_timeout",
        "STRIX_SANDBOX_MODE": "runtime.sandbox_mode",
        "DOCKER_HOST": "runtime.docker_host",
        "CAIDO_API_TOKEN": "runtime.caido_api_token",
        "STRIX_TELEMETRY": "telemetry.enabled",
        "STRIX_OTEL_TELEMETRY": "telemetry.otel_enabled",
        "STRIX_POSTHOG_TELEMETRY": "telemetry.posthog_enabled",
        "TRACELOOP_BASE_URL": "telemetry.traceloop_base_url",
        "TRACELOOP_API_KEY": "telemetry.traceloop_api_key",
        "TRACELOOP_HEADERS": "telemetry.traceloop_headers",
        "STRIX_API_HOST": "api.host",
        "STRIX_API_PORT": "api.port",
        "STRIX_API_AUTH_TOKEN": "api.auth_token",
        "STRIX_API_MAX_CONCURRENT_TASKS": "api.max_concurrent_tasks",
        "STRIX_API_ENABLE_DOCS": "api.enable_docs",
        "STRIX_API_STREAM_POLL_INTERVAL_MS": "api.stream_poll_interval_ms",
    }
    _CONFIG_KEY_PATHS = {
        "strix_llm": "llm.model",
        "llm_api_key": "llm.api_key",
        "llm_api_base": "llm.api_base",
        "llm_openai_compatible_provider": "llm.openai_compatible_provider",
        "openai_api_base": "llm.openai_api_base",
        "litellm_base_url": "llm.litellm_base_url",
        "ollama_api_base": "llm.ollama_api_base",
        "strix_reasoning_effort": "llm.reasoning_effort",
        "strix_llm_max_retries": "llm.max_retries",
        "strix_memory_compressor_timeout": "llm.memory_compressor_timeout",
        "llm_timeout": "llm.timeout",
        "perplexity_api_key": "features.perplexity_api_key",
        "strix_disable_browser": "features.disable_browser",
        "strix_image": "runtime.image",
        "strix_runtime_backend": "runtime.backend",
        "strix_sandbox_execution_timeout": "runtime.sandbox_execution_timeout",
        "strix_sandbox_connect_timeout": "runtime.sandbox_connect_timeout",
        "strix_sandbox_mode": "runtime.sandbox_mode",
        "docker_host": "runtime.docker_host",
        "caido_api_token": "runtime.caido_api_token",
        "strix_telemetry": "telemetry.enabled",
        "strix_otel_telemetry": "telemetry.otel_enabled",
        "strix_posthog_telemetry": "telemetry.posthog_enabled",
        "traceloop_base_url": "telemetry.traceloop_base_url",
        "traceloop_api_key": "telemetry.traceloop_api_key",
        "traceloop_headers": "telemetry.traceloop_headers",
        "api_host": "api.host",
        "api_port": "api.port",
        "api_auth_token": "api.auth_token",
        "api_max_concurrent_tasks": "api.max_concurrent_tasks",
        "api_enable_docs": "api.enable_docs",
        "api_stream_poll_interval_ms": "api.stream_poll_interval_ms",
    }
    _BOOL_PATHS = {
        "features.disable_browser",
        "runtime.sandbox_mode",
        "telemetry.enabled",
        "telemetry.otel_enabled",
        "telemetry.posthog_enabled",
        "api.enable_docs",
    }
    _INT_PATHS = {
        "llm.max_retries",
        "llm.memory_compressor_timeout",
        "llm.timeout",
        "runtime.sandbox_execution_timeout",
        "runtime.sandbox_connect_timeout",
        "api.port",
        "api.max_concurrent_tasks",
        "api.stream_poll_interval_ms",
    }

    @classmethod
    def tracked_vars(cls) -> list[str]:
        return sorted(cls._LEGACY_ENV_TO_PATH.keys())

    @classmethod
    def config_dir(cls) -> Path:
        return Path.home() / ".strix"

    @classmethod
    def legacy_config_file(cls) -> Path:
        return cls.config_dir() / "cli-config.json"

    @classmethod
    def config_file(cls) -> Path:
        if cls._config_file_override is not None:
            return cls._config_file_override
        return cls.config_dir() / "config.json"

    @classmethod
    def active_config_path(cls) -> Path:
        if cls._config_file_override is not None:
            return cls._config_file_override

        primary = cls.config_file()
        if primary.exists():
            return primary

        legacy = cls.legacy_config_file()
        if legacy.exists():
            return legacy

        return primary

    @classmethod
    def set_config_file(cls, path: Path) -> None:
        cls._config_file_override = path
        cls.reload()

    @classmethod
    def reload(cls) -> AppConfig:
        cls._cached_config = None
        return cls.load_model()

    @classmethod
    def _read_json_file(cls, path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        with path.open("r", encoding="utf-8") as file_obj:
            data = json.load(file_obj)
        if not isinstance(data, dict):
            raise ValueError("Config file must contain a JSON object")
        return data

    @classmethod
    def _coerce_legacy_value(cls, path: str, value: Any) -> Any:
        if value in ("", None):
            return None
        if path in cls._BOOL_PATHS:
            return _parse_bool(value)
        if path in cls._INT_PATHS:
            return int(value)
        return value

    @classmethod
    def _normalize_legacy_env(cls, env_data: dict[str, Any]) -> dict[str, Any]:
        normalized: dict[str, Any] = {}
        for raw_key, raw_value in env_data.items():
            if not isinstance(raw_key, str):
                continue
            path = cls._LEGACY_ENV_TO_PATH.get(raw_key.upper())
            if not path:
                continue
            value = cls._coerce_legacy_value(path, raw_value)
            if value is None:
                continue
            _set_nested(normalized, path, value)
        return normalized

    @classmethod
    def _normalize_dict(cls, data: dict[str, Any]) -> dict[str, Any]:
        normalized = AppConfig().model_dump(mode="python")
        body = dict(data)

        legacy_env = body.pop("env", None)
        if isinstance(legacy_env, dict):
            normalized = _deep_merge(normalized, cls._normalize_legacy_env(legacy_env))

        normalized = _deep_merge(normalized, body)
        return normalized

    @classmethod
    def _load_from_file(cls, path: Path) -> AppConfig:
        try:
            raw_data = cls._read_json_file(path)
        except FileNotFoundError:
            return AppConfig()
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in config file: {exc}") from exc

        normalized = cls._normalize_dict(raw_data)
        try:
            return AppConfig.model_validate(normalized)
        except ValidationError as exc:
            raise ValueError(f"Invalid config structure: {exc}") from exc

    @classmethod
    def validate_file(cls, path: Path) -> Path:
        cls._load_from_file(path)
        return path

    @classmethod
    def load_model(cls) -> AppConfig:
        if cls._cached_config is not None:
            return cls._cached_config

        primary = cls.config_file()
        if primary.exists():
            cls._cached_config = cls._load_from_file(primary)
            return cls._cached_config

        legacy = cls.legacy_config_file()
        if cls._config_file_override is None and legacy.exists():
            cls._cached_config = cls._load_from_file(legacy)
            return cls._cached_config

        cls._cached_config = AppConfig()
        return cls._cached_config

    @classmethod
    def load(cls) -> dict[str, Any]:
        return cls.load_model().model_dump(mode="python")

    @classmethod
    def get(cls, name: str) -> Any:
        path = cls._CONFIG_KEY_PATHS.get(name, name)
        return _get_nested(cls.load(), path)

    @classmethod
    def get_str(cls, name: str) -> str | None:
        value = cls.get(name)
        if value is None:
            return None
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)

    @classmethod
    def get_int(cls, name: str) -> int | None:
        value = cls.get(name)
        if value is None:
            return None
        return int(value)

    @classmethod
    def get_bool(cls, name: str) -> bool | None:
        value = cls.get(name)
        if value is None:
            return None
        return _parse_bool(value)

    @classmethod
    def _legacy_snapshot(cls) -> dict[str, str]:
        config = cls.load()
        snapshot: dict[str, str] = {}
        for env_key, path in cls._LEGACY_ENV_TO_PATH.items():
            value = _get_nested(config, path)
            if value is None:
                continue
            if isinstance(value, bool):
                snapshot[env_key] = "true" if value else "false"
            else:
                snapshot[env_key] = str(value)
        return snapshot

    @classmethod
    def save(cls, config: dict[str, Any]) -> bool:
        try:
            normalized = cls._normalize_dict(config)
            validated = AppConfig.model_validate(normalized)
            path = cls.config_file()
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w", encoding="utf-8") as file_obj:
                json.dump(validated.model_dump(mode="python"), file_obj, indent=2)
        except (OSError, ValidationError, ValueError):
            return False

        with contextlib.suppress(OSError):
            path.chmod(0o600)

        cls._cached_config = validated
        return True

    @classmethod
    def capture_current(cls) -> dict[str, Any]:
        return cls.load()

    @classmethod
    def save_current(cls) -> bool:
        return cls.save(cls.load())

    @classmethod
    def apply_saved(cls, force: bool = False) -> dict[str, str]:
        del force
        cls.reload()
        return cls._legacy_snapshot()


def apply_saved_config(force: bool = False) -> dict[str, str]:
    return Config.apply_saved(force=force)


def save_current_config() -> bool:
    return Config.save_current()


def resolve_llm_config() -> tuple[str | None, str | None, str | None, str | None]:
    model = Config.get_str("strix_llm")
    if not model:
        return None, None, None, None

    api_key = Config.get_str("llm_api_key")
    openai_compatible_provider = Config.get_str("llm_openai_compatible_provider")

    if model.startswith("strix/"):
        api_base: str | None = STRIX_API_BASE
    else:
        api_base = (
            Config.get_str("llm_api_base")
            or Config.get_str("openai_api_base")
            or Config.get_str("litellm_base_url")
            or Config.get_str("ollama_api_base")
        )

    return model, api_key, api_base, openai_compatible_provider
