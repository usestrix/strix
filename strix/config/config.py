import json
import os
from pathlib import Path
from typing import Any


class Config:
    """Configuration Manager for Strix."""

    # LLM Configuration
    strix_llm = "openai/gpt-5"
    llm_api_key = None
    llm_api_base = None
    openai_api_base = None
    litellm_base_url = None
    ollama_api_base = None
    strix_reasoning_effort = "high"
    llm_timeout = "300"
    llm_rate_limit_delay = "4.0"
    llm_rate_limit_concurrent = "1"

    # Tool & Feature Configuration
    perplexity_api_key = None
    strix_disable_browser = "false"

    # Runtime Configuration
    strix_image = "ghcr.io/usestrix/strix-sandbox:0.1.10"
    strix_runtime_backend = "docker"
    strix_sandbox_execution_timeout = "500"
    strix_sandbox_connect_timeout = "10"

    # Telemetry
    strix_telemetry = "1"

    @classmethod
    def _tracked_names(cls) -> list[str]:
        return [
            k
            for k, v in vars(cls).items()
            if not k.startswith("_") and k[0].islower() and (v is None or isinstance(v, str))
        ]

    @classmethod
    def tracked_vars(cls) -> list[str]:
        return [name.upper() for name in cls._tracked_names()]

    @classmethod
    def get(cls, name: str) -> str | None:
        env_name = name.upper()
        default = getattr(cls, name, None)
        return os.getenv(env_name, default)

    @classmethod
    def config_dir(cls) -> Path:
        return Path.home() / ".strix"

    @classmethod
    def config_file(cls) -> Path:
        return cls.config_dir() / "cli-config.json"

    @classmethod
    def load(cls) -> dict[str, Any]:
        path = cls.config_file()
        if not path.exists():
            return {}
        try:
            with path.open("r", encoding="utf-8") as f:
                data: dict[str, Any] = json.load(f)
                return data
        except (json.JSONDecodeError, OSError):
            return {}

    @classmethod
    def save(cls, config: dict[str, Any]) -> bool:
        try:
            cls.config_dir().mkdir(parents=True, exist_ok=True)
            with cls.config_file().open("w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
        except OSError:
            return False
        else:
            return True

    @classmethod
    def apply_saved(cls) -> dict[str, str]:
        saved = cls.load()
        env_vars = saved.get("env", {})
        applied = {}

        for var_name, var_value in env_vars.items():
            if var_name in cls.tracked_vars() and not os.getenv(var_name):
                os.environ[var_name] = var_value
                applied[var_name] = var_value

        return applied

    @classmethod
    def capture_current(cls) -> dict[str, Any]:
        env_vars = {}
        for var_name in cls.tracked_vars():
            value = os.getenv(var_name)
            if value:
                env_vars[var_name] = value
        return {"env": env_vars}

    @classmethod
    def save_current(cls) -> bool:
        existing = cls.load().get("env", {})
        current = cls.capture_current().get("env", {})
        merged = {**existing, **current}
        return cls.save({"env": merged})


def apply_saved_config() -> dict[str, str]:
    return Config.apply_saved()


def save_current_config() -> bool:
    return Config.save_current()
