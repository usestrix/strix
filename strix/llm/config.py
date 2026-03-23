from typing import Any

from strix.config import Config
from strix.config.config import resolve_llm_config
from strix.llm.utils import resolve_strix_model


class LLMConfig:
    def __init__(
        self,
        model_name: str | None = None,
        enable_prompt_caching: bool = True,
        skills: list[str] | None = None,
        timeout: int | None = None,
        scan_mode: str = "deep",
        interactive: bool = False,
        reasoning_effort: str | None = None,
        system_prompt_context: dict[str, Any] | None = None,
    ):
        resolved_model, self.api_key, self.api_base = resolve_llm_config()
        self.model_name = model_name or resolved_model

        if not self.model_name:
            raise ValueError("STRIX_LLM environment variable must be set and not empty")

        api_model, canonical = resolve_strix_model(self.model_name)
        self.litellm_model: str = api_model or self.model_name
        self.canonical_model: str = canonical or self.model_name

        self.enable_prompt_caching = enable_prompt_caching
        self.skills = skills or []

        self.timeout = timeout or int(Config.get("llm_timeout") or "300")

        self.scan_mode = scan_mode if scan_mode in ["quick", "standard", "deep"] else "deep"

        self.interactive = interactive
        self.reasoning_effort = reasoning_effort
        self.system_prompt_context = system_prompt_context or {}
