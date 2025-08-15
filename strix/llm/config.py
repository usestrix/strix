import os


class LLMConfig:
    def __init__(
        self,
        model_name: str | None = None,
        temperature: float = 0,
        enable_prompt_caching: bool = True,
        prompt_modules: list[str] | None = None,
    ):
        self.model_name = model_name or os.getenv("STRIX_LLM", "openai/gpt-5")

        if not self.model_name:
            raise ValueError("STRIX_LLM environment variable must be set and not empty")

        self.temperature = max(0.0, min(1.0, temperature))
        self.enable_prompt_caching = enable_prompt_caching
        self.prompt_modules = prompt_modules or []
