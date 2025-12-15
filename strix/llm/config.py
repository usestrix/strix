import os


class LLMConfig:
    def __init__(
        self,
        model_name: str | None = None,
        enable_prompt_caching: bool = True,
        prompt_modules: list[str] | None = None,
        timeout: int | None = None,
        scan_mode: str = "deep",
    ):
        self.model_name = model_name or os.getenv("STRIX_LLM", "openai/gpt-5")

        if not self.model_name:
            raise ValueError("STRIX_LLM environment variable must be set and not empty")

        self.enable_prompt_caching = enable_prompt_caching
        self.prompt_modules = prompt_modules or []

        self.timeout = timeout or int(os.getenv("LLM_TIMEOUT", "300"))

        self.scan_mode = scan_mode if scan_mode in ["quick", "standard", "deep"] else "deep"
