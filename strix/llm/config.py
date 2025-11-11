import logging
import os

DEFAULT_LLM_TIMEOUT_SECONDS = 180
TIMEOUT_ENV_VAR = "STRIX_LLM_TIMEOUT"

logger = logging.getLogger(__name__)


def _coerce_timeout(value: int | str) -> int:
    if isinstance(value, str):
        value = value.strip()

    try:
        timeout_int = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Timeout must be a positive integer") from exc

    if timeout_int <= 0:
        raise ValueError("Timeout must be a positive integer")

    return timeout_int


def resolve_timeout(timeout: int | None = None) -> int:
    if timeout is not None:
        return _coerce_timeout(timeout)

    env_timeout = os.getenv(TIMEOUT_ENV_VAR)
    if env_timeout:
        try:
            return _coerce_timeout(env_timeout)
        except ValueError:
            logger.warning(
                "Invalid %s value '%s'; falling back to default of %s seconds",
                TIMEOUT_ENV_VAR,
                env_timeout,
                DEFAULT_LLM_TIMEOUT_SECONDS,
            )

    return DEFAULT_LLM_TIMEOUT_SECONDS


class LLMConfig:
    def __init__(
        self,
        model_name: str | None = None,
        temperature: float = 0,
        enable_prompt_caching: bool = True,
        prompt_modules: list[str] | None = None,
        timeout: int | None = None,
    ):
        self.model_name = model_name or os.getenv("STRIX_LLM", "openai/gpt-5")

        if not self.model_name:
            raise ValueError("STRIX_LLM environment variable must be set and not empty")

        self.temperature = max(0.0, min(1.0, temperature))
        self.enable_prompt_caching = enable_prompt_caching
        self.prompt_modules = prompt_modules or []
        self.timeout = resolve_timeout(timeout)
