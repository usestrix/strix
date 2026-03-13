import logging
import warnings

import litellm

from .config import LLMConfig
from .llm import LLM, LLMRequestFailedError


__all__ = [
    "LLM",
    "LLMConfig",
    "LLMRequestFailedError",
]

litellm.suppress_debug_info = True
litellm._logging._disable_debugging()
logging.getLogger("asyncio").setLevel(logging.CRITICAL)
logging.getLogger("asyncio").propagate = False
logging.getLogger("browser_use").setLevel(logging.CRITICAL)
logging.getLogger("browser_use").propagate = False
warnings.filterwarnings("ignore", category=RuntimeWarning, module="asyncio")
warnings.filterwarnings(
    "ignore", category=RuntimeWarning, module="litellm.llms.custom_httpx.async_client_cleanup"
)
