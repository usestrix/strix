import os

from strix.config import Config

from .executor import (
    execute_tool,
    execute_tool_invocation,
    execute_tool_with_validation,
    extract_screenshot_from_result,
    process_tool_invocations,
    remove_screenshot_from_result,
    validate_tool_availability,
)
from .registry import (
    ImplementedInClientSideOnlyError,
    get_tool_by_name,
    get_tool_names,
    get_tools_prompt,
    needs_agent_state,
    register_tool,
    tools,
)


SANDBOX_MODE = os.getenv("STRIX_SANDBOX_MODE", "false").lower() == "true"


def _is_browser_disabled() -> bool:
    if os.getenv("STRIX_DISABLE_BROWSER", "").lower() == "true":
        return True
    val: str = Config.load().get("env", {}).get("STRIX_DISABLE_BROWSER", "")
    return str(val).lower() == "true"


DISABLE_BROWSER = _is_browser_disabled()


def _has_perplexity_api() -> bool:
    if os.getenv("PERPLEXITY_API_KEY"):
        return True
    return bool(Config.load().get("env", {}).get("PERPLEXITY_API_KEY"))


if not SANDBOX_MODE:
    from .agents_graph import *  # noqa: F403

    if not DISABLE_BROWSER:
        from .browser import *  # noqa: F403
    from .file_edit import *  # noqa: F403
    from .finish import *  # noqa: F403
    from .notes import *  # noqa: F403
    from .proxy import *  # noqa: F403
    from .python import *  # noqa: F403
    from .reporting import *  # noqa: F403
    from .terminal import *  # noqa: F403
    from .thinking import *  # noqa: F403
    from .todo import *  # noqa: F403

    if _has_perplexity_api():
        from .web_search import *  # noqa: F403
else:
    if not DISABLE_BROWSER:
        from .browser import *  # noqa: F403
    from .file_edit import *  # noqa: F403
    from .proxy import *  # noqa: F403
    from .python import *  # noqa: F403
    from .terminal import *  # noqa: F403

__all__ = [
    "ImplementedInClientSideOnlyError",
    "execute_tool",
    "execute_tool_invocation",
    "execute_tool_with_validation",
    "extract_screenshot_from_result",
    "get_tool_by_name",
    "get_tool_names",
    "get_tools_prompt",
    "needs_agent_state",
    "process_tool_invocations",
    "register_tool",
    "remove_screenshot_from_result",
    "tools",
    "validate_tool_availability",
]
