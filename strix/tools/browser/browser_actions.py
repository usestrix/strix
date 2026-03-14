import asyncio
import base64
import logging
import re
from functools import partial
from typing import Any, Literal

from browser_use import Agent
from browser_use.tools.service import Tools

from strix.tools.registry import register_tool

from .browser_manager import (
    BrowserSession,
    _close_session,
    _get_session,
    _launch_browser,
    _launch_local_browser,
)


logger = logging.getLogger(__name__)

BrowserUseLocalAction = Literal[
    "launch",
    "run",
    "close_browser",
    "navigate",
    "go_back",
    "wait",
    "click",
    "input",
    "scroll",
    "find_text",
    "send_keys",
    "extract",
    "search_page",
    "find_elements",
    "screenshot",
    "dropdown_options",
    "select_dropdown",
    "evaluate",
    "switch",
    "close_tab",
]

_TASK_TIMEOUT = 300


def _build_llm(metadata: dict[str, Any] | None = None) -> tuple[Any, bool]:
    import litellm

    from strix.config.config import resolve_llm_config

    from .litellm.chat import ChatLiteLLM

    model, api_key, api_base = resolve_llm_config()
    if not model:
        raise ValueError("STRIX_LLM environment variable must be set")

    return ChatLiteLLM(
        model=model,
        api_key=api_key,
        api_base=api_base,
        metadata=metadata,
    ), litellm.supports_vision(model)


def _resolve_cdp_url(agent_state: Any) -> tuple[str, str]:
    info = agent_state.sandbox_info
    api_url = info.get("api_url")
    if not api_url:
        raise ValueError("Missing api_url in sandbox_info")

    return api_url, info.get("auth_token", "")


async def _execute_task(session: BrowserSession, operation: Any, desc: str) -> dict[str, Any]:
    session.task_count += 1
    logger.info("Task #%d: %s", session.task_count, desc[:200])

    try:
        result = await asyncio.wait_for(operation(), timeout=_TASK_TIMEOUT)
        return (
            result
            if isinstance(result, dict)
            else {
                "result": result,
                "is_running": False,
            }
        )
    except TimeoutError:
        return {
            "error": f"Timeout after {_TASK_TIMEOUT}s",
            "is_running": False,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "error": f"Failed: {exc}",
            "is_running": False,
        }


async def _run_browser_agent(
    session: BrowserSession,
    task: str,
    return_fields: list[str] | None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    llm, vision = _build_llm(metadata=metadata)

    # [monkeypatch] prevent browseruse from killing the cdp connection after execution
    session.browser.browser_profile.keep_alive = True

    agent: Any = Agent(
        task=task,
        llm=llm,
        browser=session.browser,
        flash_mode=True,
        use_vision=vision,
    )

    # browseruse's setup_logging() adds a StreamHandler and disables propagation;
    # undo that so logs flow to our root file handler instead of the console
    for _name in ("browser_use", "bubus"):
        _bl = logging.getLogger(_name)
        _bl.handlers = [
            h
            for h in _bl.handlers
            if not isinstance(h, logging.StreamHandler) or isinstance(h, logging.FileHandler)
        ]
        _bl.propagate = True

    async def log_step(step: Any) -> None:
        logger.info("Agent step completed: %s", step)

    result = await agent.run(on_step_end=log_step)

    if hasattr(result, "is_successful") and not result.is_successful():
        final_result = (
            result.final_result() if callable(result.final_result) else result.final_result
        )
        return {
            "error": final_result or "Agent failed",
            "is_running": False,
        }

    final_result = (
        result.final_result()
        if hasattr(result, "final_result") and callable(result.final_result)
        else getattr(result, "final_result", str(result))
    )
    out = {
        "message": "Task completed",
        "result": final_result,
        "is_running": False,
    }

    if return_fields:
        fields = {f: getattr(result, f, None) for f in return_fields}
        out["fields"] = fields

    return out


async def _run_browser_tool(
    session: BrowserSession,
    action: str,
    params: dict[str, Any],
    metadata: dict[str, Any] | None = None,
) -> Any:
    if not session.browser.is_cdp_connected:
        await session.browser.start()

    llm, _ = _build_llm(metadata=metadata)
    tools = Tools()

    if session.local:
        from pathlib import Path

        from browser_use.filesystem.file_system import FileSystem

        base_dir = Path.cwd() / "browser_files"
        base_dir.mkdir(parents=True, exist_ok=True)
        file_system = FileSystem(base_dir=str(base_dir), create_default_files=False)
    else:

        class StubFileSystem:
            def __getattr__(self, name: str) -> Any:
                def soft_error(*args: Any, **kwargs: Any) -> dict[str, str]:
                    error_msg = f"File operation '{name}' not available in sandboxed environment"
                    logger.warning(error_msg)
                    return {"error": error_msg}

                return soft_error

        file_system = StubFileSystem()
        # [security] sandboxed browsers have no local filesystem access
        tools.exclude_action("upload_file")

    return await tools.registry.execute_action(
        action,
        params=params,
        browser_session=session.browser,
        page_extraction_llm=llm,
        file_system=file_system,
    )


async def populate_response(session: BrowserSession, response: dict[str, Any]) -> dict[str, Any]:
    try:
        screenshot = await session.browser.take_screenshot()
        screenshot_b64 = base64.b64encode(screenshot).decode("utf-8")
    except Exception as e:  # noqa: BLE001
        screenshot_b64 = None
        response["screenshot_error"] = str(e)

    try:
        title = await session.browser.get_current_page_title()
        url = await session.browser.get_current_page_url()
        all_tabs = await session.browser.get_tabs()
    except Exception as e:  # noqa: BLE001
        url = f"URL retrieval failed: {e}"
        title = "Title retrieval failed with same error"
        all_tabs = []

    try:
        vp = getattr(session.browser.browser_profile, "viewport", None)
        viewport = {
            "width": vp.width if vp else None,
            "height": vp.height if vp else None,
        }
    except Exception as e:  # noqa: BLE001
        viewport = {"error": f"Viewport retrieval failed: {e}"}

    return {
        **response,
        "screenshot": screenshot_b64,
        "url": url,
        "title": title,
        "viewport": viewport,
        "tabs": all_tabs,
    }


@register_tool(sandbox_execution=False)
async def browser_action(
    action: BrowserUseLocalAction,
    task: str | None = None,
    profile_directory: str | None = None,
    return_fields: list[str] | None = None,
    *,
    agent_state: Any = None,
    **kwargs: Any,
) -> dict[str, Any]:
    try:
        from strix.tools.context import get_current_agent_id

        agent_id = get_current_agent_id()

        metadata = {"litellm_session_id": agent_id}

        if action == "launch":
            has_sandbox = agent_state and getattr(agent_state, "sandbox_info", None)
            if not has_sandbox:
                session = await _launch_local_browser(agent_id, profile_directory)
                result = {
                    "message": "Local browser ready",
                    "mode": "local",
                    "profile": session.profile_directory or "auto",
                    "is_running": True,
                }
            else:
                cdp_url, auth_token = _resolve_cdp_url(agent_state)
                session = await _launch_browser(cdp_url, agent_id, auth_token)
                ws_url = re.sub(r"[?&]token=[^&]+", "", session.ws_url)
                result = {
                    "message": "Browser ready",
                    "mode": "sandboxed",
                    "ws_url": ws_url,
                    "is_running": True,
                }

            return result

        if action == "close_browser":
            await _close_session(agent_id)
            return {
                "message": "Browser closed",
                "is_running": False,
            }

        session = _get_session(agent_id)

        if action == "run":
            if not task:
                return {
                    "error": "task required for run action",
                    "is_running": False,
                }

            runner = partial(_run_browser_agent, session, task, return_fields, metadata)
            desc = task
        else:
            runner = partial(_run_browser_tool, session, action, kwargs, metadata)
            desc = f"{action}({list(kwargs.keys())[:3]})"

        task_output = await _execute_task(session, runner, desc)

        if "error" in task_output:
            return task_output

        return await populate_response(session, task_output)

    except Exception as error:
        logger.exception("browser_action error: %s", action)
        return {
            "error": str(error),
            "is_running": False,
        }
