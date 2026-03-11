import asyncio
import contextlib
import logging
import os
import time
from typing import Any, Literal

from strix.tools.registry import register_tool

from .browser_manager import (
    _BrowserSession,
    _close_session,
    _ensure_healthy_session,
    _get_session,
    _launch_browser,
    _launch_local_browser,
    _reinitialize_after_agent,
)


logger = logging.getLogger(__name__)

BrowserUseLocalAction = Literal[
    "launch",
    "run",
    "close",
    # Granular browser commands
    "open",
    "click",
    "type",
    "input",
    "scroll",
    "back",
    "screenshot",
    "state",
    "switch",
    "close_tab",
    "keys",
    "select",
    "eval",
    "extract",
    "hover",
    "dblclick",
    "rightclick",
    "cookies",
    "wait",
    "get",
]

# Actions that are handled by browser_commands (granular CDP control).
_GRANULAR_ACTIONS = frozenset(
    {
        "open",
        "click",
        "type",
        "input",
        "scroll",
        "back",
        "screenshot",
        "state",
        "switch",
        "close_tab",
        "keys",
        "select",
        "eval",
        "extract",
        "hover",
        "dblclick",
        "rightclick",
        "cookies",
        "wait",
        "get",
    }
)

# Hard timeout for a single browser task (seconds).
_TASK_TIMEOUT = 300


def _build_llm() -> Any:
    """Build a browser-use compatible LLM from the strix LLM config.

    Returns a ``ChatLiteLLM`` instance that routes to any provider via litellm.
    """
    from strix.config.config import resolve_llm_config

    from .llm import ChatLiteLLM

    model, api_key, api_base = resolve_llm_config()
    if not model:
        raise ValueError("STRIX_LLM environment variable must be set")

    return ChatLiteLLM(
        model=model,
        api_key=api_key or None,
        api_base=api_base or None,
    )


# ---------------------------------------------------------------------------
# Task execution helpers
# ---------------------------------------------------------------------------


def _is_websocket_error(exc: BaseException) -> bool:
    """Return True if the exception looks like a WebSocket / CDP disconnect."""
    # Check exception type hierarchy (websockets lib, ConnectionError, etc.)
    exc_type = type(exc).__name__.lower()
    if any(kw in exc_type for kw in ("connectionclosed", "websocket", "connectionerror")):
        return True

    msg = str(exc).lower()
    ws_keywords = (
        "websocket",
        "cdp",
        "not initialized",
        "not connected",
        "connection closed",
        "disconnected",
        "broken pipe",
        "connection reset",
        "eof occurred",
        "protocol error",
        "target closed",
        "session closed",
        "page closed",
        "browser has been closed",
        "browser was closed",
        "client is stopping",
        "no close frame",
        "close frame",
        "connection was closed",
        "invalid state",
    )
    return any(kw in msg for kw in ws_keywords)


async def _cleanup_agent(agent: Any) -> None:
    """Best-effort cleanup of a browser-use Agent after failure.

    browser-use's Agent may leave dangling asyncio tasks (CDP listeners,
    DOM observers) that produce "Future exception was never retrieved"
    warnings when the WebSocket is already dead.  This drains them.
    """
    # Agent may expose a close/stop/cleanup method.
    for method_name in ("close", "stop", "cleanup"):
        fn = getattr(agent, method_name, None)
        if not callable(fn):
            continue
        try:
            coro = fn()
            if asyncio.iscoroutine(coro):
                await asyncio.wait_for(coro, timeout=5)
        except Exception:  # noqa: BLE001
            logger.debug("Agent %s() cleanup failed", method_name, exc_info=True)
        else:
            return

    # Fallback: try to close the browser context the agent was using,
    # which cancels its internal CDP subscriptions.
    browser_ctx = getattr(agent, "browser_context", None)
    if browser_ctx is not None:
        close_fn = getattr(browser_ctx, "close", None)
        if callable(close_fn):
            with contextlib.suppress(Exception):
                coro = close_fn()
                if asyncio.iscoroutine(coro):
                    await asyncio.wait_for(coro, timeout=5)


async def _run_agent_task(
    task: str,
    session: _BrowserSession,
    *,
    return_fields: list[str] | None = None,
) -> dict[str, Any]:
    """Run a browser-use task on the session's browser with resilient reconnection.

    Lifecycle:
      1. Ensure the session is healthy (CDP alive, Browser fresh).
      2. Run the task.
      3. On WebSocket/CDP errors, invalidate the session and retry once.
      4. On any terminal failure, mark the session so the next call refreshes.
    """
    from browser_use import Agent

    session.task_count += 1
    task_num = session.task_count

    logger.info(
        "Task #%d for session (cdp=%s, ws=%s, age=%.1fs, failures=%d): %.200s",
        task_num,
        session.cdp_url,
        session.ws_url,
        session.age,
        session.consecutive_failures,
        task,
    )

    # --- Pre-flight health check (with recovery) ---
    preflight_err = await _ensure_healthy_session(session, task_num)
    if preflight_err:
        session.consecutive_failures += 1
        return {"error": preflight_err, "is_running": False}

    # --- Execute (with one automatic retry on WebSocket disconnect) ---
    max_attempts = 2
    last_error: str = ""

    for attempt in range(1, max_attempts + 1):
        llm = _build_llm()
        agent = Agent(task=task, llm=llm, browser=session.browser, flash_mode=True)

        try:
            result = await asyncio.wait_for(agent.run(), timeout=_TASK_TIMEOUT)
        except TimeoutError:
            logger.exception(
                "Task #%d timed out after %ds (attempt %d)",
                task_num,
                _TASK_TIMEOUT,
                attempt,
            )
            await _cleanup_agent(agent)
            # Timeout leaves the Browser in an unknown state — invalidate.
            session.invalidated = True
            session.consecutive_failures += 1
            return {
                "error": f"Browser task timed out after {_TASK_TIMEOUT}s",
                "is_running": False,
            }
        except Exception as exc:
            logger.exception(
                "Task #%d raised exception (attempt %d)",
                task_num,
                attempt,
            )
            await _cleanup_agent(agent)
            last_error = str(exc)

            if _is_websocket_error(exc) and attempt < max_attempts:
                logger.warning(
                    "Task #%d: WebSocket/CDP error — refreshing and retrying...",
                    task_num,
                )
                # Force-refresh the session and retry the task.
                session.invalidated = True
                refresh_err = await _ensure_healthy_session(session, task_num)
                if refresh_err:
                    session.consecutive_failures += 1
                    return {"error": refresh_err, "is_running": False}
                continue  # retry

            # Non-retryable error or final attempt.
            session.consecutive_failures += 1
            # If it smells like a connection issue, invalidate for next call.
            if _is_websocket_error(exc):
                session.invalidated = True
            return {"error": f"Browser task failed: {exc}", "is_running": False}

        # --- Success path ---
        interpreted = _interpret_agent_result(result, return_fields=return_fields)

        if "error" in interpreted:
            error_msg = str(interpreted["error"])
            logger.warning("Task #%d failed: %s", task_num, error_msg)

            # If the agent reported a CDP/WS error, retry once.
            if _is_websocket_error(Exception(error_msg)) and attempt < max_attempts:
                logger.warning(
                    "Task #%d: agent result contains WebSocket error — refreshing and retrying...",
                    task_num,
                )
                session.invalidated = True
                refresh_err = await _ensure_healthy_session(session, task_num)
                if refresh_err:
                    session.consecutive_failures += 1
                    return {"error": refresh_err, "is_running": False}
                continue  # retry

            session.consecutive_failures += 1
            if _is_websocket_error(Exception(error_msg)):
                session.invalidated = True
            return interpreted

        # Task succeeded — reset failure counter.
        session.consecutive_failures = 0
        result_preview = str(interpreted.get("result", ""))[:200]
        logger.info("Task #%d succeeded: %s", task_num, result_preview)
        return interpreted

    # Should not reach here, but just in case:
    session.consecutive_failures += 1
    return {
        "error": f"Browser task failed after {max_attempts} attempts: {last_error}",
        "is_running": False,
    }


_JSON_PRIMITIVES = str | int | float | bool | None


def _json_safe(value: Any) -> Any:
    """Coerce a value into a JSON-serialisable form."""
    if isinstance(value, _JSON_PRIMITIVES):
        return value
    if isinstance(value, list):
        return [v if isinstance(v, _JSON_PRIMITIVES) else str(v) for v in value]
    return str(value)


_HISTORY_ACCESSORS: dict[str, str] = {
    "urls": "urls",
    "screenshot_paths": "screenshot_paths",
    "screenshots": "screenshots",
    "action_names": "action_names",
    "extracted_content": "extracted_content",
    "errors": "errors",
    "model_actions": "model_actions",
    "model_outputs": "model_outputs",
    "last_action": "last_action",
    "final_result": "final_result",
    "is_done": "is_done",
    "has_errors": "has_errors",
    "model_thoughts": "model_thoughts",
    "action_results": "action_results",
    "action_history": "action_history",
    "number_of_steps": "number_of_steps",
    "total_duration_seconds": "total_duration_seconds",
}


def _interpret_agent_result(
    result: Any,
    return_fields: list[str] | None = None,
) -> dict[str, Any]:
    """Inspect an ``AgentHistoryList`` and return a success or error dict.

    If the browser-use agent encountered errors (CDP failures, navigation
    errors, etc.) this returns an ``{"error": ...}`` dict so the calling
    strix agent treats the task as failed rather than succeeded.

    When *return_fields* is provided, the requested history accessors are
    included in the response under a ``"fields"`` key.
    """
    # Collect errors reported by the browser-use agent.
    errors: list[str] = []
    try:
        if hasattr(result, "has_errors") and result.has_errors():
            errors = [e for e in result.errors() if e is not None]
    except Exception as exc:  # noqa: BLE001
        logger.debug("Error checking agent errors: %s", exc)

    # Determine whether the agent considers the task successful.
    success: bool | None = None
    try:
        if hasattr(result, "is_successful"):
            success = result.is_successful()
    except Exception as exc:  # noqa: BLE001
        logger.debug("Error checking agent success: %s", exc)

    # Extract the final content the agent produced.
    final_result: str | None = None
    try:
        if hasattr(result, "final_result"):
            final_result = result.final_result()
    except Exception as exc:  # noqa: BLE001
        logger.debug("Error extracting final_result: %s", exc)

    logger.debug(
        "Agent result interpretation: errors=%d, success=%s, has_final_result=%s, result_type=%s",
        len(errors),
        success,
        final_result is not None,
        type(result).__name__,
    )

    # If there are errors AND the agent didn't explicitly mark itself as
    # successful, treat as failure and surface the errors.
    if errors and success is not True:
        error_summary = "; ".join(errors)
        return {"error": error_summary, "is_running": False}

    # If the agent explicitly reported failure (is_done=True, success=False).
    if success is False:
        return {
            "error": final_result or "Browser task failed (agent reported failure)",
            "is_running": False,
        }

    out: dict[str, Any] = {
        "message": "Task completed",
        "result": final_result or str(result),
        "is_running": False,
    }

    # Attach optional fields requested by the caller.
    if return_fields:
        fields: dict[str, Any] = {}
        available = ", ".join(sorted(_HISTORY_ACCESSORS))
        for field in return_fields:
            accessor = _HISTORY_ACCESSORS.get(field)
            if accessor is None:
                fields[field] = f"unknown field (available: {available})"
                continue
            try:
                attr = getattr(result, accessor, None)
                value = attr() if callable(attr) else attr
                fields[field] = _json_safe(value)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Error extracting field %s: %s", field, exc)
                fields[field] = f"error: {exc}"
        out["fields"] = fields

    return out


# ---------------------------------------------------------------------------
# CDP URL resolution
# ---------------------------------------------------------------------------


def _resolve_cdp_url(agent_state: Any) -> tuple[str, str]:
    """Extract the CDP URL and auth token from agent_state's sandbox_info.

    The sandbox container runs Chromium with ``--remote-debugging-port``
    and the Docker runtime maps it to an ephemeral host port stored in
    ``sandbox_info["browser_cdp_port"]``.  The auth token (shared with
    the tool server) is used to authenticate against the CDP auth proxy.

    Returns ``(cdp_url, auth_token)``.
    """
    if not hasattr(agent_state, "sandbox_info") or not agent_state.sandbox_info:
        raise ValueError(
            "agent_state must have sandbox_info with browser_cdp_port. "
            "Ensure the sandbox is initialized before launching the browser. "
            f"agent_state type={type(agent_state).__name__}, "
            f"has sandbox_info={hasattr(agent_state, 'sandbox_info')}"
        )

    sandbox_info = agent_state.sandbox_info
    cdp_port = sandbox_info.get("browser_cdp_port")
    if not cdp_port:
        raise ValueError(
            "sandbox_info is missing browser_cdp_port. "
            "The sandbox container may not have Chromium CDP enabled. "
            f"Available keys: {list(sandbox_info.keys())}"
        )

    auth_token: str = sandbox_info.get("auth_token", "")

    # Resolve the Docker host (same logic used by the tool server URL).
    docker_host = os.getenv("DOCKER_HOST", "")
    if docker_host:
        from urllib.parse import urlparse

        parsed = urlparse(docker_host)
        if parsed.scheme in ("tcp", "http", "https") and parsed.hostname:
            host = parsed.hostname
        else:
            host = "127.0.0.1"
    else:
        host = "127.0.0.1"

    cdp_url = f"http://{host}:{cdp_port}"
    logger.info(
        "Resolved CDP URL: %s (port=%s, host=%s, sandbox_id=%s)",
        cdp_url,
        cdp_port,
        host,
        sandbox_info.get("workspace_id", "?")[:12],
    )
    return cdp_url, auth_token


# ---------------------------------------------------------------------------
# Tool entry-point
# ---------------------------------------------------------------------------


@register_tool(sandbox_execution=False)
async def browser_actions(
    action: BrowserUseLocalAction,
    task: str | None = None,
    use_local: bool = False,
    profile_directory: str | None = None,
    # --- Granular command parameters ---
    url: str | None = None,
    index: int | None = None,
    text: str | None = None,
    value: str | None = None,
    selector: str | None = None,
    keys: str | None = None,
    js: str | None = None,
    direction: str | None = None,
    amount: int | None = None,
    tab: int | None = None,
    x: float | None = None,
    y: float | None = None,
    full: bool = False,
    path: str | None = None,
    subcommand: str | None = None,
    query: str | None = None,
    name: str | None = None,
    domain: str | None = None,
    file: str | None = None,
    timeout: int | None = None,
    state: str | None = None,
    secure: bool = False,
    http_only: bool = False,
    same_site: str | None = None,
    expires: float | None = None,
    return_fields: list[str] | None = None,
    *,
    agent_state: Any = None,
) -> dict[str, Any]:
    """Use a browser to perform web tasks via natural language or granular commands.

    This is a **blocking** tool — the calling agent will wait for the browser
    task to fully complete before receiving results.  The browser session
    persists across calls so state (cookies, auth, tabs) carries over.

    Two modes:

    **Sandboxed** (default): The browser runs inside the sandbox container
    (with Caido proxy for traffic interception) and is controlled remotely
    via CDP.  Requires ``agent_state`` with ``sandbox_info``.

    **Local** (``use_local=True``): Uses the system Chrome installation
    directly via ``Browser.from_system_chrome()``.  No sandbox required.
    Preserves login sessions, cookies, and extensions.  You may need to
    fully close Chrome before launching.  Optionally pass
    ``profile_directory`` (e.g. ``"Profile 1"``, ``"Default"``) to select
    a specific Chrome profile.

    Actions:
      launch      - Connect to the browser.  MUST be called first.
      run         - Execute a natural-language browser task (requires ``task``).
      close       - Shut down the browser session.
      open        - Navigate to a URL (requires ``url``).
      click       - Click an element by ``index`` or coordinates (``x``, ``y``).
      type        - Insert text at the cursor (requires ``text``).
      input       - Click an element and type into it (``index`` + ``text``).
      scroll      - Scroll the page (``direction``, ``amount``).
      back        - Navigate back.
      screenshot  - Capture a screenshot (``full``, ``path``).
      state       - Get the current page DOM state.
      switch      - Switch to a tab by index (``tab``).
      close_tab   - Close a tab (``tab``).
      keys        - Send keyboard keys (``keys``).
      select      - Select a dropdown option (``index`` + ``value``).
      eval        - Execute JavaScript (``js``).
      extract     - Extract information (requires agent mode — use ``run``).
      hover       - Hover over an element (``index``).
      dblclick    - Double-click an element (``index``).
      rightclick  - Right-click an element (``index``).
      cookies     - Cookie operations (``subcommand``: get/set/clear/export/import).
      wait        - Wait for element/text (``subcommand``: selector/text).
      get         - Get page info (``subcommand``: title/html/text/value/attributes/bbox).
    """
    try:
        from strix.tools.context import get_current_agent_id

        agent_id = get_current_agent_id()
        logger.info(
            "browser_actions called: action=%s, agent_id=%s, has_task=%s, "
            "has_agent_state=%s, use_local=%s, profile_directory=%s",
            action,
            agent_id,
            task is not None,
            agent_state is not None,
            use_local,
            profile_directory,
        )

        if action == "launch":
            if use_local:
                session = await _launch_local_browser(agent_id, profile_directory)
                return {
                    "message": "Local browser launched and ready",
                    "mode": "local",
                    "profile_directory": session.profile_directory or "auto",
                    "is_running": True,
                }
            cdp_url, auth_token = _resolve_cdp_url(agent_state)
            session = await _launch_browser(cdp_url, agent_id, auth_token)
            # Strip auth token from the ws_url before returning — the
            # token is a secret and must not leak to the calling agent.
            import re

            safe_ws = re.sub(r"[?&]token=[^&]+", "", session.ws_url)
            return {
                "message": "Browser launched and ready",
                "mode": "sandboxed",
                "cdp_url": session.cdp_url,
                "ws_url": safe_ws,
                "is_running": True,
            }

        if action == "close":
            await _close_session(agent_id)
            return {"message": "Browser closed", "is_running": False}

        if action == "run":
            if not task:
                raise ValueError("task parameter is required for run action")  # noqa: TRY301
            session = _get_session(agent_id)
            logger.info(
                "Starting task for agent %s (uptime=%.1fs, tasks=%d, local=%s): %.120s",
                agent_id,
                time.monotonic() - session.created_at,
                session.task_count,
                session.local,
                task,
            )
            result = await _run_agent_task(task, session, return_fields=return_fields)
            logger.info("Browser task completed for agent %s", agent_id)

            # Agent.run() calls browser_session.kill() which destroys the
            # CDP client and event bus.  Re-create the Browser so subsequent
            # granular commands (state, eval, click, …) have a working session.
            try:
                await _reinitialize_after_agent(session)
            except Exception:  # noqa: BLE001
                logger.warning(
                    "Failed to reinitialize session after agent run for %s",
                    agent_id,
                    exc_info=True,
                )

            return result

        if action in _GRANULAR_ACTIONS:
            session = _get_session(agent_id)
            from .browser_commands import handle_command

            return await handle_command(
                action,
                session.browser,
                url=url,
                index=index,
                text=text,
                value=value,
                selector=selector,
                keys=keys,
                js=js,
                direction=direction,
                amount=amount,
                tab=tab,
                x=x,
                y=y,
                full=full,
                path=path,
                subcommand=subcommand,
                query=query,
                name=name,
                domain=domain,
                file=file,
                timeout=timeout,
                state=state,
                secure=secure,
                http_only=http_only,
                same_site=same_site,
                expires=expires,
            )

        raise ValueError(f"Unknown action: {action}")  # noqa: TRY301

    except Exception as error:
        logger.exception(
            "browser_actions error: action=%s",
            action,
        )
        return {"error": str(error), "is_running": False}
