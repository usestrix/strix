import asyncio
import atexit
import contextlib
import logging
import threading
import time
from typing import Any


logger = logging.getLogger(__name__)

# Maximum consecutive task failures before the session is forcibly invalidated.
_MAX_CONSECUTIVE_FAILURES = 3

# Maximum session age (seconds) before forcing a fresh Browser object on next task.
_MAX_SESSION_AGE = 1800  # 30 minutes

# CDP recovery: how long to wait for watchdog restart (seconds) and poll interval.
_CDP_RECOVERY_TIMEOUT = 60
_CDP_RECOVERY_INTERVAL = 2


# ---------------------------------------------------------------------------
# Persistent browser session
# ---------------------------------------------------------------------------
# browser-use's Agent.run() calls browser_session.start() internally, which
# is idempotent — it only connects to CDP if _cdp_client_root is None.
# We therefore do NOT call browser.start() during launch; we just create the
# Browser object with the CDP URL and let Agent.run() manage the connection
# on the caller's event loop.
# ---------------------------------------------------------------------------


class _BrowserSession:
    __slots__ = (
        "browser",
        "cdp_url",
        "consecutive_failures",
        "created_at",
        "invalidated",
        "local",
        "profile_directory",
        "task_count",
        "ws_url",
    )

    def __init__(
        self,
        browser: Any,
        cdp_url: str,
        ws_url: str,
        *,
        local: bool = False,
        profile_directory: str | None = None,
    ) -> None:
        self.browser = browser
        self.cdp_url = cdp_url
        self.ws_url = ws_url
        self.created_at = time.monotonic()
        self.task_count = 0
        self.consecutive_failures = 0
        self.invalidated = False
        self.local = local
        self.profile_directory = profile_directory

    @property
    def age(self) -> float:
        return time.monotonic() - self.created_at

    @property
    def needs_refresh(self) -> bool:
        """Session should get a fresh Browser object before the next task."""
        return (
            self.invalidated
            or self.consecutive_failures >= _MAX_CONSECUTIVE_FAILURES
            or self.age > _MAX_SESSION_AGE
        )


_sessions: dict[str, _BrowserSession] = {}
_lock = threading.Lock()


async def _safe_close_browser(browser: Any, label: str = "") -> None:
    """Best-effort close/stop of a Browser object, swallowing all errors."""
    if browser is None:
        return
    tag = f" ({label})" if label else ""
    for method_name in ("close", "stop"):
        fn = getattr(browser, method_name, None)
        if not callable(fn):
            continue
        try:
            coro = fn()
            if asyncio.iscoroutine(coro):
                await asyncio.wait_for(coro, timeout=10)
        except TimeoutError:
            logger.warning("Browser%s %s() timed out after 10s", tag, method_name)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Browser%s %s() failed: %s", tag, method_name, exc)
        else:
            logger.debug("Browser%s closed via %s()", tag, method_name)
            return


async def _refresh_browser(session: _BrowserSession) -> None:
    """Close the existing Browser and create a fresh one.

    For sandboxed sessions: reconnects via CDP (the primary recovery path when
    the WebSocket is stale after a crash, timeout, or too many failures).

    For local sessions: creates a fresh ``Browser.from_system_chrome()`` with
    the same profile directory.
    """
    old_browser = session.browser
    session.browser = None

    # Close the old browser in the background — don't let it block recovery.
    await _safe_close_browser(old_browser, label="stale")

    from browser_use import Browser

    if session.local:
        kwargs: dict[str, Any] = {}
        if session.profile_directory:
            kwargs["profile_directory"] = session.profile_directory
        session.browser = Browser.from_system_chrome(**kwargs)
        session.invalidated = False
        session.consecutive_failures = 0
        logger.info(
            "Local session refreshed: new Browser.from_system_chrome(profile=%s)",
            session.profile_directory or "auto",
        )
        return

    ws_url, _ = await asyncio.to_thread(
        _wait_for_cdp,
        session.cdp_url,
        max_attempts=10,
        interval=2.0,
    )

    session.browser = Browser(cdp_url=ws_url)
    session.ws_url = ws_url
    session.invalidated = False
    session.consecutive_failures = 0
    logger.info(
        "Session refreshed: new Browser with ws=%s (old ws was stale)",
        ws_url,
    )


def _wait_for_cdp(
    cdp_url: str, max_attempts: int = 30, interval: float = 1.0
) -> tuple[str, dict[str, Any]]:
    """Block until the CDP endpoint at *cdp_url* responds to ``/json/version``.

    Returns ``(ws_url, version_info)`` where *ws_url* is the WebSocket
    debugger URL rewritten to be reachable from the host.  Chromium inside
    Docker reports ``ws://127.0.0.1:<internal_port>/...`` which is not
    reachable from the host — we replace the host:port with the values from
    *cdp_url* (the Docker-mapped endpoint).

    The Chromium process inside the sandbox container may still be starting
    when the tool server is already healthy.  We poll the CDP ``/json/version``
    endpoint before handing the URL to browser-use.
    """
    from urllib.parse import urlparse

    import httpx

    version_url = cdp_url.rstrip("/") + "/json/version"
    last_error: str = ""

    for attempt in range(1, max_attempts + 1):
        try:
            with httpx.Client(trust_env=False, timeout=5) as client:
                resp = client.get(version_url)
                if resp.status_code == 200 and "webSocketDebuggerUrl" in resp.text:
                    version_info = resp.json()
                    raw_ws = version_info.get("webSocketDebuggerUrl", "")

                    # Rewrite the WebSocket URL: Chromium reports the container-
                    # internal address (e.g. ws://127.0.0.1:19222/devtools/...)
                    # but we need it on the Docker-mapped host:port.
                    parsed_cdp = urlparse(cdp_url)
                    parsed_ws = urlparse(raw_ws)
                    ws_url = raw_ws.replace(
                        f"{parsed_ws.hostname}:{parsed_ws.port}",
                        f"{parsed_cdp.hostname}:{parsed_cdp.port}",
                    )

                    logger.info(
                        "CDP ready at %s (attempt %d): browser=%s, ws_raw=%s, ws_rewritten=%s",
                        cdp_url,
                        attempt,
                        version_info.get("Browser", "unknown"),
                        raw_ws,
                        ws_url,
                    )
                    return ws_url, version_info
                last_error = f"HTTP {resp.status_code}, body={resp.text[:200]}"
                logger.debug("CDP not ready at %s (attempt %d): %s", cdp_url, attempt, last_error)
        except httpx.ConnectError as e:
            last_error = f"ConnectError: {e}"
            logger.debug("CDP connect failed (attempt %d): %s", attempt, last_error)
        except httpx.TimeoutException as e:
            last_error = f"Timeout: {e}"
            logger.debug("CDP timeout (attempt %d): %s", attempt, last_error)
        except httpx.RequestError as e:
            last_error = f"RequestError({type(e).__name__}): {e}"
            logger.debug("CDP request error (attempt %d): %s", attempt, last_error)
        time.sleep(interval)

    raise ConnectionError(
        f"Chromium CDP at {cdp_url} did not become ready after {max_attempts}s. "
        f"Last error: {last_error}. "
        "The sandbox browser may have failed to start — check container logs."
    )


async def _launch_browser(cdp_url: str, agent_id: str) -> _BrowserSession:
    """Create a new browser session connected to the sandbox browser via CDP.

    The *cdp_url* points to the Chromium instance running inside the Docker
    sandbox (exposed via port mapping).  browser-use's ``Browser`` connects
    over the Chrome DevTools Protocol rather than launching a local process.

    We do NOT call ``browser.start()`` here — ``Agent.run()`` does that
    internally (it's idempotent), which ensures the CDP connection is
    established on the correct event loop.
    """
    with _lock:
        if agent_id in _sessions:
            logger.info("Reusing existing browser session for agent %s", agent_id)
            return _sessions[agent_id]

    logger.info("Launching browser for agent %s: cdp_url=%s", agent_id, cdp_url)

    # Wait for the container's Chromium to be ready and get the rewritten WS URL.
    # We pass the ws:// URL directly so browser-use skips its own /json/version
    # fetch (which would get the container-internal address).
    ws_url, version_info = await asyncio.to_thread(_wait_for_cdp, cdp_url)
    logger.info(
        "Chromium version: %s, protocol: %s, user-agent: %s",
        version_info.get("Browser", "?"),
        version_info.get("Protocol-Version", "?"),
        version_info.get("User-Agent", "?")[:80],
    )

    from browser_use import Browser

    browser = Browser(cdp_url=ws_url)
    logger.info(
        "Browser object created for agent %s (ws=%s) — CDP connect deferred to Agent.run()",
        agent_id,
        ws_url,
    )

    session = _BrowserSession(browser=browser, cdp_url=cdp_url, ws_url=ws_url)

    with _lock:
        if agent_id in _sessions:
            # Another thread raced us; discard ours.
            logger.info("Race: another session appeared for agent %s, discarding ours", agent_id)
            return _sessions[agent_id]
        _sessions[agent_id] = session

    return session


async def _launch_local_browser(
    agent_id: str, profile_directory: str | None = None
) -> _BrowserSession:
    """Create a browser session using the local system Chrome.

    Uses ``Browser.from_system_chrome()`` which auto-detects the Chrome
    executable and user data directory.  An optional *profile_directory*
    (e.g. ``"Profile 1"``, ``"Default"``) selects a specific Chrome profile.
    """
    with _lock:
        if agent_id in _sessions:
            logger.info("Reusing existing browser session for agent %s", agent_id)
            return _sessions[agent_id]

    logger.info(
        "Launching local browser for agent %s (profile=%s)",
        agent_id,
        profile_directory or "auto",
    )

    from browser_use import Browser

    kwargs: dict[str, Any] = {}
    if profile_directory:
        kwargs["profile_directory"] = profile_directory

    browser = Browser.from_system_chrome(headless=False, **kwargs)
    logger.info(
        "Local Browser object created for agent %s (profile=%s)",
        agent_id,
        profile_directory or "auto",
    )

    session = _BrowserSession(
        browser=browser,
        cdp_url="",
        ws_url="",
        local=True,
        profile_directory=profile_directory,
    )

    with _lock:
        if agent_id in _sessions:
            logger.info("Race: another session appeared for agent %s, discarding ours", agent_id)
            return _sessions[agent_id]
        _sessions[agent_id] = session

    return session


def _get_session(agent_id: str) -> _BrowserSession:
    """Return the existing session for *agent_id*.

    Raises ``ValueError`` if no session exists (i.e. ``launch`` was not called).
    """
    with _lock:
        session = _sessions.get(agent_id)
    if session is None:
        with _lock:
            active = list(_sessions.keys())
        raise ValueError(
            "Browser not launched. You must call browser_use_local_action "
            f"with action='launch' before running tasks. "
            f"Active sessions: {active}, requested agent_id: {agent_id}"
        )
    return session


async def _shutdown_session(session: _BrowserSession) -> None:
    """Tear down a session's browser."""
    logger.info("Shutting down browser session (cdp_url=%s)", session.cdp_url)
    session.invalidated = True
    await _safe_close_browser(session.browser, label="shutdown")
    session.browser = None
    logger.info("Browser session shut down")


async def _close_session(agent_id: str) -> None:
    """Tear down the browser session for *agent_id*."""
    with _lock:
        session = _sessions.pop(agent_id, None)
    if session is None:
        logger.debug("close_session called but no session for agent %s", agent_id)
        return
    await _shutdown_session(session)


def cleanup_agent(agent_id: str) -> None:
    """Best-effort sync cleanup, called from non-async contexts."""
    with _lock:
        session = _sessions.pop(agent_id, None)
    if session is None:
        return
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(_shutdown_session(session), loop)
        else:
            loop.run_until_complete(_shutdown_session(session))
    except Exception:  # noqa: BLE001
        logger.debug("cleanup_agent: best-effort shutdown failed for %s", agent_id)


def _close_all() -> None:
    with _lock:
        agent_ids = list(_sessions.keys())
    for aid in agent_ids:
        with contextlib.suppress(Exception):
            with _lock:
                session = _sessions.pop(aid, None)
            if session is not None:
                # At atexit there's no running loop, so create one.
                with contextlib.suppress(Exception):
                    asyncio.run(_shutdown_session(session))


atexit.register(_close_all)


async def _reinitialize_after_agent(session: _BrowserSession) -> None:
    """Re-create and start the Browser after Agent.run() kills it.

    browser-use's ``Agent.run()`` calls ``browser_session.kill()`` on
    completion, which destroys the CDP client (``_cdp_client_root = None``),
    clears the event bus (removing all handlers), and creates a fresh empty
    ``EventBus``.  Core handlers registered in ``model_post_init()`` are lost
    and ``start()`` on the dead session would hang.

    The fix: create a brand-new ``Browser`` object (which runs
    ``model_post_init()`` → registers fresh handlers) pointing at the same
    CDP endpoint, then call ``start()`` to connect and attach watchdogs.
    This ensures subsequent granular commands (state, eval, click, etc.)
    have a fully functional session.
    """
    from browser_use import Browser

    if session.local:
        kwargs: dict[str, Any] = {}
        if session.profile_directory:
            kwargs["profile_directory"] = session.profile_directory
        session.browser = Browser.from_system_chrome(**kwargs)
    else:
        session.browser = Browser(cdp_url=session.ws_url)

    await session.browser.start()
    logger.info("Session reinitialized after agent run (local=%s)", session.local)


# ---------------------------------------------------------------------------
# CDP health checks & recovery
# ---------------------------------------------------------------------------


def _check_cdp_alive(cdp_url: str) -> bool:
    """Quick check that the CDP endpoint is reachable (non-blocking from sync)."""
    import httpx

    version_url = cdp_url.rstrip("/") + "/json/version"
    try:
        with httpx.Client(trust_env=False, timeout=5) as client:
            resp = client.get(version_url)
            return resp.status_code == 200 and "webSocketDebuggerUrl" in resp.text
    except Exception:  # noqa: BLE001
        return False


async def _wait_for_cdp_recovery(session: _BrowserSession, task_num: int) -> bool:
    """Wait for the CDP endpoint to come back after a crash/restart.

    Returns True if CDP recovered, False if it's still dead after the timeout.
    """
    max_attempts = int(_CDP_RECOVERY_TIMEOUT / _CDP_RECOVERY_INTERVAL)
    for attempt in range(1, max_attempts + 1):
        await asyncio.sleep(_CDP_RECOVERY_INTERVAL)
        if await asyncio.to_thread(_check_cdp_alive, session.cdp_url):
            logger.info(
                "Task #%d: CDP recovered after %ds",
                task_num,
                attempt * _CDP_RECOVERY_INTERVAL,
            )
            return True
    return False


async def _ensure_healthy_session(session: _BrowserSession, task_num: int) -> str | None:
    """Ensure the session has a working Browser before running a task.

    Returns ``None`` on success or an error message string on failure.
    """
    # --- Local sessions: only refresh on invalidation / too many failures / age ---
    if session.local:
        if session.needs_refresh:
            reason = (
                "invalidated"
                if session.invalidated
                else f"{session.consecutive_failures} consecutive failures"
                if session.consecutive_failures >= _MAX_CONSECUTIVE_FAILURES
                else f"age {session.age:.0f}s > {_MAX_SESSION_AGE}s"
            )
            logger.warning(
                "Task #%d: local session needs refresh (%s) — rebuilding Browser",
                task_num,
                reason,
            )
            try:
                await _refresh_browser(session)
            except Exception as exc:
                logger.exception("Task #%d: local session refresh failed", task_num)
                return f"Failed to refresh local browser session: {exc}"
        return None

    # --- Sandboxed sessions: CDP health checks ---

    # 1) If the session was invalidated (prior crash/timeout/too many failures)
    #    or is too old, proactively refresh the Browser object.
    if session.needs_refresh:
        reason = (
            "invalidated"
            if session.invalidated
            else f"{session.consecutive_failures} consecutive failures"
            if session.consecutive_failures >= _MAX_CONSECUTIVE_FAILURES
            else f"age {session.age:.0f}s > {_MAX_SESSION_AGE}s"
        )
        logger.warning(
            "Task #%d: session needs refresh (%s) — rebuilding Browser",
            task_num,
            reason,
        )
        # Make sure CDP is alive first (may need watchdog restart).
        cdp_alive = await asyncio.to_thread(_check_cdp_alive, session.cdp_url)
        if not cdp_alive and not await _wait_for_cdp_recovery(session, task_num):
            return (
                f"Chromium CDP at {session.cdp_url} is not responding after "
                f"{_CDP_RECOVERY_TIMEOUT}s. The sandbox browser may have "
                "crashed. Check container logs."
            )
        try:
            await _refresh_browser(session)
        except Exception as exc:
            logger.exception("Task #%d: session refresh failed", task_num)
            return f"Failed to refresh browser session: {exc}"
        return None

    # 2) Normal pre-flight: verify CDP is alive.
    if await asyncio.to_thread(_check_cdp_alive, session.cdp_url):
        return None  # all good

    # 3) CDP down — wait for watchdog, then refresh.
    logger.warning(
        "Task #%d: CDP not responding at %s — waiting for watchdog restart...",
        task_num,
        session.cdp_url,
    )
    if not await _wait_for_cdp_recovery(session, task_num):
        session.invalidated = True
        return (
            f"Chromium CDP at {session.cdp_url} is not responding after "
            f"{_CDP_RECOVERY_TIMEOUT}s. The sandbox browser may have crashed. "
            "Check container logs."
        )
    try:
        await _refresh_browser(session)
    except Exception as exc:
        session.invalidated = True
        logger.exception(
            "Task #%d: reconnection after CDP recovery failed",
            task_num,
        )
        return f"Chromium restarted but reconnection failed: {exc}"

    return None
