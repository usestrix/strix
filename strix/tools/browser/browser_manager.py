import asyncio
import atexit
import contextlib
import logging
import time
from typing import Any


logger = logging.getLogger(__name__)

_MAX_CONSECUTIVE_FAILURES = 3
_MAX_SESSION_AGE = 1800
_CDP_RECOVERY_TIMEOUT = 60
_CDP_RECOVERY_INTERVAL = 2


class BrowserSessionManager:
    def __init__(self) -> None:
        self.sessions: dict[str, BrowserSession] = {}
        self.background_tasks: set[asyncio.Task[None]] = set()

    def get(self, agent_id: str) -> "BrowserSession | None":
        return self.sessions.get(agent_id)

    def create(
        self,
        agent_id: str,
        browser: Any,
        cdp_url: str = "",
        ws_url: str = "",
        auth_token: str = "",
        local: bool = False,
        profile_directory: str | None = None,
    ) -> "BrowserSession":
        session = BrowserSession(
            browser,
            cdp_url,
            ws_url,
            auth_token=auth_token,
            local=local,
            profile_directory=profile_directory,
        )
        self.sessions[agent_id] = session
        return session

    def remove(self, agent_id: str) -> "BrowserSession | None":
        return self.sessions.pop(agent_id, None)

    def close_all(self) -> None:
        for session in list(self.sessions.values()):
            session.invalidated = True
            browser = session.browser
            session.browser = None
            if browser is None:
                continue
            for method_name in ("close", "stop"):
                fn = getattr(browser, method_name, None)
                if callable(fn):
                    with contextlib.suppress(Exception):
                        if asyncio.iscoroutine(coro := fn()):
                            coro.close()
                        break
        self.sessions.clear()


class BrowserSession:
    __slots__ = (
        "auth_token",
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
        auth_token: str = "",
        local: bool = False,
        profile_directory: str | None = None,
    ):
        self.browser = browser
        self.cdp_url = cdp_url
        self.ws_url = ws_url
        self.auth_token = auth_token
        self.local = local
        self.profile_directory = profile_directory
        self.created_at = time.monotonic()
        self.task_count = 0
        self.consecutive_failures = 0
        self.invalidated = False

    @property
    def age(self) -> float:
        return time.monotonic() - self.created_at

    @property
    def needs_refresh(self) -> bool:
        return (
            self.invalidated
            or self.consecutive_failures >= _MAX_CONSECUTIVE_FAILURES
            or self.age > _MAX_SESSION_AGE
        )

    async def close(self) -> None:
        self.invalidated = True
        await _close_browser(self.browser, label="shutdown")
        self.browser = None

    async def refresh(self) -> None:
        old_browser = self.browser
        self.browser = None
        await _close_browser(old_browser, label="stale")

        from browser_use import Browser

        if self.local:
            kwargs: dict[str, Any] = {}
            if self.profile_directory:
                kwargs["profile_directory"] = self.profile_directory
            self.browser = Browser.from_system_chrome(**kwargs)
        else:
            ws_url, _ = await asyncio.to_thread(
                _wait_for_cdp, self.cdp_url, self.auth_token, max_attempts=10, interval=2.0
            )
            self.browser = Browser(cdp_url=ws_url)
            self.ws_url = ws_url

        self.invalidated = False
        self.consecutive_failures = 0

    async def ensure_healthy(self, task_num: int) -> str | None:
        if self.local:
            if self.needs_refresh:
                try:
                    await self.refresh()
                except Exception as exc:  # noqa: BLE001
                    return f"Failed to refresh local browser session: {exc}"
            return None

        cdp_alive = await asyncio.to_thread(_check_cdp_alive, self.cdp_url, self.auth_token)

        if not self.needs_refresh and cdp_alive:
            return None

        if not cdp_alive and not await _wait_for_cdp_recovery(self, task_num):
            if not self.needs_refresh:
                self.invalidated = True
            return (
                f"Chromium CDP at {self.cdp_url} is not responding after {_CDP_RECOVERY_TIMEOUT}s"
            )

        try:
            await self.refresh()
        except Exception as exc:  # noqa: BLE001
            if not self.needs_refresh:
                self.invalidated = True
            return f"Failed to refresh browser session: {exc}"
        return None


_manager = BrowserSessionManager()


async def _close_browser(browser: Any, label: str = "") -> None:
    if browser is None:
        return

    loop = asyncio.get_running_loop()
    original_handler = loop.get_exception_handler()

    # [debug] ignore client is stopping exceptions since we... know
    def squelch_cdp_error(loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
        exc = context.get("exception")
        if isinstance(exc, ConnectionError) and "Client is stopping" in str(exc):
            return
        loop.default_exception_handler(context)

    loop.set_exception_handler(squelch_cdp_error)

    try:
        for method_name in ("close", "stop"):
            if (
                (fn := getattr(browser, method_name, None))
                and callable(fn)
                and asyncio.iscoroutine(coro := fn())
            ):
                try:
                    await asyncio.wait_for(coro, timeout=10)
                except TimeoutError:
                    logger.warning("Browser (%s) %s() timed out", label, method_name)
                except Exception:  # noqa: BLE001,S110
                    pass
                else:
                    return
    finally:
        await asyncio.sleep(0.1)
        loop.set_exception_handler(original_handler)


def _wait_for_cdp(
    cdp_url: str,
    auth_token: str = "",  # nosec B107
    max_attempts: int = 30,
    interval: float = 1.0,
) -> tuple[str, dict[str, Any]]:
    from urllib.parse import urlparse

    import httpx

    version_url = cdp_url.rstrip("/") + "/json/version"
    headers: dict[str, str] = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    last_error: str = ""

    for attempt in range(1, max_attempts + 1):
        try:
            with httpx.Client(trust_env=False, timeout=5) as client:
                resp = client.get(version_url, headers=headers)
                if resp.status_code == 200 and "webSocketDebuggerUrl" in resp.text:
                    version_info = resp.json()
                    raw_ws = version_info.get("webSocketDebuggerUrl", "")

                    # Rewrite the WebSocket URL: Chromium reports the container-
                    # internal address (e.g. ws://127.0.0.1:19222/devtools/...)
                    # but we need it routed through the tool server's CDP proxy.
                    parsed_cdp = urlparse(cdp_url)
                    parsed_ws = urlparse(raw_ws)
                    ws_url = parsed_ws._replace(
                        netloc=parsed_cdp.netloc,
                        path=parsed_cdp.path.rstrip("/") + parsed_ws.path,
                    ).geturl()

                    # Append auth token so browser-use's WebSocket upgrade
                    # request passes through the CDP auth proxy.
                    if auth_token:
                        sep = "&" if "?" in ws_url else "?"
                        ws_url = f"{ws_url}{sep}token={auth_token}"

                    # Log the WS URL with the token redacted to avoid
                    # leaking credentials into log files.
                    import re

                    safe_ws = re.sub(r"([?&])token=[^&]+", r"\1token=REDACTED", ws_url)
                    logger.info(
                        "CDP ready at %s (attempt %d): browser=%s, ws_raw=%s, ws_rewritten=%s",
                        cdp_url,
                        attempt,
                        version_info.get("Browser", "unknown"),
                        raw_ws,
                        safe_ws,
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


async def _launch_browser(cdp_url: str, agent_id: str, auth_token: str = "") -> BrowserSession:  # nosec B107
    if session := _manager.get(agent_id):
        return session

    ws_url, version_info = await asyncio.to_thread(_wait_for_cdp, cdp_url, auth_token)
    logger.info(
        "CDP ready: %s, protocol: %s",
        version_info.get("Browser", "?"),
        version_info.get("Protocol-Version", "?"),
    )

    from browser_use import Browser

    browser = Browser(cdp_url=ws_url)

    if session := _manager.get(agent_id):
        task = asyncio.ensure_future(_close_browser(browser, label="race-discarded"))
        _manager.background_tasks.add(task)
        task.add_done_callback(_manager.background_tasks.discard)
        return session

    return _manager.create(agent_id, browser, cdp_url, ws_url, auth_token=auth_token)


async def _launch_local_browser(
    agent_id: str, profile_directory: str | None = None
) -> BrowserSession:
    if session := _manager.get(agent_id):
        return session

    from browser_use import Browser

    kwargs: dict[str, Any] = {}
    if profile_directory:
        kwargs["profile_directory"] = profile_directory
    browser = Browser.from_system_chrome(headless=False, **kwargs)

    if session := _manager.get(agent_id):
        return session

    return _manager.create(agent_id, browser, local=True, profile_directory=profile_directory)


def _get_session(agent_id: str) -> BrowserSession:
    if session := _manager.get(agent_id):
        return session
    msg = (
        f"Browser not launched. Active sessions: {list(_manager.sessions.keys())}, "
        f"requested: {agent_id}"
    )
    raise ValueError(msg)


async def _close_session(agent_id: str) -> None:
    if session := _manager.remove(agent_id):
        await session.close()


def cleanup_agent(agent_id: str) -> None:
    if not (session := _manager.remove(agent_id)):
        return
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(session.close(), loop)
        else:
            loop.run_until_complete(session.close())
    except Exception:  # noqa: BLE001,S110
        pass


atexit.register(_manager.close_all)


def _check_cdp_alive(cdp_url: str, auth_token: str = "") -> bool:  # nosec B107
    import httpx

    version_url = cdp_url.rstrip("/") + "/json/version"
    headers: dict[str, str] = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    try:
        with httpx.Client(trust_env=False, timeout=5) as client:
            resp = client.get(version_url, headers=headers)
            return resp.status_code == 200 and "webSocketDebuggerUrl" in resp.text
    except Exception:  # noqa: BLE001
        return False


async def _wait_for_cdp_recovery(session: BrowserSession, task_num: int) -> bool:
    max_attempts = int(_CDP_RECOVERY_TIMEOUT / _CDP_RECOVERY_INTERVAL)
    for attempt in range(1, max_attempts + 1):
        await asyncio.sleep(_CDP_RECOVERY_INTERVAL)
        if await asyncio.to_thread(_check_cdp_alive, session.cdp_url, session.auth_token):
            logger.info(
                "Task #%d: CDP recovered after %ds", task_num, attempt * _CDP_RECOVERY_INTERVAL
            )
            return True
    return False


async def _ensure_healthy_session(session: BrowserSession, task_num: int) -> str | None:
    return await session.ensure_healthy(task_num)


def llm_supports_vision() -> bool:
    try:
        import litellm

        from strix.config.config import resolve_llm_config

        model, _, _ = resolve_llm_config()
        return bool(model and litellm.supports_vision(model))
    except Exception:  # noqa: BLE001
        return False
