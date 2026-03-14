import asyncio
import atexit
import contextlib
import logging
from typing import Any

import httpx
from browser_use import Browser
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_fixed


logger = logging.getLogger(__name__)


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
            browser = session.browser
            session.browser = None
            if browser is not None:
                with contextlib.suppress(Exception):
                    coro = browser.stop()
                    if asyncio.iscoroutine(coro):
                        coro.close()
        self.sessions.clear()


class BrowserSession:
    __slots__ = (
        "auth_token",
        "browser",
        "cdp_url",
        "local",
        "profile_directory",
        "task_count",
        "ws_url",
    )

    def __init__(
        self,
        browser: Browser,
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
        self.task_count = 0

    async def close(self) -> None:
        await _close_browser(self.browser)
        self.browser = None


_manager = BrowserSessionManager()


async def _close_browser(browser: Any) -> None:
    if browser is None:
        return

    # suppress "Client is stopping" noise that CDP fires during intentional teardown
    loop = asyncio.get_running_loop()
    prev_handler = loop.get_exception_handler()
    loop.set_exception_handler(
        lambda loop_, ctx: (
            None
            if isinstance(ctx.get("exception"), ConnectionError)
            and "Client is stopping" in str(ctx["exception"])
            else loop_.default_exception_handler(ctx)
        )
    )

    try:
        await asyncio.wait_for(browser.stop(), timeout=10)
    except Exception:  # noqa: BLE001,S110
        pass
    finally:
        await asyncio.sleep(0.1)
        loop.set_exception_handler(prev_handler)


class _CDPNotReadyError(Exception):
    pass


@retry(  # type: ignore[misc]
    stop=stop_after_attempt(30),
    wait=wait_fixed(1),
    retry=retry_if_exception_type(_CDPNotReadyError),
    reraise=True,
)
async def _wait_for_cdp(
    api_url: str,
    auth_token: str = "",  # nosec B107
) -> str:
    """Poll the tool server's /cdp/info until the WS proxy is ready."""
    headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
    async with httpx.AsyncClient(trust_env=False, timeout=5) as client:
        try:
            resp = await client.get(f"{api_url}/cdp/info", headers=headers)
        except httpx.HTTPError as e:
            raise _CDPNotReadyError(f"{type(e).__name__}: {e}") from e

    if resp.status_code != 200:
        raise _CDPNotReadyError(f"HTTP {resp.status_code}")

    # Build the full WS URL from the tool server's relative path
    ws_path: str = resp.json()["ws_url"]
    ws_url = api_url.replace("http", "ws", 1) + ws_path
    if auth_token:
        ws_url = f"{ws_url}?token={auth_token}"

    logger.info("CDP ready via %s", ws_url.split("?")[0])
    return ws_url


async def _launch_browser(api_url: str, agent_id: str, auth_token: str = "") -> BrowserSession:  # nosec B107
    if session := _manager.get(agent_id):
        return session

    ws_url = await _wait_for_cdp(api_url, auth_token)
    browser = Browser(cdp_url=ws_url)

    if session := _manager.get(agent_id):
        task = asyncio.ensure_future(_close_browser(browser))
        _manager.background_tasks.add(task)
        task.add_done_callback(_manager.background_tasks.discard)
        return session

    return _manager.create(agent_id, browser, api_url, ws_url, auth_token=auth_token)


async def _launch_local_browser(
    agent_id: str, profile_directory: str | None = None
) -> BrowserSession:
    if session := _manager.get(agent_id):
        return session

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
    raise ValueError(
        f"Browser not launched. Active: {list(_manager.sessions.keys())}, requested: {agent_id}"
    )


async def _close_session(agent_id: str) -> None:
    if session := _manager.remove(agent_id):
        await session.close()


atexit.register(_manager.close_all)
