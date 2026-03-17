import base64
import inspect
import shutil
from pathlib import Path

from pytest_check import check

from . import console as ui


SCREENSHOTS_DIR = Path(__file__).parent / "screenshots"


def setup_screenshots_dir():
    if SCREENSHOTS_DIR.exists():
        shutil.rmtree(SCREENSHOTS_DIR)
    SCREENSHOTS_DIR.mkdir(exist_ok=True)


class Browser:
    def __init__(self, agent_id, agent_state=None):
        self._agent_id = agent_id
        self._agent_state = agent_state

    def __getattr__(self, action):
        import asyncio

        from strix.tools.browser.browser_actions import browser_action
        from strix.tools.context import set_current_agent_id

        from .conftest import _bg_loop

        def call(**kwargs):
            async def _run():
                set_current_agent_id(self._agent_id)
                return await browser_action(
                    agent_state=self._agent_state,
                    action=action,
                    **kwargs,
                )

            future = asyncio.run_coroutine_threadsafe(_run(), _bg_loop)
            result = future.result(timeout=120)
            if "error" in result:
                Fail(result).error(result["error"])
            _strip_screenshot(result, _caller_test_name())
            return result

        return call


def act_parallel(tasks):
    from concurrent.futures import ThreadPoolExecutor

    def _run_one(browser, kwargs):
        action = kwargs.pop("action")
        return getattr(browser, action)(**kwargs)

    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        futures = [pool.submit(_run_one, b, dict(kw)) for b, kw in tasks]
        return [f.result(timeout=120) for f in futures]


def _caller_test_name():
    for frame in inspect.stack():
        if frame.function.startswith("test_"):
            return frame.function
    return "unknown"


def _strip_screenshot(result, name):
    b64 = result.pop("screenshot", None)
    if not b64 or not isinstance(b64, str) or len(b64) < 100:
        return
    path = SCREENSHOTS_DIR / f"{name}.png"
    path.write_bytes(base64.b64decode(b64))
    result["screenshot_path"] = str(path)


class Fail:
    def __init__(self, result=None):
        self._result = result
        self._name = _caller_test_name()
        self._screenshot = result.get("screenshot_path") if result else None

    def expected(self, value):
        self._expected = value
        return self

    def got(self, value):
        self._emit(f"expected {self._expected!r}, got {value!r}")

    def error(self, msg):
        self._emit(msg)

    def _emit(self, reason):
        ui.log_error(f"  \\[{self._name}] {reason}")
        ui.record_failure(
            self._name,
            self._name,
            reason,
            self._result,
            self._screenshot,
        )
        with check:
            check.fail(f"[{self._name}] {reason}")
