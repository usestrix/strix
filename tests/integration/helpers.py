import base64
import inspect
import shutil
from pathlib import Path

from pytest_check import check

from . import console as ui
from .conftest import _run_in_bg


SCREENSHOTS_DIR = Path(__file__).parent / "screenshots"


def setup_screenshots_dir():
    if SCREENSHOTS_DIR.exists():
        shutil.rmtree(SCREENSHOTS_DIR)
    SCREENSHOTS_DIR.mkdir(exist_ok=True)


class Browser:
    def __init__(self, agent_state):
        self._state = agent_state

    def __getattr__(self, action):
        from strix.tools.browser.browser_actions import browser_action

        def call(**kwargs):
            result = _run_in_bg(
                browser_action(
                    action=action,
                    agent_state=self._state,
                    **kwargs,
                )
            )
            if "error" in result:
                Fail(result).error(result["error"])
            return result

        return call


def _caller_test_name():
    for frame in inspect.stack():
        if frame.function.startswith("test_"):
            return frame.function
    return "unknown"


def _save_screenshot(result, name):
    b64 = result.get("screenshot")
    if not b64 or not isinstance(b64, str) or len(b64) < 100:
        return None
    path = SCREENSHOTS_DIR / f"{name}.png"
    path.write_bytes(base64.b64decode(b64))
    return str(path)


class Fail:
    def __init__(self, result=None):
        self._result = result
        self._name = _caller_test_name()
        self._screenshot = _save_screenshot(result, self._name) if result else None

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
