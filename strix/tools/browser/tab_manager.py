import atexit
import contextlib
import threading
from typing import Any

from strix.tools.context import get_current_agent_id

from .browser_instance import BrowserInstance


class BrowserTabManager:
    def __init__(self) -> None:
        self._browsers_by_agent: dict[str, BrowserInstance] = {}
        self._lock = threading.Lock()

        self._register_cleanup_handlers()

    def _get_agent_browser(self) -> BrowserInstance | None:
        agent_id = get_current_agent_id()
        with self._lock:
            return self._browsers_by_agent.get(agent_id)

    def _set_agent_browser(self, browser: BrowserInstance | None) -> None:
        agent_id = get_current_agent_id()
        with self._lock:
            if browser is None:
                self._browsers_by_agent.pop(agent_id, None)
            else:
                self._browsers_by_agent[agent_id] = browser

    def launch_browser(self, url: str | None = None) -> dict[str, Any]:
        with self._lock:
            agent_id = get_current_agent_id()
            if agent_id in self._browsers_by_agent:
                raise ValueError("Browser is already launched")

            try:
                browser = BrowserInstance()
                result = browser.launch(url)
                self._browsers_by_agent[agent_id] = browser
                result["message"] = "Browser launched successfully"
            except (OSError, ValueError, RuntimeError) as e:
                raise RuntimeError(f"Failed to launch browser: {e}") from e
            else:
                return result

    def goto_url(self, url: str, tab_id: str | None = None) -> dict[str, Any]:
        browser = self._get_agent_browser()
        if browser is None:
            raise ValueError("Browser not launched")

        try:
            result = browser.goto(url, tab_id)
            result["message"] = f"Navigated to {url}"
        except (OSError, ValueError, RuntimeError) as e:
            raise RuntimeError(f"Failed to navigate to URL: {e}") from e
        else:
            return result

    def click(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        browser = self._get_agent_browser()
        if browser is None:
            raise ValueError("Browser not launched")

        try:
            result = browser.click(coordinate, tab_id)
            result["message"] = f"Clicked at {coordinate}"
        except (OSError, ValueError, RuntimeError) as e:
            raise RuntimeError(f"Failed to click: {e}") from e
        else:
            return result

    def type_text(self, text: str, tab_id: str | None = None) -> dict[str, Any]:
        browser = self._get_agent_browser()
        if browser is None:
            raise ValueError("Browser not launched")

        try:
            result = browser.type_text(text, tab_id)
            result["message"] = f"Typed text: {text[:50]}{'...' if len(text) > 50 else ''}"
        except (OSError, ValueError, RuntimeError) as e:
            raise RuntimeError(f"Failed to type text: {e}") from e
        else:
            return result

    def scroll(self, direction: str, tab_id: str | None = None) -> dict[str, Any]:
        browser = self._get_agent_browser()
        if browser is None:
            raise ValueError("Browser not launched")

        try:
            result = browser.scroll(direction, tab_id)
            result["message"] = f"Scrolled {direction}"
        except (OSError, ValueError, RuntimeError) as e:
            raise RuntimeError(f"Failed to scroll: {e}") from e
        else:
            return result

    def back(self, tab_id: str | None = None) -> dict[str, Any]:
        browser = self._get_agent_browser()
        if browser is None:
            raise ValueError("Browser not launched")

        try:
            result = browser.back(tab_id)
            result["message"] = "Navigated back"
        except (OSError, ValueError, RuntimeError) as e:
            raise RuntimeError(f"Failed to go back: {e}") from e
        else:
            return result

    def forward(self, tab_id: str | None = None) -> dict[str, Any]:
        browser = self._get_agent_browser()
        if browser is None:
            raise ValueError("Browser not launched")

        try:
            result = browser.forward(tab_id)
            result["message"] = "Navigated forward"
        except (OSError, ValueError, RuntimeError) as e:
            raise RuntimeError(f"Failed to go forward: {e}") from e
        else:
            return result

    def new_tab(self, url: str | None = None) -> dict[str, Any]:
        browser = self._get_agent_browser()
        if browser is None:
            raise ValueError("Browser not launched")

        try:
            result = browser.new_tab(url)
            result["message"] = f"Created new tab {result.get('tab_id', '')}"
        except (OSError, ValueError, RuntimeError) as e:
            raise RuntimeError(f"Failed to create new tab: {e}") from e
        else:
            return result

    def switch_tab(self, tab_id: str) -> dict[str, Any]:
        browser = self._get_agent_browser()
        if browser is None:
            raise ValueError("Browser not launched")

        try:
            result = browser.switch_tab(tab_id)
            result["message"] = f"Switched to tab {tab_id}"
        except (OSError, ValueError, RuntimeError) as e:
            raise RuntimeError(f"Failed to switch tab: {e}") from e
        else:
            return result

    def close_tab(self, tab_id: str) -> dict[str, Any]:
        browser = self._get_agent_browser()
        if browser is None:
            raise ValueError("Browser not launched")

        try:
            result = browser.close_tab(tab_id)
            result["message"] = f"Closed tab {tab_id}"
        except (OSError, ValueError, RuntimeError) as e:
            raise RuntimeError(f"Failed to close tab: {e}") from e
        else:
            return result

    def wait_browser(self, duration: float, tab_id: str | None = None) -> dict[str, Any]:
        browser = self._get_agent_browser()
        if browser is None:
            raise ValueError("Browser not launched")

        try:
            result = browser.wait(duration, tab_id)
            result["message"] = f"Waited {duration}s"
        except (OSError, ValueError, RuntimeError) as e:
            raise RuntimeError(f"Failed to wait: {e}") from e
        else:
            return result

    def execute_js(self, js_code: str, tab_id: str | None = None) -> dict[str, Any]:
        browser = self._get_agent_browser()
        if browser is None:
            raise ValueError("Browser not launched")

        try:
            result = browser.execute_js(js_code, tab_id)
            result["message"] = "JavaScript executed successfully"
        except (OSError, ValueError, RuntimeError) as e:
            raise RuntimeError(f"Failed to execute JavaScript: {e}") from e
        else:
            return result

    def double_click(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        browser = self._get_agent_browser()
        if browser is None:
            raise ValueError("Browser not launched")

        try:
            result = browser.double_click(coordinate, tab_id)
            result["message"] = f"Double clicked at {coordinate}"
        except (OSError, ValueError, RuntimeError) as e:
            raise RuntimeError(f"Failed to double click: {e}") from e
        else:
            return result

    def hover(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        browser = self._get_agent_browser()
        if browser is None:
            raise ValueError("Browser not launched")

        try:
            result = browser.hover(coordinate, tab_id)
            result["message"] = f"Hovered at {coordinate}"
        except (OSError, ValueError, RuntimeError) as e:
            raise RuntimeError(f"Failed to hover: {e}") from e
        else:
            return result

    def press_key(self, key: str, tab_id: str | None = None) -> dict[str, Any]:
        browser = self._get_agent_browser()
        if browser is None:
            raise ValueError("Browser not launched")

        try:
            result = browser.press_key(key, tab_id)
            result["message"] = f"Pressed key {key}"
        except (OSError, ValueError, RuntimeError) as e:
            raise RuntimeError(f"Failed to press key: {e}") from e
        else:
            return result

    def save_pdf(self, file_path: str, tab_id: str | None = None) -> dict[str, Any]:
        browser = self._get_agent_browser()
        if browser is None:
            raise ValueError("Browser not launched")

        try:
            result = browser.save_pdf(file_path, tab_id)
            result["message"] = f"Page saved as PDF: {file_path}"
        except (OSError, ValueError, RuntimeError) as e:
            raise RuntimeError(f"Failed to save PDF: {e}") from e
        else:
            return result

    def get_console_logs(self, tab_id: str | None = None, clear: bool = False) -> dict[str, Any]:
        browser = self._get_agent_browser()
        if browser is None:
            raise ValueError("Browser not launched")

        try:
            result = browser.get_console_logs(tab_id, clear)
            action_text = "cleared and retrieved" if clear else "retrieved"

            logs = result.get("console_logs", [])
            truncated = any(log.get("text", "").startswith("[TRUNCATED:") for log in logs)
            truncated_text = " (truncated)" if truncated else ""

            result["message"] = (
                f"Console logs {action_text} for tab "
                f"{result.get('tab_id', 'current')}{truncated_text}"
            )
        except (OSError, ValueError, RuntimeError) as e:
            raise RuntimeError(f"Failed to get console logs: {e}") from e
        else:
            return result

    def view_source(self, tab_id: str | None = None) -> dict[str, Any]:
        browser = self._get_agent_browser()
        if browser is None:
            raise ValueError("Browser not launched")

        try:
            result = browser.view_source(tab_id)
            result["message"] = "Page source retrieved"
        except (OSError, ValueError, RuntimeError) as e:
            raise RuntimeError(f"Failed to get page source: {e}") from e
        else:
            return result

    def list_tabs(self) -> dict[str, Any]:
        browser = self._get_agent_browser()
        if browser is None:
            return {"tabs": {}, "total_count": 0, "current_tab": None}

        try:
            tab_info = {}
            for tid, tab_page in browser.pages.items():
                try:
                    tab_info[tid] = {
                        "url": tab_page.url,
                        "title": "Unknown" if tab_page.is_closed() else "Active",
                        "is_current": tid == browser.current_page_id,
                    }
                except (AttributeError, RuntimeError):
                    tab_info[tid] = {
                        "url": "Unknown",
                        "title": "Closed",
                        "is_current": False,
                    }

            return {
                "tabs": tab_info,
                "total_count": len(tab_info),
                "current_tab": browser.current_page_id,
            }
        except (OSError, ValueError, RuntimeError) as e:
            raise RuntimeError(f"Failed to list tabs: {e}") from e

    def close_browser(self) -> dict[str, Any]:
        agent_id = get_current_agent_id()
        with self._lock:
            browser = self._browsers_by_agent.pop(agent_id, None)
            if browser is None:
                raise ValueError("Browser not launched")

            try:
                browser.close()
            except (OSError, ValueError, RuntimeError) as e:
                raise RuntimeError(f"Failed to close browser: {e}") from e
            else:
                return {
                    "message": "Browser closed successfully",
                    "screenshot": "",
                    "is_running": False,
                }

    def cleanup_agent(self, agent_id: str) -> None:
        with self._lock:
            browser = self._browsers_by_agent.pop(agent_id, None)

        if browser:
            with contextlib.suppress(Exception):
                browser.close()

    def cleanup_dead_browser(self) -> None:
        with self._lock:
            dead_agents = []
            for agent_id, browser in self._browsers_by_agent.items():
                if not browser.is_alive():
                    dead_agents.append(agent_id)

            for agent_id in dead_agents:
                browser = self._browsers_by_agent.pop(agent_id)
                with contextlib.suppress(Exception):
                    browser.close()

    def close_all(self) -> None:
        with self._lock:
            browsers = list(self._browsers_by_agent.values())
            self._browsers_by_agent.clear()

        for browser in browsers:
            with contextlib.suppress(Exception):
                browser.close()

    def _register_cleanup_handlers(self) -> None:
        atexit.register(self.close_all)


_browser_tab_manager = BrowserTabManager()


def get_browser_tab_manager() -> BrowserTabManager:
    return _browser_tab_manager
