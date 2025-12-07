from typing import TYPE_CHECKING, Any, Literal, NoReturn

from strix.tools.registry import register_tool


if TYPE_CHECKING:
    from .tab_manager import BrowserTabManager


BrowserAction = Literal[
    "launch",
    "goto",
    "click",
    "type",
    "scroll_down",
    "scroll_up",
    "back",
    "forward",
    "new_tab",
    "switch_tab",
    "close_tab",
    "wait",
    "execute_js",
    "double_click",
    "hover",
    "press_key",
    "save_pdf",
    "get_console_logs",
    "view_source",
    "close",
    "list_tabs",
]


def _validate_url(action_name: str, url: str | None) -> None:
    if not url:
        raise ValueError(f"url parameter is required for {action_name} action")


def _validate_coordinate(action_name: str, coordinate: str | None) -> None:
    if not coordinate:
        raise ValueError(f"coordinate parameter is required for {action_name} action")


def _validate_text(action_name: str, text: str | None) -> None:
    if not text:
        raise ValueError(f"text parameter is required for {action_name} action")


def _validate_tab_id(action_name: str, tab_id: str | None) -> None:
    if not tab_id:
        raise ValueError(f"tab_id parameter is required for {action_name} action")


def _validate_js_code(action_name: str, js_code: str | None) -> None:
    if not js_code:
        raise ValueError(f"js_code parameter is required for {action_name} action")


def _validate_duration(action_name: str, duration: float | None) -> None:
    if duration is None:
        raise ValueError(f"duration parameter is required for {action_name} action")


def _validate_key(action_name: str, key: str | None) -> None:
    if not key:
        raise ValueError(f"key parameter is required for {action_name} action")


def _validate_file_path(action_name: str, file_path: str | None) -> None:
    if not file_path:
        raise ValueError(f"file_path parameter is required for {action_name} action")


def _handle_navigation_actions(
    manager: "BrowserTabManager",
    action: str,
    url: str | None = None,
    tab_id: str | None = None,
) -> dict[str, Any]:
    if action == "launch":
        return manager.launch_browser(url)
    if action == "goto":
        _validate_url(action, url)
        assert url is not None
        return manager.goto_url(url, tab_id)
    if action == "back":
        return manager.back(tab_id)
    if action == "forward":
        return manager.forward(tab_id)
    raise ValueError(f"Unknown navigation action: {action}")


def _handle_interaction_actions(
    manager: "BrowserTabManager",
    action: str,
    coordinate: str | None = None,
    text: str | None = None,
    key: str | None = None,
    tab_id: str | None = None,
) -> dict[str, Any]:
    if action in {"click", "double_click", "hover"}:
        _validate_coordinate(action, coordinate)
        assert coordinate is not None
        action_map = {
            "click": manager.click,
            "double_click": manager.double_click,
            "hover": manager.hover,
        }
        return action_map[action](coordinate, tab_id)

    if action in {"scroll_down", "scroll_up"}:
        direction = "down" if action == "scroll_down" else "up"
        return manager.scroll(direction, tab_id)

    if action == "type":
        _validate_text(action, text)
        assert text is not None
        return manager.type_text(text, tab_id)
    if action == "press_key":
        _validate_key(action, key)
        assert key is not None
        return manager.press_key(key, tab_id)

    raise ValueError(f"Unknown interaction action: {action}")


def _raise_unknown_action(action: str) -> NoReturn:
    raise ValueError(f"Unknown action: {action}")


def _handle_tab_actions(
    manager: "BrowserTabManager",
    action: str,
    url: str | None = None,
    tab_id: str | None = None,
) -> dict[str, Any]:
    if action == "new_tab":
        return manager.new_tab(url)
    if action == "switch_tab":
        _validate_tab_id(action, tab_id)
        assert tab_id is not None
        return manager.switch_tab(tab_id)
    if action == "close_tab":
        _validate_tab_id(action, tab_id)
        assert tab_id is not None
        return manager.close_tab(tab_id)
    if action == "list_tabs":
        return manager.list_tabs()
    raise ValueError(f"Unknown tab action: {action}")


def _handle_utility_actions(
    manager: "BrowserTabManager",
    action: str,
    duration: float | None = None,
    js_code: str | None = None,
    file_path: str | None = None,
    tab_id: str | None = None,
    clear: bool = False,
) -> dict[str, Any]:
    if action == "wait":
        _validate_duration(action, duration)
        assert duration is not None
        return manager.wait_browser(duration, tab_id)
    if action == "execute_js":
        _validate_js_code(action, js_code)
        assert js_code is not None
        return manager.execute_js(js_code, tab_id)
    if action == "save_pdf":
        _validate_file_path(action, file_path)
        assert file_path is not None
        return manager.save_pdf(file_path, tab_id)
    if action == "get_console_logs":
        return manager.get_console_logs(tab_id, clear)
    if action == "view_source":
        return manager.view_source(tab_id)
    if action == "close":
        return manager.close_browser()
    raise ValueError(f"Unknown utility action: {action}")


@register_tool
def browser_action(
    action: BrowserAction,
    url: str | None = None,
    coordinate: str | None = None,
    text: str | None = None,
    tab_id: str | None = None,
    js_code: str | None = None,
    duration: float | None = None,
    key: str | None = None,
    file_path: str | None = None,
    clear: bool = False,
) -> dict[str, Any]:
    from .tab_manager import get_browser_tab_manager

    manager = get_browser_tab_manager()

    try:
        navigation_actions = {"launch", "goto", "back", "forward"}
        interaction_actions = {
            "click",
            "type",
            "double_click",
            "hover",
            "press_key",
            "scroll_down",
            "scroll_up",
        }
        tab_actions = {"new_tab", "switch_tab", "close_tab", "list_tabs"}
        utility_actions = {
            "wait",
            "execute_js",
            "save_pdf",
            "get_console_logs",
            "view_source",
            "close",
        }

        if action in navigation_actions:
            return _handle_navigation_actions(manager, action, url, tab_id)
        if action in interaction_actions:
            return _handle_interaction_actions(manager, action, coordinate, text, key, tab_id)
        if action in tab_actions:
            return _handle_tab_actions(manager, action, url, tab_id)
        if action in utility_actions:
            return _handle_utility_actions(
                manager, action, duration, js_code, file_path, tab_id, clear
            )

        _raise_unknown_action(action)

    except (ValueError, RuntimeError) as e:
        return {
            "error": str(e),
            "tab_id": tab_id,
            "screenshot": "",
            "is_running": False,
        }
