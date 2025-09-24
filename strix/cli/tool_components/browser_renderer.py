from typing import Any, ClassVar

from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class BrowserRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "browser_action"
    css_classes: ClassVar[list[str]] = ["tool-call", "browser-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        status = tool_data.get("status", "unknown")

        action = args.get("action", "unknown")

        content = cls._build_sleek_content(action, args)

        css_classes = cls.get_css_classes(status)
        return Static(content, classes=css_classes)

    @classmethod
    def _build_sleek_content(cls, action: str, args: dict[str, Any]) -> str:
        browser_icon = "🌐"

        url = args.get("url")
        text = args.get("text")
        js_code = args.get("js_code")
        key = args.get("key")
        file_path = args.get("file_path")

        if action in [
            "launch",
            "goto",
            "new_tab",
            "type",
            "execute_js",
            "click",
            "double_click",
            "hover",
            "press_key",
            "save_pdf",
        ]:
            if action == "launch":
                display_url = cls._format_url(url) if url else None
                message = (
                    f"launching {display_url} on browser" if display_url else "launching browser"
                )
            elif action == "goto":
                display_url = cls._format_url(url) if url else None
                message = f"navigating to {display_url}" if display_url else "navigating"
            elif action == "new_tab":
                display_url = cls._format_url(url) if url else None
                message = f"opening tab {display_url}" if display_url else "opening tab"
            elif action == "type":
                display_text = cls._format_text(text) if text else None
                message = f"typing {display_text}" if display_text else "typing"
            elif action == "execute_js":
                display_js = cls._format_js(js_code) if js_code else None
                message = (
                    f"executing javascript\n{display_js}" if display_js else "executing javascript"
                )
            elif action == "press_key":
                display_key = cls.escape_markup(key) if key else None
                message = f"pressing key {display_key}" if display_key else "pressing key"
            elif action == "save_pdf":
                display_path = cls.escape_markup(file_path) if file_path else None
                message = f"saving PDF to {display_path}" if display_path else "saving PDF"
            else:
                action_words = {
                    "click": "clicking",
                    "double_click": "double clicking",
                    "hover": "hovering",
                }
                message = cls.escape_markup(action_words[action])

            return f"{browser_icon} [#06b6d4]{message}[/]"

        simple_actions = {
            "back": "going back in browser history",
            "forward": "going forward in browser history",
            "scroll_down": "scrolling down",
            "scroll_up": "scrolling up",
            "refresh": "refreshing browser tab",
            "close_tab": "closing browser tab",
            "switch_tab": "switching browser tab",
            "list_tabs": "listing browser tabs",
            "view_source": "viewing page source",
            "get_console_logs": "getting console logs",
            "screenshot": "taking screenshot of browser tab",
            "wait": "waiting...",
            "close": "closing browser",
        }

        if action in simple_actions:
            return f"{browser_icon} [#06b6d4]{cls.escape_markup(simple_actions[action])}[/]"

        return f"{browser_icon} [#06b6d4]{cls.escape_markup(action)}[/]"

    @classmethod
    def _format_url(cls, url: str) -> str:
        if len(url) > 300:
            url = url[:297] + "..."
        return cls.escape_markup(url)

    @classmethod
    def _format_text(cls, text: str) -> str:
        if len(text) > 200:
            text = text[:197] + "..."
        return cls.escape_markup(text)

    @classmethod
    def _format_js(cls, js_code: str) -> str:
        if len(js_code) > 200:
            js_code = js_code[:197] + "..."
        return f"[white]{cls.escape_markup(js_code)}[/white]"
