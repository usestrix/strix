from functools import cache
from typing import Any, ClassVar

from pygments.lexers import get_lexer_by_name
from pygments.styles import get_style_by_name
from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@cache
def _get_style_colors() -> dict[Any, str]:
    style = get_style_by_name("native")
    return {token: f"#{style_def['color']}" for token, style_def in style if style_def["color"]}


@register_tool_renderer
class BrowserRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "browser_action"
    css_classes: ClassVar[list[str]] = ["tool-call", "browser-tool"]

    SIMPLE_ACTIONS: ClassVar[dict[str, str]] = {
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

    @classmethod
    def _get_token_color(cls, token_type: Any) -> str | None:
        colors = _get_style_colors()
        while token_type:
            if token_type in colors:
                return colors[token_type]
            token_type = token_type.parent
        return None

    @classmethod
    def _highlight_js(cls, code: str) -> Text:
        lexer = get_lexer_by_name("javascript")
        text = Text()

        for token_type, token_value in lexer.get_tokens(code):
            if not token_value:
                continue
            color = cls._get_token_color(token_type)
            text.append(token_value, style=color)

        return text

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        status = tool_data.get("status", "unknown")

        action = args.get("action", "unknown")
        content = cls._build_content(action, args)

        css_classes = cls.get_css_classes(status)
        return Static(content, classes=css_classes)

    @classmethod
    def _build_url_action(cls, text: Text, label: str, url: str | None, suffix: str = "") -> None:
        text.append(label, style="#06b6d4")
        if url:
            text.append(url, style="#06b6d4")
            if suffix:
                text.append(suffix, style="#06b6d4")

    @classmethod
    def _build_content(cls, action: str, args: dict[str, Any]) -> Text:
        text = Text()
        text.append("🌐 ")

        if action in cls.SIMPLE_ACTIONS:
            text.append(cls.SIMPLE_ACTIONS[action], style="#06b6d4")
            return text

        url = args.get("url")

        url_actions = {
            "launch": ("launching ", " on browser" if url else "browser"),
            "goto": ("navigating to ", ""),
            "new_tab": ("opening tab ", ""),
        }
        if action in url_actions:
            label, suffix = url_actions[action]
            if action == "launch" and not url:
                text.append("launching browser", style="#06b6d4")
            else:
                cls._build_url_action(text, label, url, suffix)
            return text

        click_actions = {
            "click": "clicking",
            "double_click": "double clicking",
            "hover": "hovering",
        }
        if action in click_actions:
            text.append(click_actions[action], style="#06b6d4")
            return text

        handlers: dict[str, tuple[str, str | None]] = {
            "type": ("typing ", args.get("text")),
            "press_key": ("pressing key ", args.get("key")),
            "save_pdf": ("saving PDF to ", args.get("file_path")),
        }
        if action in handlers:
            label, value = handlers[action]
            text.append(label, style="#06b6d4")
            if value:
                text.append(str(value), style="#06b6d4")
            return text

        if action == "execute_js":
            text.append("executing javascript", style="#06b6d4")
            js_code = args.get("js_code")
            if js_code:
                text.append("\n")
                text.append_text(cls._highlight_js(js_code))
            return text

        text.append(action, style="#06b6d4")
        return text
