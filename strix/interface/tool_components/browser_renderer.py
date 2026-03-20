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
        "launch": "launching browser",
        "go_back": "going back in browser history",
        "close_browser": "closing browser",
        "close_tab": "closing browser tab",
        "screenshot": "taking screenshot of browser tab",
        "dropdown_options": "getting dropdown options",
        "extract": "extracting content from page",
        "wait": "waiting...",
    }
    PARAM_ACTIONS: ClassVar[dict[str, str]] = {
        "click": "clicking",
        "find_text": "finding text ",
        "send_keys": "pressing key ",
        "search_page": "searching page for ",
        "find_elements": "finding elements matching ",
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

        action = args.get("action", "")
        content = cls._build_content(action, args)

        css_classes = cls.get_css_classes(status)
        return Static(content, classes=css_classes)

    @classmethod
    def _build_url_action(
        cls,
        text: Text,
        label: str,
        url: str | None,
        suffix: str = "",
    ) -> None:
        text.append(label, style="#06b6d4")
        if url:
            text.append(url, style="#06b6d4")
            if suffix:
                text.append(suffix, style="#06b6d4")

    @classmethod
    def _base_text(cls) -> Text:
        text = Text()
        text.append("🌐 ")
        return text

    @classmethod
    def _build_simple_action(cls, action: str, args: dict[str, Any]) -> Text:
        text = cls._base_text()
        text.append(cls.SIMPLE_ACTIONS[action], style="#06b6d4")
        if action == "wait" and args.get("seconds") is not None:
            text.append(f" {args['seconds']}s", style="#06b6d4")
        return text

    @classmethod
    def _build_run(cls, args: dict[str, Any]) -> Text:
        text = cls._base_text()
        text.append("running browser task", style="#06b6d4")
        task = args.get("task")
        if task:
            text.append("\n")
            text.append(str(task), style="#06b6d4")
        return text

    @classmethod
    def _build_navigate(cls, args: dict[str, Any]) -> Text:
        text = cls._base_text()
        suffix = " in new tab" if args.get("new_tab") else ""
        cls._build_url_action(text, "navigating to ", args.get("url"), suffix)
        return text

    @classmethod
    def _build_param_action(cls, action: str, args: dict[str, Any]) -> Text:
        text = cls._base_text()
        text.append(cls.PARAM_ACTIONS[action], style="#06b6d4")

        value_key = {
            "click": "index",
            "find_text": "text",
            "send_keys": "keys",
            "search_page": "pattern",
            "find_elements": "selector",
        }[action]
        value = args.get(value_key)
        if value is not None:
            if action == "click":
                text.append(f" element #{value}", style="#06b6d4")
            else:
                text.append(str(value), style="#06b6d4")
        return text

    @classmethod
    def _build_input(cls, args: dict[str, Any]) -> Text:
        text = cls._base_text()
        text.append("typing ", style="#06b6d4")
        if args.get("text"):
            text.append(str(args["text"]), style="#06b6d4")
        index = args.get("index")
        if index is not None:
            text.append(f" into element #{index}", style="#06b6d4")
        if args.get("clear"):
            text.append(" with clear enabled", style="#06b6d4")
        return text

    @classmethod
    def _build_scroll(cls, args: dict[str, Any]) -> Text:
        text = cls._base_text()
        direction = "down" if args.get("down", True) else "up"
        text.append(f"scrolling {direction}", style="#06b6d4")
        if args.get("pages") is not None:
            text.append(f" {args['pages']} page(s)", style="#06b6d4")
        if args.get("index") is not None:
            text.append(f" on element #{args['index']}", style="#06b6d4")
        return text

    @classmethod
    def _build_select_dropdown(cls, args: dict[str, Any]) -> Text:
        text = cls._base_text()
        text.append("selecting dropdown option ", style="#06b6d4")
        if args.get("text"):
            text.append(str(args["text"]), style="#06b6d4")
        if args.get("index") is not None:
            text.append(f" on element #{args['index']}", style="#06b6d4")
        return text

    @classmethod
    def _build_evaluate(cls, args: dict[str, Any]) -> Text:
        text = cls._base_text()
        text.append("executing javascript", style="#06b6d4")
        js_code = args.get("code")
        if js_code:
            text.append("\n")
            text.append_text(cls._highlight_js(str(js_code)))
        return text

    @classmethod
    def _build_switch(cls, args: dict[str, Any]) -> Text:
        text = cls._base_text()
        text.append("switching browser tab", style="#06b6d4")
        if args.get("tab_id"):
            text.append(" to ", style="#06b6d4")
            text.append(str(args["tab_id"]), style="#06b6d4")
        return text

    @classmethod
    def _build_fallback(cls, action: str) -> Text:
        text = cls._base_text()
        if action:
            text.append(action, style="#06b6d4")
        return text

    @classmethod
    def _build_content(cls, action: str, args: dict[str, Any]) -> Text:
        builders = {
            "run": cls._build_run,
            "navigate": cls._build_navigate,
            "input": cls._build_input,
            "scroll": cls._build_scroll,
            "select_dropdown": cls._build_select_dropdown,
            "evaluate": cls._build_evaluate,
            "switch": cls._build_switch,
        }

        if action in cls.SIMPLE_ACTIONS:
            return cls._build_simple_action(action, args)
        if action in cls.PARAM_ACTIONS:
            return cls._build_param_action(action, args)
        if action in builders:
            return builders[action](args)

        return cls._build_fallback(action)
