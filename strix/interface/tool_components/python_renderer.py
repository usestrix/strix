from functools import cache
from typing import Any, ClassVar

from pygments.lexers import PythonLexer
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
class PythonRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "python_action"
    css_classes: ClassVar[list[str]] = ["tool-call", "python-tool"]

    @classmethod
    def _get_token_color(cls, token_type: Any) -> str | None:
        colors = _get_style_colors()
        while token_type:
            if token_type in colors:
                return colors[token_type]
            token_type = token_type.parent
        return None

    @classmethod
    def _highlight_python(cls, code: str) -> Text:
        lexer = PythonLexer()
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

        action = args.get("action", "")
        code = args.get("code", "")

        text = Text()
        text.append("</> ")
        text.append("Python", style="bold #3b82f6")
        text.append("\n")

        if code and action in ["new_session", "execute"]:
            code_display = cls.truncate(code, 2000)
            text.append_text(cls._highlight_python(code_display))
        elif action == "close":
            text.append("  ")
            text.append("Closing session...", style="dim")
        elif action == "list_sessions":
            text.append("  ")
            text.append("Listing sessions...", style="dim")
        else:
            text.append("  ")
            text.append("Running...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)
