from functools import cache
from typing import Any, ClassVar

from pygments.lexers import PythonLexer
from pygments.styles import get_style_by_name
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
    def _highlight_python(cls, code: str) -> str:
        lexer = PythonLexer()
        result_parts: list[str] = []

        for token_type, token_value in lexer.get_tokens(code):
            if not token_value:
                continue

            escaped_value = cls.escape_markup(token_value)
            color = cls._get_token_color(token_type)

            if color:
                result_parts.append(f"[{color}]{escaped_value}[/]")
            else:
                result_parts.append(escaped_value)

        return "".join(result_parts)

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        action = args.get("action", "")
        code = args.get("code", "")

        header = "</> [bold #3b82f6]Python[/]"

        if code and action in ["new_session", "execute"]:
            code_display = code[:2000] + "..." if len(code) > 2000 else code
            highlighted_code = cls._highlight_python(code_display)
            content_text = f"{header}\n{highlighted_code}"
        elif action == "close":
            content_text = f"{header}\n  [dim]Closing session...[/]"
        elif action == "list_sessions":
            content_text = f"{header}\n  [dim]Listing sessions...[/]"
        else:
            content_text = f"{header}\n  [dim]Running...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)
