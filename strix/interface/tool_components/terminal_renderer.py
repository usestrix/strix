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
class TerminalRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "terminal_execute"
    css_classes: ClassVar[list[str]] = ["tool-call", "terminal-tool"]

    CONTROL_SEQUENCES: ClassVar[set[str]] = {
        "C-c",
        "C-d",
        "C-z",
        "C-a",
        "C-e",
        "C-k",
        "C-l",
        "C-u",
        "C-w",
        "C-r",
        "C-s",
        "C-t",
        "C-y",
        "^c",
        "^d",
        "^z",
        "^a",
        "^e",
        "^k",
        "^l",
        "^u",
        "^w",
        "^r",
        "^s",
        "^t",
        "^y",
    }
    SPECIAL_KEYS: ClassVar[set[str]] = {
        "Enter",
        "Escape",
        "Space",
        "Tab",
        "BTab",
        "BSpace",
        "DC",
        "IC",
        "Up",
        "Down",
        "Left",
        "Right",
        "Home",
        "End",
        "PageUp",
        "PageDown",
        "PgUp",
        "PgDn",
        "PPage",
        "NPage",
        "F1",
        "F2",
        "F3",
        "F4",
        "F5",
        "F6",
        "F7",
        "F8",
        "F9",
        "F10",
        "F11",
        "F12",
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
    def _highlight_bash(cls, code: str) -> Text:
        lexer = get_lexer_by_name("bash")
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

        command = args.get("command", "")
        is_input = args.get("is_input", False)

        content = cls._build_content(command, is_input)

        css_classes = cls.get_css_classes(status)
        return Static(content, classes=css_classes)

    @classmethod
    def _build_content(cls, command: str, is_input: bool) -> Text:
        text = Text()
        terminal_icon = ">_"

        if not command.strip():
            text.append(terminal_icon)
            text.append(" ")
            text.append("getting logs...", style="dim")
            return text

        is_special = (
            command in cls.CONTROL_SEQUENCES
            or command in cls.SPECIAL_KEYS
            or command.startswith(("M-", "S-", "C-S-", "C-M-", "S-M-"))
        )

        text.append(terminal_icon)
        text.append(" ")

        if is_special:
            text.append(command, style="#ef4444")
        elif is_input:
            text.append(">>>", style="#3b82f6")
            text.append(" ")
            text.append_text(cls._format_command(command))
        else:
            text.append("$", style="#22c55e")
            text.append(" ")
            text.append_text(cls._format_command(command))

        return text

    @classmethod
    def _format_command(cls, command: str) -> Text:
        if len(command) > 2000:
            command = command[:2000] + "..."
        return cls._highlight_bash(command)
