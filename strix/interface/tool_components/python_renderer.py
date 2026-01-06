import re
from functools import cache
from typing import Any, ClassVar

from pygments.lexers import PythonLexer
from pygments.styles import get_style_by_name
from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


MAX_OUTPUT_LINES = 50
MAX_LINE_LENGTH = 200

STRIP_PATTERNS = [
    r"\.\.\. \[(stdout|stderr|result|output|error) truncated at \d+k? chars\]",
]


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
    def _clean_output(cls, output: str) -> str:
        cleaned = output
        for pattern in STRIP_PATTERNS:
            cleaned = re.sub(pattern, "", cleaned)
        return cleaned.strip()

    @classmethod
    def _truncate_line(cls, line: str) -> str:
        if len(line) > MAX_LINE_LENGTH:
            return line[: MAX_LINE_LENGTH - 3] + "..."
        return line

    @classmethod
    def _format_output(cls, output: str) -> Text:
        text = Text()
        lines = output.splitlines()
        total_lines = len(lines)

        head_count = MAX_OUTPUT_LINES // 2
        tail_count = MAX_OUTPUT_LINES - head_count - 1

        if total_lines <= MAX_OUTPUT_LINES:
            display_lines = lines
            truncated = False
            hidden_count = 0
        else:
            display_lines = lines[:head_count]
            truncated = True
            hidden_count = total_lines - head_count - tail_count

        for i, line in enumerate(display_lines):
            truncated_line = cls._truncate_line(line)
            text.append("  ")
            text.append(truncated_line, style="dim")
            if i < len(display_lines) - 1 or truncated:
                text.append("\n")

        if truncated:
            text.append(f"  ... {hidden_count} lines truncated ...", style="dim italic")
            text.append("\n")
            tail_lines = lines[-tail_count:]
            for i, line in enumerate(tail_lines):
                truncated_line = cls._truncate_line(line)
                text.append("  ")
                text.append(truncated_line, style="dim")
                if i < len(tail_lines) - 1:
                    text.append("\n")

        return text

    @classmethod
    def _append_output(cls, text: Text, result: dict[str, Any]) -> None:
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")

        stdout = cls._clean_output(stdout) if stdout else ""
        stderr = cls._clean_output(stderr) if stderr else ""

        if stdout:
            text.append("\n")
            formatted_output = cls._format_output(stdout)
            text.append_text(formatted_output)

        if stderr:
            text.append("\n")
            text.append("  stderr: ", style="bold #ef4444")
            formatted_stderr = cls._format_output(stderr)
            text.append_text(formatted_stderr)

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        status = tool_data.get("status", "unknown")
        result = tool_data.get("result")

        action = args.get("action", "")
        code = args.get("code", "")

        text = Text()
        text.append("</> ", style="dim")

        if code and action in ["new_session", "execute"]:
            text.append_text(cls._highlight_python(code))
        elif action == "close":
            text.append("Closing session...", style="dim")
        elif action == "list_sessions":
            text.append("Listing sessions...", style="dim")
        else:
            text.append("Running...", style="dim")

        if result and isinstance(result, dict):
            cls._append_output(text, result)

        css_classes = cls.get_css_classes(status)
        return Static(text, classes=css_classes)
