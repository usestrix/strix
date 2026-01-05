from functools import cache
from typing import Any, ClassVar

from pygments.lexers import get_lexer_by_name, guess_lexer
from pygments.styles import get_style_by_name
from pygments.util import ClassNotFound
from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


_HEADER_STYLES = [
    ("###### ", 7, "bold #4ade80"),
    ("##### ", 6, "bold #22c55e"),
    ("#### ", 5, "bold #16a34a"),
    ("### ", 4, "bold #15803d"),
    ("## ", 3, "bold #22c55e"),
    ("# ", 2, "bold #4ade80"),
]


@cache
def _get_style_colors() -> dict[Any, str]:
    style = get_style_by_name("native")
    return {token: f"#{style_def['color']}" for token, style_def in style if style_def["color"]}


def _get_token_color(token_type: Any) -> str | None:
    colors = _get_style_colors()
    while token_type:
        if token_type in colors:
            return colors[token_type]
        token_type = token_type.parent
    return None


def _highlight_code(code: str, language: str | None = None) -> Text:
    text = Text()

    try:
        lexer = get_lexer_by_name(language) if language else guess_lexer(code)
    except ClassNotFound:
        text.append(code, style="#d4d4d4")
        return text

    for token_type, token_value in lexer.get_tokens(code):
        if not token_value:
            continue
        color = _get_token_color(token_type)
        text.append(token_value, style=color)

    return text


def _try_parse_header(line: str) -> tuple[str, str] | None:
    for prefix, strip_len, style in _HEADER_STYLES:
        if line.startswith(prefix):
            return (line[strip_len:], style)
    return None


def _apply_markdown_styles(text: str) -> Text:  # noqa: PLR0912
    result = Text()
    lines = text.split("\n")

    in_code_block = False
    code_block_lang: str | None = None
    code_block_lines: list[str] = []

    for i, line in enumerate(lines):
        if i > 0 and not in_code_block:
            result.append("\n")

        if line.startswith("```"):
            if not in_code_block:
                in_code_block = True
                code_block_lang = line[3:].strip() or None
                code_block_lines = []
                if i > 0:
                    result.append("\n")
            else:
                in_code_block = False
                code_content = "\n".join(code_block_lines)
                if code_content:
                    result.append_text(_highlight_code(code_content, code_block_lang))
                code_block_lines = []
                code_block_lang = None
            continue

        if in_code_block:
            code_block_lines.append(line)
            continue

        header = _try_parse_header(line)
        if header:
            result.append(header[0], style=header[1])
        elif line.startswith("> "):
            result.append("┃ ", style="#22c55e")
            result.append_text(_process_inline_formatting(line[2:]))
        elif line.startswith(("- ", "* ")):
            result.append("• ", style="#22c55e")
            result.append_text(_process_inline_formatting(line[2:]))
        elif len(line) > 2 and line[0].isdigit() and line[1:3] in (". ", ") "):
            result.append(line[0] + ". ", style="#22c55e")
            result.append_text(_process_inline_formatting(line[2:]))
        elif line.strip() in ("---", "***", "___"):
            result.append("─" * 40, style="#22c55e")
        else:
            result.append_text(_process_inline_formatting(line))

    if in_code_block and code_block_lines:
        code_content = "\n".join(code_block_lines)
        result.append_text(_highlight_code(code_content, code_block_lang))

    return result


def _process_inline_formatting(line: str) -> Text:
    result = Text()
    i = 0
    n = len(line)

    while i < n:
        if i + 1 < n and line[i : i + 2] in ("**", "__"):
            marker = line[i : i + 2]
            end = line.find(marker, i + 2)
            if end != -1:
                result.append(line[i + 2 : end], style="bold #4ade80")
                i = end + 2
                continue

        if i + 1 < n and line[i : i + 2] == "~~":
            end = line.find("~~", i + 2)
            if end != -1:
                result.append(line[i + 2 : end], style="strike #525252")
                i = end + 2
                continue

        if line[i] == "`":
            end = line.find("`", i + 1)
            if end != -1:
                result.append(line[i + 1 : end], style="bold #22c55e on #0a0a0a")
                i = end + 1
                continue

        if line[i] in ("*", "_"):
            marker = line[i]
            if i + 1 < n and line[i + 1] != marker:
                end = line.find(marker, i + 1)
                if end != -1 and (end + 1 >= n or line[end + 1] != marker):
                    result.append(line[i + 1 : end], style="italic #86efac")
                    i = end + 1
                    continue

        result.append(line[i])
        i += 1

    return result


@register_tool_renderer
class AgentMessageRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "agent_message"
    css_classes: ClassVar[list[str]] = ["chat-message", "agent-message"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        content = tool_data.get("content", "")

        if not content:
            return Static(Text(), classes=" ".join(cls.css_classes))

        styled_text = _apply_markdown_styles(content)

        return Static(styled_text, classes=" ".join(cls.css_classes))

    @classmethod
    def render_simple(cls, content: str) -> Text:
        if not content:
            return Text()

        from strix.llm.utils import clean_content

        cleaned = clean_content(content)
        if not cleaned:
            return Text()

        return _apply_markdown_styles(cleaned)
