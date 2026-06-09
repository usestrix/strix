import re
from functools import cache
from typing import Any, ClassVar

from pygments.lexers import get_lexer_by_name
from pygments.styles import get_style_by_name
from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


MAX_OUTPUT_LINES = 50
MAX_LINE_LENGTH = 200

STRIP_PATTERNS = [
    r"^Chunk ID: [0-9a-f]+\s*$",
    r"^Wall time: [\d.]+ seconds\s*$",
    r"^Process exited with code -?\d+\s*$",
    r"^Process running with session ID \d+\s*$",
    r"^Original token count: \d+\s*$",
]

_EXIT_RE = re.compile(r"Process exited with code (-?\d+)")
_SESSION_RE = re.compile(r"Process running with session ID (\d+)")
_OUTPUT_HEADER = "\nOutput:\n"

_CONTROL_BYTES_TO_DROP = dict.fromkeys(
    [b for b in range(0x20) if b not in (0x09, 0x0A)] + [0x7F],
    None,
)


@cache
def _get_style_colors() -> dict[Any, str]:
    style = get_style_by_name("native")
    return {token: f"#{style_def['color']}" for token, style_def in style if style_def["color"]}


def _parse_sdk_shell_result(result: Any) -> dict[str, Any]:
    """Translate the SDK's terminal-output string into the dict shape the
    renderer's `_append_output` helper expects.

    The SDK returns a header-prefixed string ending with `Output:\\n<actual>`.
    We extract `content`, `exit_code`, and `session_id`; anything else (or a
    non-string result) flows through unchanged so renderers can handle errors.
    """
    if isinstance(result, dict):
        return result
    if not isinstance(result, str):
        return {"content": "" if result is None else str(result)}

    exit_match = _EXIT_RE.search(result)
    session_match = _SESSION_RE.search(result)
    idx = result.find(_OUTPUT_HEADER)
    content = result[idx + len(_OUTPUT_HEADER) :] if idx >= 0 else result

    parsed: dict[str, Any] = {"content": content}
    if exit_match:
        parsed["exit_code"] = int(exit_match.group(1))
    if session_match:
        parsed["session_id"] = int(session_match.group(1))
    return parsed


def _truncate_line(line: str) -> str:
    if len(line) > MAX_LINE_LENGTH:
        return line[: MAX_LINE_LENGTH - 3] + "..."
    return line


def _clean_output(output: str) -> str:
    cleaned = Text.from_ansi(output).plain.translate(_CONTROL_BYTES_TO_DROP)
    for pattern in STRIP_PATTERNS:
        cleaned = re.sub(pattern, "", cleaned, flags=re.MULTILINE)

    if cleaned.strip():
        lines = cleaned.splitlines()
        filtered_lines: list[str] = []
        for line in lines:
            if not filtered_lines and not line.strip():
                continue
            if line.strip() == "Output:":
                continue
            filtered_lines.append(line)
        while filtered_lines and not filtered_lines[-1].strip():
            filtered_lines.pop()
        cleaned = "\n".join(filtered_lines)

    return cleaned.strip()


def _format_output(output: str) -> Text:
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
        text.append("  ")
        text.append(_truncate_line(line), style="dim")
        if i < len(display_lines) - 1 or truncated:
            text.append("\n")

    if truncated:
        text.append(f"  ... {hidden_count} lines truncated ...", style="dim italic")
        text.append("\n")
        tail_lines = lines[-tail_count:]
        for i, line in enumerate(tail_lines):
            text.append("  ")
            text.append(_truncate_line(line), style="dim")
            if i < len(tail_lines) - 1:
                text.append("\n")

    return text


def _get_token_color(token_type: Any) -> str | None:
    colors = _get_style_colors()
    while token_type:
        if token_type in colors:
            return colors[token_type]
        token_type = token_type.parent
    return None


def _highlight_bash(code: str) -> Text:
    lexer = get_lexer_by_name("bash")
    text = Text()
    for token_type, token_value in lexer.get_tokens(code):
        if not token_value:
            continue
        color = _get_token_color(token_type)
        text.append(token_value, style=color)
    return text


def _append_output(text: Text, parsed: dict[str, Any], tool_status: str) -> None:
    raw_output = parsed.get("content", "") or ""
    output = _clean_output(raw_output) if isinstance(raw_output, str) else ""
    exit_code = parsed.get("exit_code")

    if tool_status == "running":
        if output:
            text.append("\n")
            text.append_text(_format_output(output))
        return

    if not output:
        if exit_code is not None and exit_code != 0:
            text.append("\n")
            text.append(f"  exit {exit_code}", style="dim #ef4444")
        return

    text.append("\n")
    text.append_text(_format_output(output))

    if exit_code is not None and exit_code != 0:
        text.append("\n")
        text.append(f"  exit {exit_code}", style="dim #ef4444")


def _build_terminal_content(
    *,
    prompt: str,
    prompt_style: str,
    command: str,
    parsed_result: dict[str, Any] | None,
    tool_status: str,
    meta: str | None = None,
) -> Text:
    text = Text()
    text.append(">_", style="dim")
    text.append(" ")

    if not command.strip():
        text.append("getting logs...", style="dim")
    else:
        text.append(prompt, style=prompt_style)
        text.append(" ")
        text.append_text(_highlight_bash(command))

    if meta:
        text.append(f"  {meta}", style="dim")

    if parsed_result is not None:
        _append_output(text, parsed_result, tool_status)

    return text


@register_tool_renderer
class ExecCommandRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "exec_command"
    css_classes: ClassVar[list[str]] = ["tool-call", "terminal-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        status = tool_data.get("status", "unknown")
        result = tool_data.get("result")

        cmd = str(args.get("cmd", ""))
        workdir = args.get("workdir")
        tty = bool(args.get("tty"))

        meta_parts: list[str] = []
        if workdir:
            meta_parts.append(f"cwd:{workdir}")
        if tty:
            meta_parts.append("tty")
        meta = ", ".join(meta_parts) if meta_parts else None

        parsed = _parse_sdk_shell_result(result) if result is not None else None

        content = _build_terminal_content(
            prompt="$",
            prompt_style="#22c55e",
            command=cmd,
            parsed_result=parsed,
            tool_status=status,
            meta=meta,
        )

        return Static(content, classes=cls.get_css_classes(status))


@register_tool_renderer
class WriteStdinRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "write_stdin"
    css_classes: ClassVar[list[str]] = ["tool-call", "terminal-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        status = tool_data.get("status", "unknown")
        result = tool_data.get("result")

        chars = str(args.get("chars", ""))
        session_id = args.get("session_id")
        meta = f"session #{session_id}" if session_id is not None else None

        parsed = _parse_sdk_shell_result(result) if result is not None else None

        content = _build_terminal_content(
            prompt=">>>",
            prompt_style="#3b82f6",
            command=chars,
            parsed_result=parsed,
            tool_status=status,
            meta=meta,
        )

        return Static(content, classes=cls.get_css_classes(status))
