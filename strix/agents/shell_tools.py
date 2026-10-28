"""Adapt SDK shell tools: output limits, argument decoding and PTY session state."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any, cast

from agents.sandbox.errors import InvalidManifestPathError
from agents.sandbox.session.pty_types import PTY_YIELD_TIME_MS_MAX
from pydantic import ValidationError

from strix.config import load_settings


if TYPE_CHECKING:
    from agents.tool import FunctionTool


_CHARS_ESCAPE_RE = re.compile(r"\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0abtnvfr\\])")
_PTY_SESSION_NOT_FOUND_RE = re.compile(
    r"write_stdin failed: PTY session not found: (?P<session_id>\d+)"
)
_WRITE_STDIN_DEAD_SESSION_RESULT_TEMPLATE = (
    "write_stdin: session {session_id} is already terminal/non-retryable "
    "after PTY session not found."
)
_CHARS_ESCAPE_MAP = {
    "\\\\": "\\",
    "\\n": "\n",
    "\\t": "\t",
    "\\r": "\r",
    "\\0": "\x00",
    "\\a": "\x07",
    "\\b": "\x08",
    "\\v": "\x0b",
    "\\f": "\x0c",
}


def _decode_chars_escape(s: str) -> str:
    if "\\" not in s:
        return s

    def sub(match: re.Match[str]) -> str:
        token = match.group(0)
        if token in _CHARS_ESCAPE_MAP:
            return _CHARS_ESCAPE_MAP[token]
        if token.startswith(("\\u", "\\x")):
            return chr(int(token[2:], 16))
        return token

    return _CHARS_ESCAPE_RE.sub(sub, s)


def _format_validation_error(tool_name: str, exc: ValidationError) -> str:
    parts: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(x) for x in err.get("loc", ()))
        msg = err.get("msg", "invalid")
        parts.append(f"{loc}: {msg}" if loc else msg)
    return f"{tool_name}: invalid arguments — " + "; ".join(parts)


def _apply_shell_output_cap(parsed: dict[str, Any]) -> None:
    """Clamp the SDK shell tools' ``max_output_tokens`` to the configured
    ceiling; a smaller explicit value is respected."""
    ceiling = load_settings().context.tool_output_max_tokens
    requested = parsed.get("max_output_tokens")
    parsed["max_output_tokens"] = (
        ceiling if not isinstance(requested, int) or requested > ceiling else requested
    )


_EXEC_YIELD_CAP_S = PTY_YIELD_TIME_MS_MAX // 1000

_EXEC_COMMAND_DESCRIPTION_NOTE = (
    f"The wait for output is capped at {_EXEC_YIELD_CAP_S} s whatever yield_time_ms says. "
    "A non-TTY command still running at the yield cannot be read later (write_stdin fails "
    "on it and its output is lost): run anything longer in the background with its output "
    "redirected to a file (`cmd > /tmp/out.log 2>&1 &`, then read the log), or start it with "
    'tty=true and poll with write_stdin(session_id=<id>, chars="").'
)

_RUNNING_NON_TTY_NOTICE = (
    "Note: this non-TTY process cannot be polled and its later output is lost. Rerun it in "
    "the background (`cmd > /tmp/out.log 2>&1 &`, then read the log) or with tty=true."
)

_PROCESS_RUNNING_RE = re.compile(r"^Process running with session ID \d+$", re.MULTILINE)
_OUTPUT_HEADER_RE = re.compile(r"^Output:\n", re.MULTILINE)


def _annotate_running_non_tty(parsed: dict[str, Any], result: Any) -> Any:
    if parsed.get("tty") or not isinstance(result, str):
        return result
    header = _OUTPUT_HEADER_RE.search(result)
    head_end = len(result) if header is None else header.start()
    if _PROCESS_RUNNING_RE.search(result, 0, head_end) is None:
        return result
    notice = _RUNNING_NON_TTY_NOTICE
    requested = parsed.get("yield_time_ms")
    if isinstance(requested, int | float) and requested > PTY_YIELD_TIME_MS_MAX:
        notice = (
            f"Note: yield_time_ms={int(requested)} was capped at {PTY_YIELD_TIME_MS_MAX} "
            f"({_EXEC_YIELD_CAP_S} s). " + notice.removeprefix("Note: ")
        )
    if header is None:
        return f"{result}\n{notice}"
    return f"{result[: header.end()]}{notice}\n{result[header.end() :]}"


def _wrap_exec_command(tool: FunctionTool) -> FunctionTool:
    invoke_tool = tool.on_invoke_tool
    tool.description = f"{tool.description.rstrip()} {_EXEC_COMMAND_DESCRIPTION_NOTE}"

    async def invoke(ctx: Any, raw_input: str) -> Any:
        try:
            parsed = json.loads(raw_input)
        except (json.JSONDecodeError, TypeError):
            parsed = None
        if isinstance(parsed, dict):
            if "shell" not in parsed:
                parsed["shell"] = "bash"
            _apply_shell_output_cap(parsed)
            raw_input = json.dumps(parsed)
        try:
            result = await invoke_tool(ctx, raw_input)
        except ValidationError as exc:
            return _format_validation_error(tool.name, exc)
        except InvalidManifestPathError as exc:
            rel = exc.context.get("rel", "?")
            return (
                "exec_command: workdir must be a path inside /workspace "
                "(or omitted to use the turn's cwd). "
                f"Got: {rel!r}."
            )
        if isinstance(parsed, dict):
            return _annotate_running_non_tty(parsed, result)
        return result

    tool.on_invoke_tool = invoke
    return tool


def _wrap_write_stdin(tool: FunctionTool) -> FunctionTool:
    invoke_tool = tool.on_invoke_tool
    dead_pty_session_ids: set[int] = set()

    async def invoke(ctx: Any, raw_input: str) -> Any:
        parsed: dict[str, Any] | None
        try:
            raw_parsed: Any = json.loads(raw_input)
        except json.JSONDecodeError:
            parsed = None
        else:
            parsed = cast("dict[str, Any]", raw_parsed) if isinstance(raw_parsed, dict) else None
        session_id = parsed.get("session_id") if isinstance(parsed, dict) else None
        chars = parsed.get("chars") if isinstance(parsed, dict) else None
        # An empty poll sends no input: `chars` is "" or omitted entirely (None).
        # Both must hit the dead-session guard, otherwise dropping `chars` reopens
        # the exact repeat-poll storm this wrapper exists to stop.
        is_empty_poll = chars is None or chars == ""
        if isinstance(session_id, int) and is_empty_poll and session_id in dead_pty_session_ids:
            return _WRITE_STDIN_DEAD_SESSION_RESULT_TEMPLATE.format(session_id=session_id)
        if isinstance(parsed, dict):
            if isinstance(chars, str):
                parsed["chars"] = _decode_chars_escape(chars)
            _apply_shell_output_cap(parsed)
            raw_input = json.dumps(parsed)
        try:
            result = await invoke_tool(ctx, raw_input)
        except ValidationError as exc:
            return _format_validation_error(tool.name, exc)
        if isinstance(result, str):
            # Only a result that is *exactly* the terminal failure marks the
            # session dead. A live poll whose captured output merely contains
            # this text must never poison the session (cf. the running-marker
            # guard in _annotate_running_non_tty).
            match = _PTY_SESSION_NOT_FOUND_RE.fullmatch(result.strip())
            if match is not None:
                dead_pty_session_ids.add(int(match.group("session_id")))
        return result

    tool.on_invoke_tool = invoke
    return tool
