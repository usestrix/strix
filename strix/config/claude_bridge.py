"""Pure translation between Strix's Agents-SDK I/O and ``claude -p`` structured output.

No subprocess, no network — this module is a function of bytes to objects, so it
tests against recorded ``claude -p`` transcripts with no live calls. See
``.artifacts/SPIKE-DECISION.md`` for the 4b protocol these functions implement.

The contract with Claude Code (driven via ``--json-schema`` + ``--tools ""``):
Strix renders one turn's worth of history and tool descriptions into a single
text prompt; Claude Code replies with exactly

    {"text": "<assistant prose>", "tool_calls": [{"name": ..., "arguments": {...}}, ...]}

in the terminal ``result`` line's ``structured_output``. We fold that back into
a :class:`ModelResponse` carrying an assistant message plus one
``ResponseFunctionToolCall`` per requested call.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

from agents.items import ModelResponse
from agents.usage import Usage
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)
from openai.types.responses.response_usage import InputTokensDetails, OutputTokensDetails


if TYPE_CHECKING:
    from collections.abc import Iterable

    from agents.items import TResponseInputItem
    from agents.tool import Tool


logger = logging.getLogger(__name__)

# Schema handed to ``claude --json-schema``; the model's reply is forced into it.
RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "text": {
            "type": "string",
            "description": "Your reasoning and narration for this single step.",
        },
        "tool_calls": {
            "type": "array",
            "description": "Tools to run this step. Empty when the task is complete.",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "arguments": {"type": "object"},
                },
                "required": ["name", "arguments"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["text", "tool_calls"],
    "additionalProperties": False,
}


class ClaudeStreamError(RuntimeError):
    """A ``claude -p`` turn failed. ``status_code`` classifies it for the retry policy."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


# --------------------------------------------------------------------------- #
# Request encoding: Strix history + tools -> one text prompt
# --------------------------------------------------------------------------- #


def build_prompt(
    system_instructions: str | None,
    input: str | list[TResponseInputItem],  # noqa: A002
    tools: list[Tool],
) -> str:
    """Render one turn into the single text blob fed to ``claude -p`` on stdin."""
    sections: list[str] = []
    if system_instructions:
        sections.append("# System instructions\n\n" + system_instructions.strip())
    tool_block = _render_tools(tools)
    if tool_block:
        sections.append(tool_block)
    sections.append("# Conversation\n\n" + _render_input(input))
    sections.append(
        "# Your task\n\n"
        "Produce the next single assistant step. Put your narration in `text`. "
        "To act, list the tools to run in `tool_calls` using the exact names and "
        "argument shapes above. Request only tools you need this step; leave "
        "`tool_calls` empty when no action is needed or the task is done."
    )
    return "\n\n".join(sections)


def _render_tools(tools: list[Tool]) -> str:
    lines: list[str] = []
    for tool in tools:
        name = getattr(tool, "name", None)
        if not name:
            continue
        description = (getattr(tool, "description", "") or "").strip()
        schema = getattr(tool, "params_json_schema", None)
        entry = f"## {name}\n{description}".rstrip()
        if schema is not None:
            entry += "\nArguments (JSON Schema): " + json.dumps(schema, separators=(",", ":"))
        lines.append(entry)
    if not lines:
        return ""
    return "# Available tools\n\n" + "\n\n".join(lines)


def _render_input(input: str | list[TResponseInputItem]) -> str:  # noqa: A002
    if isinstance(input, str):
        return input
    rendered = [line for item in input if (line := _render_item(_as_dict(item)))]
    return "\n\n".join(rendered) if rendered else "(no prior messages)"


def _as_dict(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return cast("dict[str, Any]", item)
    dump = getattr(item, "model_dump", None)
    if callable(dump):
        result = dump()
        if isinstance(result, dict):
            return cast("dict[str, Any]", result)
    return {}


def _render_item(item: dict[str, Any]) -> str:
    itype = item.get("type")
    role = item.get("role")

    if itype in {"function_call", None} and item.get("name") and "arguments" in item:
        args = item.get("arguments")
        args_str = args if isinstance(args, str) else json.dumps(args)
        return f"[assistant tool call] {item['name']}({args_str})"

    if itype == "function_call_output" or ("call_id" in item and "output" in item):
        return f"[tool result] {_stringify(item.get('output'))}"

    if itype == "reasoning":
        return ""  # opaque; nothing useful to replay as text

    if role or itype == "message":
        speaker = str(role or "message").capitalize()
        return f"{speaker}: {_stringify(item.get('content'))}"

    return ""


def _stringify(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        blocks: list[Any] = content
        for block in blocks:
            block_dict = _as_dict(block)
            text = block_dict.get("text") or block_dict.get("output") or block_dict.get("content")
            if isinstance(text, str):
                parts.append(text)
            elif text is not None:
                parts.append(json.dumps(text))
        return "\n".join(parts)
    return json.dumps(content)


# --------------------------------------------------------------------------- #
# Response decoding: claude -p transcript -> one Strix turn
# --------------------------------------------------------------------------- #


def parse_transcript(lines: Iterable[str]) -> dict[str, Any]:
    """Return the terminal ``result`` event from a stream-json transcript.

    Non-JSON lines (Claude Code prints occasional diagnostics to stdout) are
    skipped. Raises :class:`ClaudeStreamError` if no ``result`` line is present.
    """
    result: dict[str, Any] | None = None
    for raw in lines:
        text = raw.strip()
        if not text:
            continue
        try:
            event = json.loads(text)
        except json.JSONDecodeError:
            logger.debug("skipping non-JSON claude -p line: %.120s", text)
            continue
        if isinstance(event, dict):
            event_dict = cast("dict[str, Any]", event)
            if event_dict.get("type") == "result":
                result = event_dict
    if result is None:
        raise ClaudeStreamError("claude -p produced no result event")
    return result


def decode_result(result: dict[str, Any]) -> ModelResponse:
    """Fold a terminal ``result`` event into a :class:`ModelResponse`.

    Raises :class:`ClaudeStreamError` on an error result, tagging rate-limit and
    overload failures with a retryable status code.
    """
    if result.get("is_error"):
        status = _error_status(result)
        message = _stringify(result.get("result")) or result.get("subtype") or "claude -p error"
        raise ClaudeStreamError(str(message), status_code=status)

    payload = _structured_payload(result)
    output: list[Any] = []

    text = str(payload.get("text") or "")
    if text:
        output.append(
            ResponseOutputMessage(
                id=f"msg_{uuid4().hex}",
                content=[ResponseOutputText(annotations=[], text=text, type="output_text")],
                role="assistant",
                status="completed",
                type="message",
            )
        )

    for call in cast("list[Any]", payload.get("tool_calls") or []):
        call_dict = _as_dict(call)
        name = _strip_namespace(str(call_dict.get("name") or ""))
        if not name:
            continue
        arguments = call_dict.get("arguments")
        call_id = f"call_{uuid4().hex}"
        output.append(
            ResponseFunctionToolCall(
                arguments=arguments if isinstance(arguments, str) else json.dumps(arguments or {}),
                call_id=call_id,
                name=name,
                type="function_call",
                id=call_id,
            )
        )

    return ModelResponse(
        output=output,
        usage=_decode_usage(result.get("usage")),
        response_id=result.get("session_id"),
    )


def _structured_payload(result: dict[str, Any]) -> dict[str, Any]:
    payload = result.get("structured_output")
    if isinstance(payload, dict):
        return cast("dict[str, Any]", payload)
    # Fall back to parsing the `result` string when structured_output is absent.
    raw = result.get("result")
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {"text": raw, "tool_calls": []}
        if isinstance(parsed, dict):
            return cast("dict[str, Any]", parsed)
    return {"text": "", "tool_calls": []}


def _strip_namespace(name: str) -> str:
    # If a future 4a path surfaces MCP-prefixed names (mcp__strix__shell), the run
    # loop only knows the bare tool name it registered.
    if name.startswith("mcp__"):
        return name.rsplit("__", 1)[-1]
    return name


def _error_status(result: dict[str, Any]) -> int | None:
    explicit = result.get("api_error_status")
    if isinstance(explicit, int):
        return explicit
    haystack = f"{result.get('result', '')} {result.get('subtype', '')}".lower()
    if "429" in haystack or "rate limit" in haystack or "rate_limit" in haystack:
        return 429
    if "overloaded" in haystack or "529" in haystack:
        return 529
    return None


def _decode_usage(raw: Any) -> Usage:
    data: dict[str, Any] = cast("dict[str, Any]", raw) if isinstance(raw, dict) else {}
    input_tokens = int(data.get("input_tokens") or 0)
    output_tokens = int(data.get("output_tokens") or 0)
    cached = int(data.get("cache_read_input_tokens") or 0)
    cache_write = int(data.get("cache_creation_input_tokens") or 0)
    total = data.get("total_tokens")
    return Usage(
        requests=1,
        input_tokens=input_tokens,
        input_tokens_details=InputTokensDetails(
            cached_tokens=cached, cache_write_tokens=cache_write
        ),
        output_tokens=output_tokens,
        output_tokens_details=OutputTokensDetails(reasoning_tokens=0),
        total_tokens=int(total) if isinstance(total, int) else input_tokens + output_tokens,
    )
