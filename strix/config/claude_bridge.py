"""Pure translation between Strix's Agents-SDK I/O and ``claude -p`` structured output.

No subprocess, no network, this module is a function of bytes to objects, so it
tests against recorded ``claude -p`` transcripts with no live calls.

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
import math
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
    sections.append(_task_section(tools=bool(tool_block)))
    return "\n\n".join(sections)


def _task_section(*, tools: bool) -> str:
    """Closing instruction. A tool-less turn is a plain completion, not an agent step.

    Strix calls this backend two ways: agent turns, which carry tools and must
    reply in the ``{text, tool_calls}`` schema, and one-shot completions with
    ``tools=[]`` (deduplication, preflight) whose callers parse the reply
    themselves. Handing the second kind the agent framing makes the model narrate
    a "step" instead of answering, which is why dedupe could never find the JSON
    object it asked for.
    """
    if not tools:
        return (
            "# Your task\n\n"
            "Answer the request above directly. Reply with the answer itself and "
            "nothing else, in exactly the format the instructions ask for."
        )
    return (
        "# Your task\n\n"
        "Produce the next single assistant step. Put your narration in `text`. "
        "To act, list the tools to run in `tool_calls` using the exact names and "
        "argument shapes above. Request only tools you need this step; leave "
        "`tool_calls` empty when no action is needed or the task is done."
    )


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


# The block types the rest of Strix already treats as images: llm/compaction.py
# and interface/tui/live_view.py match on exactly these, core/sessions.py on the
# input_image the SDK's sandbox tools emit. Matching a stray ``image_url`` or
# ``source`` key instead swallows any text block that happens to carry one.
_IMAGE_BLOCK_TYPES = frozenset({"image", "image_url", "input_image", "output_image"})

_IMAGE_MARKER = "[image returned by tool, not visible to this backend]"


def _stringify(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return _stringify_blocks(content)
    return json.dumps(content)


def _stringify_blocks(blocks: Any) -> str:
    """Render a content-block list, marking the images this bridge cannot carry."""
    parts: list[str] = []
    for block in blocks:
        block_dict = _as_dict(block)
        if _is_image_block(block_dict):
            # This text bridge cannot carry an image to claude -p. Emit an
            # explicit marker rather than dropping it silently, so the model
            # knows a screenshot was produced and does not narrate having
            # inspected one it never received.
            parts.append(_IMAGE_MARKER)
            continue
        text = block_dict.get("text") or block_dict.get("output") or block_dict.get("content")
        if isinstance(text, str):
            parts.append(text)
        elif text is not None:
            parts.append(json.dumps(text))
    return "\n".join(parts)


def _is_image_block(block: dict[str, Any]) -> bool:
    return str(block.get("type") or "").lower() in _IMAGE_BLOCK_TYPES


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
        # Only a reply shaped like RESULT_SCHEMA is our envelope. A tool-less turn
        # returns the caller's own answer, which is frequently a JSON object of its
        # own (dedupe asks for one); treating that as the envelope would read its
        # missing "text" key as an empty response and discard the answer.
        if isinstance(parsed, dict) and ("text" in parsed or "tool_calls" in parsed):
            return cast("dict[str, Any]", parsed)
        return {"text": raw, "tool_calls": []}
    return {"text": "", "tool_calls": []}


def _strip_namespace(name: str) -> str:
    # If an MCP-based transport ever surfaces prefixed names (mcp__strix__shell),
    # the run loop only knows the bare tool name it registered.
    if name.startswith("mcp__"):
        return name.rsplit("__", 1)[-1]
    return name


# Phrases Claude Code uses when the account may not run inference on the plan at
# all -- an org policy, a plan change, or revoked entitlement. Observed verbatim:
# "Your organization has disabled Claude subscription access for Claude Code -
#  Use an Anthropic API key instead, or ask your admin to enable access".
_ENTITLEMENT_MARKERS = (
    "subscription access for claude code",
    "disabled claude subscription access",
    "use an anthropic api key instead",
)


def _error_status(result: dict[str, Any]) -> int | None:
    explicit = result.get("api_error_status")
    if isinstance(explicit, int):
        return explicit
    haystack = f"{result.get('result', '')} {result.get('subtype', '')}".lower()
    if any(marker in haystack for marker in _ENTITLEMENT_MARKERS):
        # 403, so the run stops instead of retrying. These arrive with no
        # api_error_status, and an untagged error hits the statusless fallback --
        # five attempts with 2s..90s backoff, per turn, per agent, for something
        # a second attempt cannot clear.
        return 403
    if "429" in haystack or "rate limit" in haystack or "rate_limit" in haystack:
        return 429
    if "overloaded" in haystack or "529" in haystack:
        return 529
    return None


def _finite_number(value: Any) -> float | None:
    """``value`` as a float when it is a real, finite number, else None.

    Everything here is decoded from CLI stdout, and ``json.loads`` accepts the
    non-standard ``Infinity``/``NaN`` literals, so a malformed field would
    otherwise reach the accounting layer as an unusable float. ``bool`` is
    excluded explicitly because it is an ``int`` subclass.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _token_count(data: dict[str, Any], key: str) -> int:
    """Non-negative token count for ``key``, tolerating a malformed payload.

    A field that is missing, null, or not a finite number degrades to zero: a
    usage block Strix cannot read is a reporting problem, not a reason to fail an
    agent turn that already succeeded. A value that is present but unreadable is
    logged, so a wire-format change shows up as something other than silence.
    """
    raw = data.get(key)
    number = _finite_number(raw)
    if number is None:
        if raw is not None:
            logger.debug("unreadable claude -p usage field %s: %r", key, raw)
        return 0
    return max(0, int(number))


def _thinking_tokens(data: dict[str, Any]) -> int:
    """Extended-thinking tokens, which Anthropic nests under output_tokens_details."""
    details = data.get("output_tokens_details")
    if not isinstance(details, dict):
        return 0
    return _token_count(cast("dict[str, Any]", details), "thinking_tokens")


def _decode_usage(raw: Any) -> Usage:
    data: dict[str, Any] = cast("dict[str, Any]", raw) if isinstance(raw, dict) else {}
    cached = _token_count(data, "cache_read_input_tokens")
    cache_write = _token_count(data, "cache_creation_input_tokens")
    # Anthropic reports input_tokens EXCLUDING both cache counters. Every other
    # Strix route normalizes through LiteLLM, whose Anthropic transformation does
    # `prompt_tokens += cache_creation_input_tokens + cache_read_input_tokens`, so
    # reporting the bare number here undercounts a cache-heavy turn by orders of
    # magnitude (a real turn measured 143 tokens against an actual 7396) and
    # starves the budget guard on a metered session.
    input_tokens = _token_count(data, "input_tokens") + cached + cache_write
    output_tokens = _token_count(data, "output_tokens")
    return Usage(
        requests=1,
        input_tokens=input_tokens,
        input_tokens_details=InputTokensDetails(
            cached_tokens=cached, cache_write_tokens=cache_write
        ),
        output_tokens=output_tokens,
        output_tokens_details=OutputTokensDetails(reasoning_tokens=_thinking_tokens(data)),
        # Derived, never read back from the payload: a `total_tokens` the CLI
        # supplied would carry Anthropic's cache-excluding semantics and reopen
        # the same undercount.
        total_tokens=input_tokens + output_tokens,
    )


def result_cost(result: dict[str, Any]) -> float | None:
    """The dollar cost Claude Code computed for this turn, or None.

    Authoritative in a way a local estimate is not: the CLI prices every model the
    turn touched (it may dispatch a cheaper side model of its own) at that model's
    real rate, whereas Strix would have to guess a single rate from a
    ``claude-code/<slug>`` name LiteLLM does not carry a first-party price for.

    On a subscription the ledger discards this; on an API-key session it is the
    charge the budget guard has to see, so an unreadable value must read as
    "nothing to record" rather than reach the guard.
    """
    cost = _finite_number(result.get("total_cost_usd"))
    return cost if cost is not None and cost > 0 else None
