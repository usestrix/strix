"""Keep replayed tool-call arguments valid JSON.

A model occasionally emits a tool call whose ``arguments`` string is not a
JSON object (truncated, unbalanced, empty). The call itself fails safely: the
tool reports the parse error and the run continues. But the raw string is
recorded in the session as-is, and strict OpenAI-compatible servers (vLLM,
SGLang, ...) validate every assistant tool call in the request, so from then
on each turn is rejected with ``Assistant tool call function.arguments must
be valid JSON`` and the agent can never recover. Rewriting the replayed
arguments to a JSON object that carries the original text keeps the history
valid while the model still sees what it sent.
"""

from __future__ import annotations

import json
from typing import Any

from openai.types.responses import ResponseFunctionToolCall


MALFORMED_ARGUMENTS_KEY = "malformed_arguments"


def describe_malformed_arguments(tool_name: str, arguments: str) -> str | None:
    """Return a model-facing recovery message if ``arguments`` is not a JSON object.

    A tool call whose arguments do not parse is almost always one the stream cut
    off (the server flushed a prefix of the JSON, or the client closed early),
    so instead of the SDK's generic parse-error result the model is told the
    call never ran and must be re-issued whole.
    """
    if not arguments.strip():
        return None
    try:
        parsed = json.loads(arguments)
    except ValueError as exc:
        detail = str(exc)
    else:
        if isinstance(parsed, dict):
            return None
        detail = f"expected a JSON object, got {type(parsed).__name__}"
    return (
        f"{tool_name}: the tool call was not executed because its arguments were "
        f"truncated or otherwise not valid JSON ({detail}). The response was likely "
        "cut off mid-call. Re-issue the call with complete, valid JSON arguments."
    )


def repair_arguments(arguments: object) -> str | None:
    """Return replacement arguments a strict server accepts, or ``None`` if already valid."""
    if not isinstance(arguments, str) or not arguments.strip():
        return "{}"
    try:
        parsed = json.loads(arguments)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        return None
    return json.dumps({MALFORMED_ARGUMENTS_KEY: arguments}, ensure_ascii=False)


def repair_history_arguments(items: list[Any]) -> tuple[list[Any], bool]:
    """Rewrite function calls in a conversation history whose arguments are not a JSON object."""
    rebuilt: list[Any] = []
    changed = False

    for item in items:
        if isinstance(item, dict):
            if item.get("type") == "function_call":
                repaired = repair_arguments(item.get("arguments"))
                if repaired is not None:
                    item = {**item, "arguments": repaired}  # noqa: PLW2901
                    changed = True
        elif isinstance(item, ResponseFunctionToolCall):
            repaired = repair_arguments(item.arguments)
            if repaired is not None:
                item = item.model_copy(update={"arguments": repaired})  # noqa: PLW2901
                changed = True
        rebuilt.append(item)

    return rebuilt, changed


def repair_input(model_input: str | list[Any]) -> str | list[Any]:
    if isinstance(model_input, str):
        return model_input
    rebuilt, changed = repair_history_arguments(model_input)
    return rebuilt if changed else model_input
