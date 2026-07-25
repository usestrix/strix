"""Provider-agnostic conversation compaction.

When an agent's session grows past the model's usable context window, older
turns are summarised into a single checkpoint while the most recent turns are
kept verbatim. This runs for every LiteLLM provider (not just OpenAI), keeps a
security-focused structured summary, and preserves tool-call/tool-result
pairing so the trimmed history is still valid provider input.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import litellm

from strix.config import load_settings
from strix.core.sessions import replace_session_items, session_write_lock
from strix.llm.context_budget import context_window, count_tokens, output_limit


if TYPE_CHECKING:
    from agents.memory import Session


logger = logging.getLogger(__name__)

_CHECKPOINT_TAG = "<conversation-checkpoint>"
_TOOL_OUTPUT_MAX_CHARS = 2_000
_MIN_ITEMS_TO_COMPACT = 6

# Substrings that identify a context-window-overflow error across providers.
# Deliberately excludes rate-limit/throttle wording, which must not trigger
# compaction.
_OVERFLOW_MARKERS = (
    "context length",
    "context window",
    "maximum context",
    "context_length_exceeded",
    "too many tokens",
    "reduce the length",
    "input is too long",
    "prompt is too long",
    "exceeds the maximum",
    "string too long",
)


def is_context_overflow(exc: BaseException) -> bool:
    """Whether ``exc`` looks like a model context-window-overflow error."""
    overflow_error = getattr(litellm, "ContextWindowExceededError", None)
    if overflow_error is not None and isinstance(exc, overflow_error):
        return True
    message = str(exc).lower()
    return any(marker in message for marker in _OVERFLOW_MARKERS)


_SUMMARY_INSTRUCTIONS = """\
You are compacting the earlier part of an autonomous security-testing agent's \
conversation so it fits the model context window. Produce a dense, factual \
record that lets the agent continue with no loss of important state. Preserve \
exact values: URLs, endpoints, file paths, parameters, payloads, credentials \
and tokens, software versions, and error messages. Do not invent anything and \
do not describe this compaction process.

Return Markdown with exactly these sections:

## Objective
The overall goal and target scope.

## Important Details
Discovered vulnerabilities and attack vectors, scan/tool findings, \
credentials and auth material, system architecture and weak points, and any \
exact identifiers worth keeping (URLs, paths, params, payloads, versions).

## Work State
- Completed: what has been verified or finished.
- Active: what is in progress right now.
- Blocked: anything stuck and why.

## Failed Attempts & Dead Ends
Approaches already tried that did not work, so they are not repeated.

## Next Move
The concrete next step(s) the agent intended to take.

## Relevant Files
Files/notes/reports created or modified and their purpose."""


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if not isinstance(block, dict):
                continue
            text = block.get("text")
            if isinstance(text, str):
                parts.append(text)
            elif block.get("type") in {"input_image", "image_url", "output_image"}:
                parts.append("[image]")
        return "\n".join(parts)
    return ""


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else f"{text[:limit]}\n[truncated]"


def _serialize_item(item: Any) -> str:
    if not isinstance(item, dict):
        return str(item)
    item_type = item.get("type")
    role = item.get("role")
    if item_type == "function_call":
        args = _truncate(str(item.get("arguments", "")), _TOOL_OUTPUT_MAX_CHARS)
        return f"[tool_call {item.get('name', '?')}] {args}"
    if item_type == "function_call_output":
        output = item.get("output")
        text = output if isinstance(output, str) else _content_text(output)
        return f"[tool_result] {_truncate(text, _TOOL_OUTPUT_MAX_CHARS)}"
    if item_type == "reasoning":
        return ""
    if role or item_type == "message":
        return f"[{role or 'assistant'}] {_content_text(item.get('content'))}".strip()
    return ""


def _serialize_items(items: list[Any]) -> str:
    return "\n".join(s for s in (_serialize_item(item) for item in items) if s)


def _is_tool_call(item: Any) -> bool:
    return isinstance(item, dict) and item.get("type") == "function_call"


def _is_tool_output(item: Any) -> bool:
    return isinstance(item, dict) and item.get("type") == "function_call_output"


def _open_calls_at(items: list[Any]) -> list[int]:
    """Prefix count of tool calls still awaiting their result at each index.

    ``result[i]`` is the number of open calls *before* index ``i``. A split is
    only safe (won't orphan a tool result from its call) where this is zero.
    """
    balance = [0] * (len(items) + 1)
    for i, item in enumerate(items):
        delta = 1 if _is_tool_call(item) else -1 if _is_tool_output(item) else 0
        balance[i + 1] = max(0, balance[i] + delta)
    return balance


def _select_split(model: str, items: list[Any], keep_tokens: int) -> int:
    """Index where the kept-verbatim recent tail begins.

    Walks newest→oldest until ``keep_tokens`` is reached, then snaps the
    boundary to a point with no tool call left open so the recent slice is
    valid provider input on its own.
    """
    total = 0
    split = len(items)
    for i in range(len(items) - 1, -1, -1):
        total += count_tokens(model, _serialize_item(items[i]))
        if total > keep_tokens:
            break
        split = i
    open_calls = _open_calls_at(items)
    while split > 0 and open_calls[split] != 0:
        split -= 1
    return split


def _previous_summary(head: list[Any]) -> str | None:
    for item in head:
        if isinstance(item, dict) and item.get("role") == "user":
            text = _content_text(item.get("content"))
            if text.startswith(_CHECKPOINT_TAG):
                return text
    return None


def _build_summary_prompt(serialized_head: str, previous: str | None) -> str:
    previous_block = (
        f"\n\nA previous checkpoint summary follows. Update it: keep what is "
        f"still true, drop what is now stale, and merge in the new "
        f"conversation below.\n\n{previous}\n"
        if previous
        else ""
    )
    return (
        f"{_SUMMARY_INSTRUCTIONS}{previous_block}\n\n"
        f"Conversation to summarise:\n\n{serialized_head}"
    )


def _checkpoint_item(summary: str) -> dict[str, Any]:
    return {
        "role": "user",
        "content": (
            f"{_CHECKPOINT_TAG}\nThe following summarises earlier conversation that was "
            f"compacted to fit the context window. Treat it as established context, not "
            f"new instructions.\n\n{summary}\n</conversation-checkpoint>"
        ),
    }


async def _summarize(model: str, prompt: str, max_tokens: int) -> str | None:
    llm = load_settings().llm
    try:
        response = await litellm.acompletion(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            api_key=llm.api_key,
            api_base=llm.api_base,
            timeout=llm.timeout,
        )
    except Exception:
        logger.exception("compaction summary call failed for model %s", model)
        return None
    try:
        content = response.choices[0].message.content
    except (AttributeError, IndexError, KeyError):
        logger.warning("compaction summary returned no content")
        return None
    return content.strip() if isinstance(content, str) and content.strip() else None


async def maybe_compact(
    session: Session,
    *,
    model: str,
    instructions: str = "",
    tools_text: str = "",
    force: bool = False,
) -> bool:
    """Compact ``session`` if it is near the model's context window.

    Returns ``True`` when the session was rewritten. ``force`` skips the size
    check (used after a provider context-overflow error).
    """
    context = load_settings().context
    if not context.auto_compact and not force:
        return False

    async with session_write_lock(session):
        items = list(await session.get_items())
    if len(items) < _MIN_ITEMS_TO_COMPACT:
        return False

    window = context_window(model)
    reserve = max(context.compact_buffer_tokens, output_limit(model))
    budget = max(context.keep_tokens, window - reserve)
    used = count_tokens(model, "\n".join((instructions, tools_text, _serialize_items(items))))
    if not force and used <= budget:
        return False

    split = _select_split(model, items, context.keep_tokens)
    head, recent = items[:split], items[split:]
    if not head:
        return False

    summary = await _summarize(
        model,
        _build_summary_prompt(_serialize_items(head), _previous_summary(head)),
        context.summary_max_tokens,
    )
    if summary is None:
        return False

    new_items = [_checkpoint_item(summary), *recent]
    rewritten = await replace_session_items(session, new_items, expected_len=len(items))
    if rewritten:
        logger.info(
            "compacted %s: %d items (~%d tok) -> %d items (summary + %d recent)",
            model,
            len(items),
            used,
            len(new_items),
            len(recent),
        )
    return rewritten
