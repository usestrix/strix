"""Provider-agnostic conversation compaction.

When an agent's session grows past the model's usable context window, older
turns are summarised into a single checkpoint while the most recent turns are
kept verbatim. This runs for every LiteLLM provider (not just OpenAI), keeps a
security-focused structured summary, and preserves tool-call/tool-result
pairing so the trimmed history is still valid provider input.
"""

from __future__ import annotations

import logging
from functools import cache
from typing import TYPE_CHECKING, Any

from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from openai.types.responses import ResponseOutputMessage, ResponseOutputText

from strix.config import load_settings
from strix.config.models import StrixProvider
from strix.core.inputs import make_model_settings
from strix.core.sessions import replace_session_items, session_write_lock
from strix.llm.context_budget import context_window, count_tokens, output_limit


if TYPE_CHECKING:
    from agents.items import ModelResponse
    from agents.memory import Session


logger = logging.getLogger(__name__)

_CHECKPOINT_TAG = "<conversation-checkpoint>"
_TOOL_OUTPUT_MAX_CHARS = 2_000
_MIN_ITEMS_TO_COMPACT = 6
_HEAD_TRUNCATED_MARKER = "\n\n[... older conversation omitted to fit the summary request ...]\n\n"


# Providers that don't type overflow errors (OpenRouter maps every 400 to a
# plain BadRequestError) leave only the message to go on, so we match it the way
# LiteLLM's own checker does — but with rate-limit exclusions first, so a
# throttling 429 is never mistaken for an overflow and sent into compaction.
_OVERFLOW_EXCLUSIONS = (
    "rate limit",
    "too many requests",
    "throttling",
    "service unavailable",
    "quota",
)
_OVERFLOW_MARKERS = (
    "context length",
    "context window",
    "context_length_exceeded",
    "prompt is too long",
    "input is too long",
    "input length",
    "maximum prompt length",
    "reduce the length of the messages",
    "too many tokens",
    "token limit exceeded",
    "request entity too large",
)


@cache
def _overflow_error_types() -> tuple[type[BaseException], type[BaseException]]:
    """``(ContextWindowExceededError, BadRequestError)``, imported on first use.

    LiteLLM costs seconds to import, and nothing needs it until a model call is
    actually made, so it stays off the launch path.
    """
    from litellm.exceptions import BadRequestError, ContextWindowExceededError

    return ContextWindowExceededError, BadRequestError


def is_context_overflow(exc: BaseException) -> bool:
    """Whether ``exc`` is a model context-window-overflow error.

    LiteLLM types most providers' overflow as ContextWindowExceededError, but its
    OpenRouter branch raises a plain BadRequestError, so for that we fall back to
    matching the provider message.
    """
    context_window_exceeded, bad_request = _overflow_error_types()
    if isinstance(exc, context_window_exceeded):
        return True
    if isinstance(exc, bad_request):
        msg = str(exc).lower()
        if any(x in msg for x in _OVERFLOW_EXCLUSIONS):
            return False
        return any(x in msg for x in _OVERFLOW_MARKERS)
    return False


_SUMMARY_INSTRUCTIONS = """\
You are compacting the earlier part of an autonomous security-testing agent's \
conversation so it fits the model context window. Produce a dense, factual \
record that lets the agent continue with no loss of important state.

This is a security engagement: dropped findings mean lost vulnerabilities. Be \
EXHAUSTIVE, not concise. Enumerate every distinct item as its own bullet — \
never merge, deduplicate, generalise, or omit distinct findings, credentials, \
or dead ends, even if they seem minor or repetitive. If the source mentions \
five vulnerabilities, list five. Copy exact values verbatim: URLs, endpoints, \
file paths, parameters, payloads, credentials, tokens, keys, hashes, cracked \
passwords, software versions, and error messages — never paraphrase or \
placeholder them. Do not invent anything and do not describe this compaction \
process.

Return Markdown with exactly these sections:

## Objective
The overall goal and target scope.

## Vulnerabilities & Findings
One bullet per DISTINCT vulnerability or finding (SQLi, XSS, SSRF, auth bypass, \
misconfig, etc.). For each: type, exact location (URL/endpoint/param/file), the \
verbatim payload or proof, confirmation status, and impact. List them all.

## Credentials & Secrets
One bullet per credential, secret, API key, token, hash, or cracked password, \
copied verbatim with where it applies. Write "(none)" only if truly none.

## System & Recon Details
Architecture, tech stack, versions, discovered endpoints/paths/params, and \
other weak points worth keeping.

## Work State
- Completed: what has been verified or finished.
- Active: what is in progress right now.
- Blocked: anything stuck and why.

## Failed Attempts & Dead Ends
One bullet per approach already tried that did not work (including WAF blocks, \
filtered inputs, non-exploitable leads) so they are not repeated. Write \
"(none)" only if truly none.

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
    """Prefix count of tool calls still awaiting their result at each index;
    a split is only safe where this is zero."""
    balance = [0] * (len(items) + 1)
    for i, item in enumerate(items):
        delta = 1 if _is_tool_call(item) else -1 if _is_tool_output(item) else 0
        balance[i + 1] = max(0, balance[i] + delta)
    return balance


def _select_split(model: str, items: list[Any], keep_tokens: int) -> int:
    """Index where the kept-verbatim recent tail begins: walk newest→oldest to
    ``keep_tokens``, then snap to a point with no tool call left open."""
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


def _fit_to_tokens(model: str, text: str, max_tokens: int) -> str:
    """Head+tail-truncate ``text`` to ``max_tokens``, keeping start and end."""
    if count_tokens(model, text) <= max_tokens:
        return text
    # Rough char budget (~4x tokens), then tighten by real token count.
    budget_chars = max_tokens * 4
    head_chars = budget_chars // 2
    tail_chars = budget_chars - head_chars
    candidate = text[:head_chars] + _HEAD_TRUNCATED_MARKER + text[len(text) - tail_chars :]
    while count_tokens(model, candidate) > max_tokens and (head_chars > 0 or tail_chars > 0):
        head_chars = int(head_chars * 0.8)
        tail_chars = int(tail_chars * 0.8)
        candidate = text[:head_chars] + _HEAD_TRUNCATED_MARKER + text[len(text) - tail_chars :]
    return candidate


def _summary_output_tokens(model: str) -> int:
    """Summary output allowance, capped at the model's own output limit."""
    return min(load_settings().context.summary_max_tokens, output_limit(model))


def _summary_input_budget(model: str, previous: str | None) -> int:
    """Token room left for the head after instructions and the summary output."""
    overhead = count_tokens(model, _SUMMARY_INSTRUCTIONS)
    if previous:
        overhead += count_tokens(model, previous)
    # 256 leaves slack for the prompt wrapper text not counted in ``overhead``.
    room = context_window(model) - _summary_output_tokens(model) - overhead - 256
    return max(0, room)


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


def _extract_text(response: ModelResponse) -> str:
    parts: list[str] = []
    for item in response.output:
        if not isinstance(item, ResponseOutputMessage):
            continue
        parts.extend(
            chunk.text
            for chunk in item.content
            if isinstance(chunk, ResponseOutputText) and chunk.text
        )
    return "".join(parts)


async def _summarize(model: str, prompt: str, max_tokens: int) -> str | None:
    llm = load_settings().llm
    model_settings = make_model_settings(
        None,
        model_name=model,
        request_timeout=llm.timeout,
        prompt_cache=False,
        extra_headers=llm.extra_headers,
        has_tools=False,
    ).resolve(ModelSettings(max_tokens=max_tokens))
    try:
        response = (
            await StrixProvider()
            .get_model(model)
            .get_response(
                system_instructions=None,
                input=prompt,
                model_settings=model_settings,
                tools=[],
                output_schema=None,
                handoffs=[],
                tracing=ModelTracing.DISABLED,
                previous_response_id=None,
                conversation_id=None,
                prompt=None,
            )
        )
    except Exception:
        logger.exception("compaction summary call failed for model %s", model)
        return None
    content = _extract_text(response).strip()
    if not content:
        logger.warning("compaction summary returned no content")
        return None
    return content


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
    previous = _previous_summary(head)
    input_budget = _summary_input_budget(model, previous)
    if not head or input_budget <= 0:
        # Nothing to summarise, or no room for even the summary request itself.
        if head:
            logger.warning(
                "skipping compaction for %s: no room to summarise within its context window", model
            )
        return False

    serialized_head = _fit_to_tokens(model, _serialize_items(head), input_budget)
    summary = await _summarize(
        model,
        _build_summary_prompt(serialized_head, previous),
        _summary_output_tokens(model),
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
