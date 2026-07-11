"""Helpers for capping tool outputs that would blow the LLM context window."""

from __future__ import annotations

import json
import logging
import re
from typing import Any


logger = logging.getLogger(__name__)

# Defaults match the practical ceiling used in community fix PR #583.
DEFAULT_MAX_TOOL_OUTPUT_CHARS = 65_536
DEFAULT_MAX_JSON_RECORDS = 50
DEFAULT_MAX_LINES = 300

_CONTEXT_WINDOW_MARKERS = (
    "contextwindowexceeded",
    "context window",
    "context_length",
    "maximum context",
    "max context",
    "prompt is too long",
    "prompt too long",
    "input is too long",
    "too many tokens",
    "token limit",
    "maximum number of tokens",
)


def is_context_window_error(exc: BaseException) -> bool:
    """Return True when ``exc`` indicates an LLM context-window overflow."""
    name = type(exc).__name__.lower()
    if "contextwindow" in name.replace("_", ""):
        return True

    # Walk the exception chain (LiteLLM often wraps provider errors).
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        text = str(current).lower()
        if any(marker in text for marker in _CONTEXT_WINDOW_MARKERS):
            return True
        # "1,023,797 tokens > 1,000,000" style messages
        if re.search(r"\d[\d,]*\s*tokens?\s*>\s*\d", text):
            return True
        current = current.__cause__ or current.__context__  # type: ignore[assignment]
    return False


def truncate_tool_output(
    text: str,
    max_chars: int,
    *,
    max_json_records: int = DEFAULT_MAX_JSON_RECORDS,
    max_lines: int = DEFAULT_MAX_LINES,
) -> str:
    """Cap a tool result string so it can fit in subsequent model turns.

    ``max_chars <= 0`` disables truncation. Prefer structured JSON trimming
    when the payload is a JSON array (typical of scanners like semgrep);
    otherwise keep the first ``max_lines`` lines, then hard-cap by chars.
    """
    if max_chars <= 0 or len(text) <= max_chars:
        return text

    original_len = len(text)
    stripped = text.lstrip()
    if stripped.startswith(("[", "{")):
        truncated_json = _truncate_json_payload(
            stripped,
            max_chars=max_chars,
            max_json_records=max_json_records,
            original_len=original_len,
        )
        if truncated_json is not None:
            return truncated_json

    return _truncate_text_payload(
        text,
        max_chars=max_chars,
        max_lines=max_lines,
        original_len=original_len,
    )


def _hard_cap(text: str, max_chars: int) -> str:
    """Return ``text`` guaranteed to be at most ``max_chars`` characters."""
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    marker = "\n...[truncated]"
    if max_chars <= len(marker):
        return text[:max_chars]
    return text[: max_chars - len(marker)] + marker


def _truncate_json_array(
    data: list[Any],
    *,
    max_chars: int,
    max_json_records: int,
    original_len: int,
) -> str:
    total = len(data)
    kept = data[: max(1, max_json_records)]
    # Shrink further if even the first records exceed the char budget.
    while kept:
        body = json.dumps(kept, ensure_ascii=False, indent=2)
        header = (
            f"[truncated JSON array: showing {len(kept)}/{total} records; "
            f"original {original_len} chars. Re-run with a narrower path/"
            f"rule filter or write results to a file and inspect samples.]\n"
        )
        candidate = header + body
        if len(candidate) <= max_chars:
            return candidate
        if len(kept) == 1:
            return _hard_cap(candidate, max_chars)
        kept = kept[: max(1, len(kept) // 2)]
    return _hard_cap(json.dumps(data[:1], ensure_ascii=False), max_chars)


def _truncate_json_object(
    data: dict[str, Any],
    *,
    max_chars: int,
    max_json_records: int,
    original_len: int,
) -> str:
    body = json.dumps(data, ensure_ascii=False, indent=2)
    if len(body) <= max_chars:
        return body
    header = (
        f"[truncated JSON object; original {original_len} chars. "
        f"Write full output to a file and inspect targeted fields.]\n"
    )
    slim: dict[str, Any] = {}
    candidate = header + "{}"
    for key, value in data.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            slim[key] = value
        elif isinstance(value, list):
            slim[key] = value[: max(1, max_json_records)]
            slim[f"{key}__truncated"] = True
        else:
            slim[key] = f"<{type(value).__name__} omitted>"
        candidate = header + json.dumps(slim, ensure_ascii=False, indent=2)
        if len(candidate) > max_chars:
            break
    return _hard_cap(candidate, max_chars)


def _truncate_json_payload(
    text: str,
    *,
    max_chars: int,
    max_json_records: int,
    original_len: int,
) -> str | None:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None

    if isinstance(data, list):
        return _truncate_json_array(
            data,
            max_chars=max_chars,
            max_json_records=max_json_records,
            original_len=original_len,
        )
    if isinstance(data, dict):
        return _truncate_json_object(
            data,
            max_chars=max_chars,
            max_json_records=max_json_records,
            original_len=original_len,
        )
    return None


def _truncate_text_payload(
    text: str,
    *,
    max_chars: int,
    max_lines: int,
    original_len: int,
) -> str:
    lines = text.splitlines()
    if len(lines) > max_lines:
        head = "\n".join(lines[:max_lines])
        notice = (
            f"[truncated: showing first {max_lines}/{len(lines)} lines; "
            f"original {original_len} chars. Pipe output to a file and read "
            f"targeted sections instead of dumping everything.]\n"
        )
        candidate = notice + head
    else:
        candidate = text

    if len(candidate) <= max_chars:
        return candidate
    notice = f"[truncated to {max_chars} chars; original {original_len} chars]\n"
    marker = "\n...[truncated]"
    budget = max_chars - len(notice) - len(marker)
    if budget < 1:
        return _hard_cap(candidate, max_chars)
    return notice + candidate[:budget] + marker
