"""Tests for context-window tool-output helpers."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock

import pytest

from strix.core.sessions import truncate_large_outputs_in_session
from strix.core.tool_output import _hard_cap, is_context_window_error, truncate_tool_output


def test_is_context_window_error_by_class_name() -> None:
    class ContextWindowExceededError(Exception):
        status_code = 400

    assert is_context_window_error(ContextWindowExceededError("boom"))


def test_is_context_window_error_by_message() -> None:
    err = Exception("This model's maximum context length is 1000000 tokens")
    assert is_context_window_error(err)
    assert is_context_window_error(Exception("1,023,797 tokens > 1,000,000 max"))


def test_is_context_window_error_false_for_other_400() -> None:
    class BadRequestError(Exception):
        status_code = 400

    assert not is_context_window_error(BadRequestError("invalid image"))


def test_truncate_disabled_when_max_non_positive() -> None:
    text = "x" * 100_000
    assert truncate_tool_output(text, 0) == text
    assert truncate_tool_output(text, -1) == text


def test_truncate_passes_small_text_through() -> None:
    assert truncate_tool_output("hello", 100) == "hello"


def test_truncate_json_array_keeps_prefix_records() -> None:
    payload = [{"id": i, "msg": "finding"} for i in range(200)]
    raw = json.dumps(payload)
    out = truncate_tool_output(raw, max_chars=4_000, max_json_records=50)
    assert "truncated JSON array" in out
    assert "showing" in out
    # Must be valid-ish truncated payload under the cap.
    assert len(out) <= 4_000 or out.endswith("...[truncated]")
    assert "finding" in out


def test_truncate_text_by_lines() -> None:
    # Each line is long enough that the full dump exceeds max_chars, so the
    # line-cap path runs (short lines under the char budget are left alone).
    lines = [f"line-{i}-" + ("x" * 80) for i in range(1_000)]
    raw = "\n".join(lines)
    out = truncate_tool_output(raw, max_chars=20_000, max_lines=300)
    assert "truncated" in out
    assert "line-0-" in out
    assert "line-999-" not in out
    assert len(out) < len(raw)
    assert len(out) <= 20_000 or out.endswith("...[truncated]")


def test_truncate_hard_char_cap() -> None:
    raw = "a" * 10_000
    out = truncate_tool_output(raw, max_chars=500, max_lines=10_000)
    assert len(out) <= 500
    assert "truncated" in out


def test_hard_cap_never_exceeds_limit() -> None:
    huge = "x" * 10_000
    for cap in (1, 5, 16, 100, 500):
        out = _hard_cap(huge, cap)
        assert len(out) <= cap


@pytest.mark.asyncio
async def test_truncate_session_restores_history_on_write_failure() -> None:
    huge = "z" * 100_000
    original = [
        {
            "type": "function_call_output",
            "call_id": "c1",
            "output": huge,
        }
    ]
    session = _FakeSession(original)
    session.add_items = AsyncMock(side_effect=[RuntimeError("disk full"), None])

    with pytest.raises(RuntimeError, match="disk full"):
        await truncate_large_outputs_in_session(session, max_chars=1_000)  # type: ignore[arg-type]

    # clear (wipe) + failed add + clear (restore prep) + restore previous
    assert session.clear_session.await_count == 2
    assert session.add_items.await_count == 2
    restored = session.add_items.await_args_list[1].args[0]
    assert restored == original


class _FakeSession:
    def __init__(self, items: list[Any]) -> None:
        self._items = items
        self.clear_session = AsyncMock()
        self.add_items = AsyncMock()

    async def get_items(self) -> list[Any]:
        return list(self._items)


@pytest.mark.asyncio
async def test_truncate_large_outputs_in_session_rewrites_string_output() -> None:
    huge = "z" * 100_000
    session = _FakeSession(
        [
            {
                "type": "function_call_output",
                "call_id": "c1",
                "output": huge,
            },
            {"type": "message", "role": "user", "content": "ok"},
        ]
    )
    changed = await truncate_large_outputs_in_session(session, max_chars=1_000)  # type: ignore[arg-type]
    assert changed is True
    session.clear_session.assert_awaited_once()
    session.add_items.assert_awaited_once()
    rewritten = session.add_items.await_args.args[0]
    assert rewritten[0]["type"] == "function_call_output"
    assert len(rewritten[0]["output"]) < len(huge)
    assert "truncated" in rewritten[0]["output"]


@pytest.mark.asyncio
async def test_truncate_large_outputs_noop_when_small() -> None:
    session = _FakeSession(
        [
            {
                "type": "function_call_output",
                "call_id": "c1",
                "output": "tiny",
            }
        ]
    )
    changed = await truncate_large_outputs_in_session(session, max_chars=1_000)  # type: ignore[arg-type]
    assert changed is False
    session.clear_session.assert_not_awaited()


def test_is_context_window_error_walks_cause_chain() -> None:
    root = Exception("context window exceeded by model")
    wrapped = RuntimeError("provider failed")
    wrapped.__cause__ = root
    assert is_context_window_error(wrapped)


def test_execution_skips_image_strip_predicate() -> None:
    """Sanity: 400 alone is not enough to classify as context overflow."""

    class Fake400Error(Exception):
        status_code = 400

    assert not is_context_window_error(Fake400Error("image rejected"))
