"""Tests for per-agent todo id normalization and resolution."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

import strix.tools.todo.tools as todo_tools
from strix.tools.todo.tools import _normalize_todo_ids


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _reset_todos_storage(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(todo_tools, "_todos_path", None)
    with todo_tools._todos_io_lock:
        todo_tools._todos_storage.clear()
    yield
    with todo_tools._todos_io_lock:
        todo_tools._todos_storage.clear()


def test_bare_numeric_looking_id_is_preserved() -> None:
    # ids are `str(uuid.uuid4())[:6]` hex slugs; slugs like these are valid
    # JSON numbers, so json.loads would turn "1e5230" into inf and "2363e0"
    # into 2363.0. They must be kept verbatim as literal ids.
    assert _normalize_todo_ids("1e5230") == ["1e5230"]
    assert _normalize_todo_ids("2363e0") == ["2363e0"]
    assert _normalize_todo_ids("0e4440") == ["0e4440"]


def test_plain_hex_and_digit_ids_are_preserved() -> None:
    assert _normalize_todo_ids("a3f9c2") == ["a3f9c2"]
    assert _normalize_todo_ids("123456") == ["123456"]


def test_json_array_of_ids_is_unpacked() -> None:
    assert _normalize_todo_ids('["1e5230", "a3f9c2"]') == ["1e5230", "a3f9c2"]


def test_json_string_scalar_id_is_unwrapped() -> None:
    # A caller may JSON-encode a single id ('"a3f9c2"'); the surrounding
    # quotes must be stripped, not treated as part of the id. A quoted
    # numeric-looking slug stays a literal string (not a parsed number),
    # and an empty JSON string yields no ids.
    assert _normalize_todo_ids('"a3f9c2"') == ["a3f9c2"]
    assert _normalize_todo_ids('"1e5230"') == ["1e5230"]
    assert _normalize_todo_ids('""') == []


def test_comma_separated_ids_are_split() -> None:
    assert _normalize_todo_ids("1e5230, a3f9c2") == ["1e5230", "a3f9c2"]


def test_list_input_is_stringified_and_stripped() -> None:
    assert _normalize_todo_ids([" 1e5230 ", "a3f9c2"]) == ["1e5230", "a3f9c2"]


def test_empty_and_none_inputs_yield_no_ids() -> None:
    assert _normalize_todo_ids("") == []
    assert _normalize_todo_ids("   ") == []
    assert _normalize_todo_ids(None) == []


def test_mark_resolves_a_bare_numeric_looking_id() -> None:
    # End-to-end: marking a bare id whose slug is a valid JSON number must
    # find and update the real todo, not fail with "Todo with ID 'inf' not
    # found".
    agent_id = "agent-1"
    todos = todo_tools._get_agent_todos(agent_id)
    todos["1e5230"] = {
        "title": "probe /admin",
        "description": None,
        "priority": "normal",
        "status": "pending",
        "created_at": "2026-07-03T00:00:00+00:00",
        "updated_at": "2026-07-03T00:00:00+00:00",
        "completed_at": None,
    }

    result = json.loads(todo_tools._mark(agent_id=agent_id, todo_ids="1e5230", new_status="done"))

    assert result["success"] is True
    assert result["marked"] == ["1e5230"]
    assert "errors" not in result
    assert todos["1e5230"]["status"] == "done"
