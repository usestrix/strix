"""Tests for per-agent todo id generation and collision handling."""

from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING

import pytest
from agents.tool_context import ToolContext

import strix.tools.todo.tools as todo_tools
from strix.tools.todo.tools import _generate_todo_id


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


class _FakeUUID:
    """Minimal stand-in whose ``str()`` yields a controlled slug.

    Todo ids are ``str(uuid.uuid4())[:6]``, so only the first six chars matter.
    """

    def __init__(self, value: str) -> None:
        self._value = value

    def __str__(self) -> str:
        return self._value


def _patch_uuid_sequence(monkeypatch: pytest.MonkeyPatch, slugs: list[str]) -> None:
    """Make ``uuid.uuid4()`` yield ``str()`` values built from ``slugs`` in order."""
    values = iter(f"{slug}-0000-0000-0000-000000000000" for slug in slugs)
    monkeypatch.setattr(uuid, "uuid4", lambda: _FakeUUID(next(values)))


def _seed_todo(agent_id: str, todo_id: str, title: str) -> None:
    todo_tools._get_agent_todos(agent_id)[todo_id] = {
        "title": title,
        "description": None,
        "priority": "normal",
        "status": "pending",
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
        "completed_at": None,
    }


def _ctx(agent_id: str) -> ToolContext:
    return ToolContext(
        context={"agent_id": agent_id},
        tool_name="create_todo",
        tool_call_id="call-1",
        tool_arguments="{}",
    )


def test_generate_id_returns_a_six_char_slug() -> None:
    todo_id = _generate_todo_id({})
    assert isinstance(todo_id, str)
    assert len(todo_id) == 6


def test_generate_id_skips_a_colliding_slug(monkeypatch: pytest.MonkeyPatch) -> None:
    # First draw collides with an existing id; the generator must retry and
    # return the next, unused slug instead of handing back the taken one.
    _patch_uuid_sequence(monkeypatch, ["abcdef", "123456"])
    assert _generate_todo_id({"abcdef": {}}) == "123456"


def test_generate_id_returns_none_when_space_is_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Every draw collides — the generator gives up rather than looping forever
    # or returning a taken id.
    monkeypatch.setattr(
        uuid,
        "uuid4",
        lambda: _FakeUUID("abcdef-0000-0000-0000-000000000000"),
    )
    assert _generate_todo_id({"abcdef": {}}) is None


@pytest.mark.asyncio
async def test_create_todo_does_not_overwrite_on_id_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Regression: a fresh todo whose generated id collides with an existing one
    # must NOT clobber the existing todo. The generator retries to a free slug.
    agent_id = "agent-1"
    _seed_todo(agent_id, "abcdef", "keep me")
    _patch_uuid_sequence(monkeypatch, ["abcdef", "bbccdd"])

    raw = await todo_tools.create_todo.on_invoke_tool(
        _ctx(agent_id), json.dumps({"todos": '[{"title": "new task"}]'})
    )
    result = json.loads(raw)

    assert result["success"] is True
    assert result["created"] == [{"todo_id": "bbccdd", "title": "new task", "priority": "normal"}]
    todos = todo_tools._get_agent_todos(agent_id)
    assert todos["abcdef"]["title"] == "keep me"
    assert todos["bbccdd"]["title"] == "new task"
    assert result["total_count"] == 2


@pytest.mark.asyncio
async def test_create_todo_reports_error_when_id_cannot_be_generated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # If the (astronomically unlikely) id space is exhausted, the task is
    # reported as an error rather than silently dropping or overwriting.
    agent_id = "agent-2"
    _seed_todo(agent_id, "abcdef", "keep me")
    monkeypatch.setattr(
        uuid,
        "uuid4",
        lambda: _FakeUUID("abcdef-0000-0000-0000-000000000000"),
    )

    raw = await todo_tools.create_todo.on_invoke_tool(
        _ctx(agent_id), json.dumps({"todos": '[{"title": "new task"}]'})
    )
    result = json.loads(raw)

    assert result["success"] is False
    assert result["created"] == []
    assert result["errors"] == [
        {"title": "new task", "error": "Failed to generate a unique todo ID"}
    ]
    todos = todo_tools._get_agent_todos(agent_id)
    assert todos["abcdef"]["title"] == "keep me"
    assert result["total_count"] == 1
