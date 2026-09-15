"""Tests for the optional per-agent ``model`` override on ``create_agent``.

``create_agent`` normally spawns children on the scan's configured model.
``model`` lets the caller deliberately give one child a different model (a
"second opinion" specialist) without touching every other agent in the run.
These tests pin down the three contract points: omitting ``model`` must be a
no-op regression guard, a valid alternate model string must be threaded
through to the spawner unchanged, and an invalid model string must fail
cleanly instead of spawning anything or raising.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents.tool_context import ToolContext

import strix.tools.agents_graph.tools as agents_graph_tools
from strix.core.agents import AgentCoordinator
from strix.tools.agents_graph.tools import create_agent


if TYPE_CHECKING:
    from collections.abc import Iterator


class _FakeLlmSettings:
    def __init__(self, api_base: str | None = None) -> None:
        self.api_base = api_base


class _FakeSettings:
    def __init__(self, api_base: str | None = None) -> None:
        self.llm = _FakeLlmSettings(api_base=api_base)


@pytest.fixture
def _no_api_base(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Pin ``load_settings()`` so the bare-name validation path is deterministic."""

    def _load_fake_settings() -> _FakeSettings:
        return _FakeSettings()

    monkeypatch.setattr(agents_graph_tools, "load_settings", _load_fake_settings)
    yield


async def _graph() -> AgentCoordinator:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.attach_runtime("root", resumable=False)
    return coordinator


class _RecordingSpawner:
    """Stand-in for the ``spawn_child_agent`` closure the runner puts in context."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return {
            "success": True,
            "agent_id": "child-1",
            "name": kwargs.get("name"),
            "parent_id": kwargs.get("parent_ctx", {}).get("agent_id"),
            "message": "spawned",
        }


async def _call_create_agent(
    coordinator: AgentCoordinator, spawner: _RecordingSpawner, args: dict[str, Any]
) -> dict[str, Any]:
    ctx = ToolContext(
        context={
            "coordinator": coordinator,
            "agent_id": "root",
            "spawn_child_agent": spawner,
        },
        tool_name=create_agent.name,
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    raw: str = await create_agent.on_invoke_tool(ctx, json.dumps(args))
    return cast("dict[str, Any]", json.loads(raw))


@pytest.mark.asyncio
async def test_omitting_model_spawns_exactly_as_before(_no_api_base: None) -> None:
    coordinator = await _graph()
    spawner = _RecordingSpawner()

    result = await _call_create_agent(
        coordinator, spawner, {"name": "Validator", "task": "check the thing"}
    )

    assert result["success"] is True
    assert len(spawner.calls) == 1
    assert spawner.calls[0]["model"] is None


@pytest.mark.asyncio
async def test_valid_alternate_model_is_threaded_through_unchanged(_no_api_base: None) -> None:
    coordinator = await _graph()
    spawner = _RecordingSpawner()

    result = await _call_create_agent(
        coordinator,
        spawner,
        {
            "name": "Second Opinion",
            "task": "re-review already-covered surfaces",
            "model": "anthropic/claude-opus-4-7",
        },
    )

    assert result["success"] is True
    assert len(spawner.calls) == 1
    assert spawner.calls[0]["model"] == "anthropic/claude-opus-4-7"


@pytest.mark.asyncio
async def test_invalid_model_string_returns_a_clean_error(_no_api_base: None) -> None:
    coordinator = await _graph()
    spawner = _RecordingSpawner()

    result = await _call_create_agent(
        coordinator,
        spawner,
        {
            "name": "Second Opinion",
            "task": "re-review already-covered surfaces",
            "model": "definitely-not-a-real-model",
        },
    )

    assert result["success"] is False
    assert "invalid model" in result["error"]
    assert result["agent_id"] is None
    assert spawner.calls == []
