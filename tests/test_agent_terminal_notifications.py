"""Regression tests for terminal child-agent notifications."""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents.exceptions import MaxTurnsExceeded
from agents.tool_context import ToolContext

from strix.core.agents import AgentCoordinator, Status
from strix.core.execution import _run_cycle  # pyright: ignore[reportPrivateUsage]
from strix.tools.agents_graph.tools import agent_finish


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from agents import RunConfig
    from agents.memory import Session


class _RecordingSession:
    def __init__(self) -> None:
        self.items: list[Any] = []

    async def add_items(self, items: list[Any]) -> None:
        self.items.extend(items)

    async def get_items(self, limit: int | None = None) -> list[Any]:
        return self.items[-limit:] if limit is not None else list(self.items)


class _MaxTurnsStream:
    run_loop_exception = MaxTurnsExceeded("Max turns (500) exceeded")

    def __init__(self) -> None:
        self.events: list[Any] = []

    async def stream_events(self) -> AsyncIterator[Any]:
        for event in self.events:
            yield event


async def _coordinator_with_child() -> tuple[AgentCoordinator, _RecordingSession]:
    coordinator = AgentCoordinator()
    parent_session = _RecordingSession()
    await coordinator.register("parent", "coordinator", parent_id=None)
    await coordinator.attach_runtime(
        "parent",
        session=cast("Session", parent_session),
    )
    await coordinator.register("child", "sql-injection", parent_id="parent")
    return coordinator, parent_session


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["completed", "stopped", "failed", "crashed"])
async def test_terminal_child_status_notifies_waiting_parent(status: Status) -> None:
    coordinator, parent_session = await _coordinator_with_child()
    waiter = asyncio.create_task(coordinator.wait_for_message("parent"))
    await asyncio.sleep(0)

    await coordinator.set_status("child", status, error="child terminated")
    await coordinator.set_status("child", status, error="duplicate transition")

    await asyncio.wait_for(waiter, timeout=1.0)
    pending, items = await coordinator.consume_pending("parent", include_items=True)
    assert pending == 1
    assert items == parent_session.items
    assert f"entered terminal status '{status}'" in str(items[0])
    assert "child terminated" in str(items[0])


@pytest.mark.asyncio
async def test_terminal_child_notification_can_be_suppressed() -> None:
    coordinator, parent_session = await _coordinator_with_child()

    await coordinator.set_status("child", "completed", notify_parent=False)

    pending, items = await coordinator.consume_pending("parent", include_items=True)
    assert pending == 0
    assert items == []
    assert parent_session.items == []


@pytest.mark.asyncio
@pytest.mark.parametrize("report_to_parent, expected_messages", [(True, 1), (False, 0)])
async def test_agent_finish_avoids_duplicate_terminal_notification(
    report_to_parent: bool,
    expected_messages: int,
) -> None:
    coordinator, parent_session = await _coordinator_with_child()
    tool_arguments = json.dumps(
        {
            "result_summary": "Testing finished",
            "report_to_parent": report_to_parent,
        }
    )
    ctx = ToolContext(
        context={
            "coordinator": coordinator,
            "agent_id": "child",
            "parent_id": "parent",
            "task": "Test SQL injection",
        },
        tool_name="agent_finish",
        tool_call_id="call-agent-finish",
        tool_arguments=tool_arguments,
    )

    raw_result = await agent_finish.on_invoke_tool(ctx, tool_arguments)

    assert json.loads(raw_result)["agent_completed"] is True
    pending, _ = await coordinator.consume_pending("parent", include_items=True)
    assert pending == expected_messages
    assert len(parent_session.items) == expected_messages
    assert all("entered terminal status" not in str(item) for item in parent_session.items)


@pytest.mark.asyncio
async def test_max_turns_exceeded_child_wakes_parent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator, _ = await _coordinator_with_child()
    waiter = asyncio.create_task(coordinator.wait_for_message("parent"))
    await asyncio.sleep(0)

    def run_streamed(*_args: Any, **_kwargs: Any) -> _MaxTurnsStream:
        return _MaxTurnsStream()

    monkeypatch.setattr("strix.core.execution.Runner.run_streamed", run_streamed)

    result = await _run_cycle(
        agent=object(),
        coordinator=coordinator,
        agent_id="child",
        input_data=[],
        run_config=cast("RunConfig", object()),
        context={},
        max_turns=500,
        session=None,
        interactive=True,
        event_sink=None,
        hooks=None,
    )

    assert result is None
    assert coordinator.statuses["child"] == "stopped"
    await asyncio.wait_for(waiter, timeout=1.0)
    pending, items = await coordinator.consume_pending("parent", include_items=True)
    assert pending == 1
    assert "Max turns (500) exceeded" in str(items[0])
