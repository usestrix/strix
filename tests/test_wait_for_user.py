"""Tests for the ``wait_for_user`` yield tool."""

from __future__ import annotations

import json
from typing import Any

import pytest
from agents.tool_context import ToolContext

from strix.core.agents import AgentCoordinator
from strix.tools.wait_for_user.tool import wait_for_user


async def _call(context: dict[str, Any]) -> dict[str, Any]:
    ctx = ToolContext(
        context=context,
        tool_name="wait_for_user",
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    raw = await wait_for_user.on_invoke_tool(ctx, "{}")
    return json.loads(raw)  # type: ignore[no-any-return]


async def _context(*, interactive: bool, agent_id: str = "root") -> dict[str, Any]:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    return {"coordinator": coordinator, "agent_id": agent_id, "interactive": interactive}


def test_takes_no_arguments() -> None:
    """Plain text is the only channel to the user, so the tool carries none.

    A message parameter here is a second channel the model fills with the same
    words it already wrote, and the user reads its answer twice.
    """
    assert wait_for_user.params_json_schema.get("properties", {}) == {}


@pytest.mark.asyncio
async def test_parks_the_agent_for_the_user() -> None:
    context = await _context(interactive=True)
    result = await _call(context)

    coordinator = context["coordinator"]
    assert result["success"] is True
    assert result["wait_outcome"] == "waiting"
    assert "message" not in result
    assert coordinator.statuses["root"] == "waiting"
    # Recorded as a human wait, so the driver never auto-resumes it.
    assert coordinator.wait_kinds["root"] == "user"


@pytest.mark.asyncio
async def test_rejected_in_an_autonomous_run() -> None:
    context = await _context(interactive=False)
    result = await _call(context)

    assert result["success"] is False
    assert "finish_scan" in result["error"]
    assert context["coordinator"].statuses["root"] == "running"


@pytest.mark.asyncio
async def test_a_message_that_already_arrived_is_taken_instead_of_parking() -> None:
    context = await _context(interactive=True)
    coordinator = context["coordinator"]
    await coordinator.send("root", {"from": "user", "content": "wait, one more thing"})

    result = await _call(context)

    assert result["wait_outcome"] == "message_arrived"
    assert result["pending_messages"] == 1
    assert coordinator.statuses["root"] == "running"


@pytest.mark.asyncio
async def test_a_stopped_agent_is_left_stopped() -> None:
    context = await _context(interactive=True)
    coordinator = context["coordinator"]
    await coordinator.set_status("root", "stopped")

    result = await _call(context)

    assert result["wait_outcome"] == "stopped"
    assert coordinator.statuses["root"] == "stopped"
