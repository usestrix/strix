"""Tests for the ``respond_to_user`` yield tool."""

from __future__ import annotations

import json
from typing import Any

import pytest
from agents.tool_context import ToolContext

from strix.core.agents import AgentCoordinator
from strix.tools.respond.tool import respond_to_user


async def _call(context: dict[str, Any], message: str = "here is what I found") -> dict[str, Any]:
    ctx = ToolContext(
        context=context,
        tool_name="respond_to_user",
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    raw = await respond_to_user.on_invoke_tool(ctx, json.dumps({"message": message}))
    return json.loads(raw)  # type: ignore[no-any-return]


async def _context(*, interactive: bool, agent_id: str = "root") -> dict[str, Any]:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    return {"coordinator": coordinator, "agent_id": agent_id, "interactive": interactive}


@pytest.mark.asyncio
async def test_parks_the_agent_and_carries_the_message() -> None:
    context = await _context(interactive=True)
    result = await _call(context)

    coordinator = context["coordinator"]
    assert result["success"] is True
    assert result["wait_outcome"] == "waiting"
    assert result["message"] == "here is what I found"
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


async def _call_without_message(context: dict[str, Any]) -> dict[str, Any]:
    ctx = ToolContext(
        context=context,
        tool_name="respond_to_user",
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    raw = await respond_to_user.on_invoke_tool(ctx, "{}")
    return json.loads(raw)  # type: ignore[no-any-return]


@pytest.mark.asyncio
async def test_parks_without_a_message() -> None:
    """An agent that has already said its piece as plain text can just wait.

    The nudge is what leaves it here, and while a message was required the only
    way to stop was to send the same answer a second time.
    """
    context = await _context(interactive=True)

    result = await _call_without_message(context)

    assert result["success"] is True
    assert result["wait_outcome"] == "waiting"
    assert result["message"] == ""
    assert context["coordinator"].statuses["root"] == "waiting"
