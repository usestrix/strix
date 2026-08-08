"""Tests for the ``respond_to_user`` yield tool."""

from __future__ import annotations

import json
from typing import Any

import pytest
from agents.tool_context import ToolContext

from strix.core.agents import AgentCoordinator
from strix.tools.respond.tool import DELIVERED_PLAIN_TEXT, respond_to_user


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
async def test_parks_on_text_already_delivered_without_repeating_it() -> None:
    """A turn that ended in plain text can wait without saying it all again.

    The recovery nudge is what leaves the agent here, and being told to call this
    tool used to mean supplying a message it had just sent, so the user read the
    same answer twice.
    """
    context = await _context(interactive=True)
    context[DELIVERED_PLAIN_TEXT] = "Hi! What would you like me to test?"

    result = await _call_without_message(context)

    assert result["success"] is True
    assert result["wait_outcome"] == "waiting"
    # The text stands as the answer, so the record holds it...
    assert result["message"] == "Hi! What would you like me to test?"
    # ...and it is consumed, so a later turn cannot park on it a second time.
    assert DELIVERED_PLAIN_TEXT not in context
    assert context["coordinator"].statuses["root"] == "waiting"


@pytest.mark.asyncio
async def test_refuses_to_park_when_nothing_was_said() -> None:
    """Parking silently would leave the user waiting on an agent that said nothing."""
    context = await _context(interactive=True)

    result = await _call_without_message(context)

    assert result["success"] is False
    assert "nothing to wait on" in result["error"]
    assert context["coordinator"].statuses["root"] != "waiting"


@pytest.mark.asyncio
async def test_a_message_is_kept_even_when_text_was_delivered() -> None:
    """Adding to what was said replaces it; it does not concatenate."""
    context = await _context(interactive=True)
    context[DELIVERED_PLAIN_TEXT] = "Hi!"

    result = await _call(context, message="One more thing: which host?")

    assert result["success"] is True
    assert result["message"] == "One more thing: which host?"
    assert DELIVERED_PLAIN_TEXT not in context
