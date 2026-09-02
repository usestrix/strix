"""Tests for collapsing repeated waits queued inside one model turn.

An orchestrator that writes out its whole poll loop ahead of time queues
many ``wait_for_agents`` calls in a single response. Each one parks for its
full timeout, so the agent stops reacting for hours while its children run
unsupervised. Only the first wait of a turn parks; the rest return at once.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents import RunContextWrapper
from agents.tool_context import ToolContext

from strix.core.agents import AgentCoordinator
from strix.core.hooks import LLM_TURN_KEY, ReportUsageHooks
from strix.tools.agents_graph.tools import wait_for_agents


if TYPE_CHECKING:
    from collections.abc import Iterator


_WAIT_SECONDS = 2


@pytest.fixture
def _fast_wait(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    # The real ceiling is 300s per wait; the shape of the bug is the same.
    monkeypatch.setattr(
        "strix.tools.agents_graph.tools._WAIT_DEFAULT_TIMEOUT_S", _WAIT_SECONDS, raising=True
    )
    yield


async def _context() -> dict[str, Any]:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    # A live child keeps the wait genuine: with nobody to hear from it returns at once.
    await coordinator.register("child", "recon", parent_id="root")
    return {"agent_id": "root", "coordinator": coordinator}


async def _wait(inner: dict[str, Any]) -> dict[str, Any]:
    ctx = ToolContext(
        context=inner,
        tool_name="wait_for_agents",
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    raw: str = await wait_for_agents.on_invoke_tool(
        ctx, json.dumps({"reason": "waiting for wave 1", "timeout_seconds": _WAIT_SECONDS})
    )
    return cast("dict[str, Any]", json.loads(raw))


@pytest.mark.asyncio
async def test_waits_queued_in_one_turn_each_park_without_the_guard(_fast_wait: None) -> None:
    # Repro: no turn marker in context (as before the fix) — every queued wait
    # parks for its full timeout, so N waits cost N x timeout.
    inner = await _context()

    started = time.monotonic()
    outcomes = [(await _wait(inner))["wait_outcome"] for _ in range(3)]
    elapsed = time.monotonic() - started

    assert outcomes == ["timeout", "timeout", "timeout"]
    assert elapsed >= 3 * _WAIT_SECONDS


@pytest.mark.asyncio
async def test_repeated_waits_in_one_turn_are_collapsed(_fast_wait: None) -> None:
    inner = await _context()
    inner[LLM_TURN_KEY] = 1

    started = time.monotonic()
    outcomes = [(await _wait(inner))["wait_outcome"] for _ in range(3)]
    elapsed = time.monotonic() - started

    assert outcomes == ["timeout", "already_waited", "already_waited"]
    assert elapsed < 2 * _WAIT_SECONDS


@pytest.mark.asyncio
async def test_a_wait_in_the_next_turn_still_parks(_fast_wait: None) -> None:
    inner = await _context()
    inner[LLM_TURN_KEY] = 1
    assert (await _wait(inner))["wait_outcome"] == "timeout"
    assert (await _wait(inner))["wait_outcome"] == "already_waited"

    inner[LLM_TURN_KEY] = 2

    assert (await _wait(inner))["wait_outcome"] == "timeout"


@pytest.mark.asyncio
async def test_each_model_turn_bumps_the_turn_marker() -> None:
    hooks = ReportUsageHooks(model="gw-model")
    context: RunContextWrapper[dict[str, Any]] = RunContextWrapper(context={})
    agent = cast("Any", None)

    await hooks.on_llm_start(context, agent, None, [])
    await hooks.on_llm_start(context, agent, None, [])

    assert context.context[LLM_TURN_KEY] == 2


@pytest.mark.asyncio
async def test_a_collapsed_wait_still_reports_arriving_messages(_fast_wait: None) -> None:
    inner = await _context()
    inner[LLM_TURN_KEY] = 1
    coordinator = cast("AgentCoordinator", inner["coordinator"])

    async def _send() -> None:
        await asyncio.sleep(0.1)
        await coordinator.send("root", {"type": "information", "content": "child done"})

    task = asyncio.create_task(_send())
    first = await _wait(inner)
    await task

    assert first["wait_outcome"] == "message_arrived"
    assert (await _wait(inner))["wait_outcome"] == "already_waited"
