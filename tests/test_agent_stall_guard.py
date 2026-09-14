"""Tests for the per-agent stall guard.

The model-stream idle watchdog only covers the model call. A turn can also
wedge in what the run loop awaits *between* events — a re-issued request that
never opens, a tool transport that never answers — and nothing bounded that,
so the agent stayed ``running`` forever and its parent waited on it forever.
Two layers now cover it: the run cycle abandons a turn that emits no event for
the stall timeout, and a parent's ``wait_for_agents`` fails any agent that has
been silent for longer still.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents import RunConfig, Runner
from agents.tool_context import ToolContext

from strix.core import execution
from strix.core.agents import AgentCoordinator
from strix.tools.agents_graph import tools as graph_tools
from strix.tools.agents_graph.tools import wait_for_agents


if TYPE_CHECKING:
    from collections.abc import Iterator


class _HangingStream:
    """Emits one event, then never produces another."""

    def __init__(self) -> None:
        self.run_loop_exception: BaseException | None = None
        self.cancelled = False

    async def stream_events(self) -> Any:
        yield "first"
        await asyncio.Event().wait()

    def cancel(self, mode: str = "immediate") -> None:  # noqa: ARG002
        self.cancelled = True


class _HealthyStream:
    def __init__(self) -> None:
        self.run_loop_exception: BaseException | None = None

    async def stream_events(self) -> Any:
        for i in range(3):
            await asyncio.sleep(0.01)
            yield f"event-{i}"


@pytest.fixture
def _fast_stall(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(execution, "_agent_stall_timeout", lambda: 0.2)
    monkeypatch.setattr(execution, "_TRANSIENT_MODEL_RETRY_BASE_DELAY_S", 0.0)
    monkeypatch.setattr(execution, "_TRANSIENT_MODEL_RETRY_MAX_DELAY_S", 0.0)
    yield


def _serve(monkeypatch: pytest.MonkeyPatch, streams: list[Any]) -> dict[str, int]:
    calls = {"n": 0}

    def _fake_run_streamed(*_args: Any, **_kwargs: Any) -> Any:
        stream = streams[calls["n"]]
        calls["n"] += 1
        return stream

    monkeypatch.setattr(Runner, "run_streamed", _fake_run_streamed)
    return calls


async def _run_cycle(coordinator: AgentCoordinator) -> Any:
    return await execution._run_cycle(
        object(),
        coordinator,
        "root",
        input_data="task",
        run_config=cast("RunConfig", object()),
        context={},
        max_turns=5,
        session=None,
        interactive=False,
        event_sink=None,
        hooks=None,
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("_fast_stall")
async def test_hung_turn_is_abandoned_and_replayed(monkeypatch: pytest.MonkeyPatch) -> None:
    hung = _HangingStream()
    healthy = _HealthyStream()
    calls = _serve(monkeypatch, [hung, healthy])
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    started = time.monotonic()
    result = await _run_cycle(coordinator)

    assert result is healthy
    assert calls["n"] == 2
    assert hung.cancelled is True
    assert time.monotonic() - started < 2


@pytest.mark.asyncio
@pytest.mark.usefixtures("_fast_stall")
async def test_agent_that_never_recovers_is_marked_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _serve(
        monkeypatch,
        [_HangingStream() for _ in range(execution._MAX_TRANSIENT_MODEL_RETRIES + 1)],
    )
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    with pytest.raises(TimeoutError, match="produced no event"):
        await _run_cycle(coordinator)

    assert coordinator.statuses["root"] == "crashed"


@pytest.mark.asyncio
async def test_stall_guard_is_off_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(execution, "_agent_stall_timeout", lambda: 0.0)
    hung = _HangingStream()
    _serve(monkeypatch, [hung])
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(_run_cycle(coordinator), timeout=0.5)

    assert hung.cancelled is False


# --- wait_for_agents reaps silent children ------------------------------------------


async def _call_wait(coordinator: AgentCoordinator, args: dict[str, Any]) -> dict[str, Any]:
    ctx = ToolContext(
        context={"coordinator": coordinator, "agent_id": "root"},
        tool_name=wait_for_agents.name,
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    raw: str = await wait_for_agents.on_invoke_tool(ctx, json.dumps(args))
    return cast("dict[str, Any]", json.loads(raw))


@pytest.fixture
def _reap_after(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    async def _reap(coordinator: AgentCoordinator, me: str) -> list[dict[str, Any]]:
        return await coordinator.reap_stalled(0.3, under=me)

    monkeypatch.setattr(graph_tools, "_reap_stalled_agents", _reap)
    yield


@pytest.mark.asyncio
@pytest.mark.usefixtures("_reap_after")
async def test_waiting_parent_fails_a_child_silent_too_long() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "ATO-Chaining", parent_id="root")
    await coordinator.attach_runtime("root", resumable=False)
    child_task = asyncio.create_task(asyncio.Event().wait())
    await coordinator.attach_runtime("child", task=child_task, resumable=False)

    result = await _call_wait(coordinator, {"timeout_seconds": 1})

    assert result["wait_outcome"] == "timeout"
    assert [a["agent_id"] for a in result["stalled_agents"]] == ["child"]
    assert coordinator.statuses["child"] == "failed"
    assert "stalled" in coordinator.errors["child"]
    await asyncio.sleep(0)
    assert child_task.cancelled()

    # Nothing is left to wait on, so the next wait returns at once.
    result = await _call_wait(coordinator, {"timeout_seconds": 60})
    assert result["wait_outcome"] == "no_active_agents"


@pytest.mark.asyncio
@pytest.mark.usefixtures("_reap_after")
async def test_child_that_keeps_emitting_events_is_left_alone() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "DeepFuzz", parent_id="root")
    await coordinator.attach_runtime("root", resumable=False)
    await coordinator.attach_runtime("child", resumable=False)

    async def _heartbeat() -> None:
        for _ in range(12):
            await asyncio.sleep(0.1)
            coordinator.touch("child")

    beat = asyncio.create_task(_heartbeat())
    result = await _call_wait(coordinator, {"timeout_seconds": 1})
    await beat

    assert result["wait_outcome"] == "timeout"
    assert result["stalled_agents"] == []
    assert coordinator.statuses["child"] == "running"


@pytest.mark.asyncio
@pytest.mark.usefixtures("_reap_after")
async def test_waiting_children_are_not_reaped() -> None:
    # A child parked in its own wait emits no events by design.
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "Coordinator", parent_id="root")
    await coordinator.attach_runtime("root", resumable=False)
    await coordinator.attach_runtime("child", resumable=False)
    await coordinator.park_waiting("child", wait_kind="agents")

    result = await _call_wait(coordinator, {"timeout_seconds": 1})

    assert result["wait_outcome"] == "timeout"
    assert result["stalled_agents"] == []
    assert coordinator.statuses["child"] == "waiting"


@pytest.mark.asyncio
async def test_reaping_is_off_when_disabled() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "X", parent_id="root")
    coordinator.runtimes["child"].last_activity -= 10_000

    assert await coordinator.reap_stalled(0, under="root") == []
    assert coordinator.statuses["child"] == "running"


@pytest.mark.asyncio
async def test_reaping_stays_inside_the_callers_subtree() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("a", "A", parent_id="root")
    await coordinator.register("a1", "A1", parent_id="a")
    await coordinator.register("b", "B", parent_id="root")
    for aid in ("root", "a1", "b"):
        coordinator.runtimes[aid].last_activity -= 10_000

    reaped = await coordinator.reap_stalled(1, under="a")

    assert [r["agent_id"] for r in reaped] == ["a1"]
    assert coordinator.statuses["a1"] == "failed"
    assert coordinator.statuses["b"] == "running"
    assert coordinator.statuses["root"] == "running"
