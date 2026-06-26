"""Tests for the scan-wide budget-stop signal on the agent coordinator."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest

from strix.core import execution
from strix.core.agents import AgentCoordinator
from strix.core.execution import _run_cycle


@pytest.mark.asyncio
async def test_budget_stop_sets_flag() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    assert coordinator.budget_stopped is False
    await coordinator.trigger_budget_stop()
    assert coordinator.budget_stopped is True


@pytest.mark.asyncio
async def test_budget_stop_unblocks_parked_agent() -> None:
    # A parent parked in wait_for_message (awaiting a child) must be released so
    # it can exit, no matter where in the tree the budget limit was hit.
    coordinator = AgentCoordinator()
    await coordinator.register("parent", "strix", parent_id=None)

    waiter = asyncio.create_task(coordinator.wait_for_message("parent"))
    await asyncio.sleep(0)  # let the waiter park
    assert not waiter.done()

    await coordinator.trigger_budget_stop()
    await asyncio.wait_for(waiter, timeout=1.0)


@pytest.mark.asyncio
async def test_wait_for_message_returns_immediately_after_budget_stop() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("agent", "recon", parent_id="parent")
    await coordinator.trigger_budget_stop()

    # No pending messages, but the stop flag short-circuits the wait.
    await asyncio.wait_for(coordinator.wait_for_message("agent"), timeout=1.0)


class _RestartableStreamError(Exception):
    pass


class _FakeStream:
    def __init__(
        self,
        *,
        events: tuple[Any, ...] | list[Any] = (),
        exc: Exception | None = None,
    ) -> None:
        self._events = list(events)
        self._exc = exc
        self.run_loop_exception: Exception | None = None

    async def stream_events(self):
        for event in self._events:
            yield event
        if self._exc is not None:
            raise self._exc


@pytest.mark.asyncio
async def test_run_cycle_retries_restartable_stream_errors(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    streams = [
        _FakeStream(exc=_RestartableStreamError("first")),
        _FakeStream(exc=_RestartableStreamError("second")),
        _FakeStream(events=[{"type": "done"}]),
    ]
    emitted: list[tuple[str, Any]] = []

    def run_streamed(*_args: object, **_kwargs: object) -> _FakeStream:
        return streams.pop(0)

    monkeypatch.setattr(
        execution,
        "_STREAM_RESTARTABLE_EXCEPTIONS",
        (_RestartableStreamError,),
    )
    monkeypatch.setattr(execution.Runner, "run_streamed", run_streamed)

    with caplog.at_level(logging.WARNING):
        result = await _run_cycle(
            object(),
            coordinator,
            "root",
            input_data=[{"role": "user", "content": "hello"}],
            run_config=object(),
            context={},
            max_turns=4,
            session=None,
            interactive=False,
            event_sink=lambda agent_id, event: emitted.append((agent_id, event)),
            hooks=None,
        )

    assert result is not None
    assert emitted == [("root", {"type": "done"})]
    assert coordinator.runtimes["root"].stream is None
    assert sum("Restarting stream for root" in message for message in caplog.messages) == 2


@pytest.mark.asyncio
async def test_run_cycle_stops_retrying_after_restart_limit(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    streams = [_FakeStream(exc=_RestartableStreamError(f"boom-{index}")) for index in range(4)]

    def run_streamed(*_args: object, **_kwargs: object) -> _FakeStream:
        return streams.pop(0)

    monkeypatch.setattr(
        execution,
        "_STREAM_RESTARTABLE_EXCEPTIONS",
        (_RestartableStreamError,),
    )
    monkeypatch.setattr(execution.Runner, "run_streamed", run_streamed)

    with caplog.at_level(logging.WARNING), pytest.raises(_RestartableStreamError, match="boom-3"):
        await _run_cycle(
            object(),
            coordinator,
            "root",
            input_data=[],
            run_config=object(),
            context={},
            max_turns=4,
            session=None,
            interactive=False,
            event_sink=None,
            hooks=None,
        )

    assert coordinator.runtimes["root"].stream is None
    assert sum("Restarting stream for root" in message for message in caplog.messages) == 3
