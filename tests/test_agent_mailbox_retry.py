"""consume_pending must not lose mailbox messages when the session write fails."""

from __future__ import annotations

from typing import Any

import pytest

from strix.core.agents import AgentCoordinator


class _FailingSession:
    """Session whose write always fails, as under a SQLite lock."""

    def __init__(self) -> None:
        self.attempts = 0

    async def add_items(self, items: list[Any]) -> None:  # noqa: ARG002
        self.attempts += 1
        msg = "database is locked"
        raise RuntimeError(msg)


class _RecordingSession:
    def __init__(self) -> None:
        self.items: list[Any] = []

    async def add_items(self, items: list[Any]) -> None:
        self.items.extend(items)


async def _agent_with_session(session: Any) -> AgentCoordinator:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.attach_runtime("root", session=session)
    return coordinator


@pytest.mark.asyncio
async def test_consume_pending_keeps_messages_when_session_write_fails() -> None:
    # The mailbox is drained before the write, so a failed write must not report
    # the message as delivered: callers with include_items=False read the next
    # turn from the session and would otherwise run without the instruction.
    session = _FailingSession()
    coordinator = await _agent_with_session(session)
    await coordinator.send("root", {"from": "user", "content": "scan the login form"})

    count, items = await coordinator.consume_pending("root")

    assert session.attempts == 1
    assert count == 0  # nothing was delivered
    assert items == []
    mailbox = coordinator.runtimes["root"].mailbox
    assert [m["content"] for m in mailbox] == ["scan the login form"]
    assert coordinator.pending_counts["root"] == 1


@pytest.mark.asyncio
async def test_consume_pending_retries_the_message_on_the_next_drain() -> None:
    coordinator = await _agent_with_session(_FailingSession())
    await coordinator.send("root", {"from": "user", "content": "scan the login form"})
    await coordinator.consume_pending("root")

    # a later drain, once the session accepts writes again, still has the message
    good = _RecordingSession()
    await coordinator.attach_runtime("root", session=good)
    count, _ = await coordinator.consume_pending("root")

    assert count == 1
    assert len(good.items) == 1
    assert coordinator.runtimes["root"].mailbox == []


@pytest.mark.asyncio
async def test_consume_pending_preserves_order_against_a_concurrent_send() -> None:
    coordinator = await _agent_with_session(_FailingSession())
    await coordinator.send("root", {"from": "user", "content": "first"})
    await coordinator.consume_pending("root")
    await coordinator.send("root", {"from": "user", "content": "second"})

    mailbox = coordinator.runtimes["root"].mailbox
    assert [m["content"] for m in mailbox] == ["first", "second"]


@pytest.mark.asyncio
async def test_consume_pending_still_delivers_when_the_write_succeeds() -> None:
    session = _RecordingSession()
    coordinator = await _agent_with_session(session)
    await coordinator.send("root", {"from": "user", "content": "scan the login form"})

    count, _ = await coordinator.consume_pending("root")

    assert count == 1
    assert len(session.items) == 1
    assert coordinator.runtimes["root"].mailbox == []
    assert coordinator.pending_counts["root"] == 0
