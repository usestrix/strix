"""Tests for the scan-wide budget-stop signal on the agent coordinator."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from strix.core.agents import AgentCoordinator
from strix.core.execution import _notify_parent_on_budget_reserve


@pytest.mark.asyncio
async def test_reserve_stop_notifies_parent(monkeypatch: pytest.MonkeyPatch) -> None:
    # A reserve-stopped child never runs agent_finish, so it must post a message to the
    # parent's inbox (which wakes it) rather than leaving it to hang.
    coordinator = AgentCoordinator()
    await coordinator.register("parent", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="parent")

    sent: list[tuple[str, dict[str, Any]]] = []

    async def _record(target_agent_id: str, message: dict[str, Any]) -> bool:
        sent.append((target_agent_id, message))
        return True

    monkeypatch.setattr(coordinator, "send", _record)
    await _notify_parent_on_budget_reserve(coordinator, "child")

    assert len(sent) == 1
    target, message = sent[0]
    assert target == "parent"
    assert message["type"] == "budget_reserve_stop"
    assert "finish_scan" in str(message["content"])


@pytest.mark.asyncio
async def test_reserve_stop_notify_noop_for_root(monkeypatch: pytest.MonkeyPatch) -> None:
    # The root has no parent, so there is nobody to notify.
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    sent: list[tuple[str, dict[str, Any]]] = []

    async def _record(target_agent_id: str, message: dict[str, Any]) -> bool:
        sent.append((target_agent_id, message))
        return True

    monkeypatch.setattr(coordinator, "send", _record)
    await _notify_parent_on_budget_reserve(coordinator, "root")

    assert sent == []


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
