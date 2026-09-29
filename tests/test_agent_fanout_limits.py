"""Tests for multi-agent fan-out caps in strix.tools.agents_graph.tools."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from strix.config import loader
from strix.core.agents import AgentCoordinator
from strix.tools.agents_graph.tools import _depth_limit_error


if TYPE_CHECKING:
    import pytest


async def _graph(*edges: tuple[str, str | None]) -> AgentCoordinator:
    """Build a coordinator from (agent_id, parent_id) edges, root first."""
    coordinator = AgentCoordinator()
    for agent_id, parent_id in edges:
        await coordinator.register(agent_id, agent_id, parent_id)
    return coordinator


async def test_reserve_blocks_when_limit_reached() -> None:
    coordinator = await _graph(("root", None), ("child", "root"))

    assert await coordinator.try_reserve_agent_slot(2) is False


async def test_reserve_allows_below_limit() -> None:
    coordinator = await _graph(("root", None), ("child", "root"))

    assert await coordinator.try_reserve_agent_slot(4) is True


async def test_reserve_unlimited_when_zero() -> None:
    coordinator = await _graph(("root", None), ("a", "root"), ("b", "a"), ("c", "b"))

    assert await coordinator.try_reserve_agent_slot(0) is True


async def test_concurrent_reservations_cannot_overshoot_cap() -> None:
    # Two parents race for the last slot. Counting only registered agents would
    # wave both through, because neither child registers before the other checks.
    coordinator = await _graph(("root", None), ("a", "root"))

    granted = await asyncio.gather(*(coordinator.try_reserve_agent_slot(3) for _ in range(2)))

    assert sorted(granted) == [False, True]


async def test_released_slot_is_reusable() -> None:
    coordinator = await _graph(("root", None), ("a", "root"))

    assert await coordinator.try_reserve_agent_slot(3) is True
    assert await coordinator.try_reserve_agent_slot(3) is False
    await coordinator.release_agent_slot()
    assert await coordinator.try_reserve_agent_slot(3) is True


async def test_release_does_not_go_negative() -> None:
    coordinator = await _graph(("root", None))

    await coordinator.release_agent_slot()
    await coordinator.release_agent_slot()

    # A stray release must not hand out a free slot beyond the cap.
    assert await coordinator.try_reserve_agent_slot(1) is False


async def test_max_depth_blocks_grandchild(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_MAX_AGENTS", "0")
    monkeypatch.setenv("STRIX_MAX_AGENT_DEPTH", "2")
    loader._cached = None
    try:
        coordinator = await _graph(("root", None), ("child", "root"))
        # Spawning from the child would create a depth-3 grandchild.
        child_error = await _depth_limit_error(coordinator, "child")
        # Spawning from the root creates a depth-2 child — allowed.
        root_error = await _depth_limit_error(coordinator, "root")
    finally:
        loader._cached = None

    assert child_error is not None
    assert "depth limit reached" in child_error
    assert root_error is None


async def test_depth_limit_disabled_when_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_MAX_AGENTS", "0")
    monkeypatch.setenv("STRIX_MAX_AGENT_DEPTH", "0")
    loader._cached = None
    try:
        coordinator = await _graph(
            ("root", None), ("a", "root"), ("b", "a"), ("c", "b"), ("d", "c")
        )
        error = await _depth_limit_error(coordinator, "d")
    finally:
        loader._cached = None

    assert error is None
