"""Tests for multi-agent fan-out caps in strix.tools.agents_graph.tools."""

from __future__ import annotations

from typing import TYPE_CHECKING

from strix.config import loader
from strix.core.agents import AgentCoordinator
from strix.tools.agents_graph.tools import _fan_out_limit_error


if TYPE_CHECKING:
    import pytest


async def _graph(*edges: tuple[str, str | None]) -> AgentCoordinator:
    """Build a coordinator from (agent_id, parent_id) edges, root first."""
    coordinator = AgentCoordinator()
    for agent_id, parent_id in edges:
        await coordinator.register(agent_id, agent_id, parent_id)
    return coordinator


async def test_max_agents_blocks_when_reached(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_MAX_AGENTS", "2")
    monkeypatch.setenv("STRIX_MAX_AGENT_DEPTH", "0")
    loader._cached = None
    try:
        coordinator = await _graph(("root", None), ("child", "root"))
        error = await _fan_out_limit_error(coordinator, "root")
    finally:
        loader._cached = None

    assert error is not None
    assert "Agent limit reached" in error


async def test_max_agents_allows_below_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_MAX_AGENTS", "4")
    monkeypatch.setenv("STRIX_MAX_AGENT_DEPTH", "0")
    loader._cached = None
    try:
        coordinator = await _graph(("root", None), ("child", "root"))
        error = await _fan_out_limit_error(coordinator, "root")
    finally:
        loader._cached = None

    assert error is None


async def test_max_depth_blocks_grandchild(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_MAX_AGENTS", "0")
    monkeypatch.setenv("STRIX_MAX_AGENT_DEPTH", "2")
    loader._cached = None
    try:
        coordinator = await _graph(("root", None), ("child", "root"))
        # Spawning from the child would create a depth-3 grandchild.
        child_error = await _fan_out_limit_error(coordinator, "child")
        # Spawning from the root creates a depth-2 child — allowed.
        root_error = await _fan_out_limit_error(coordinator, "root")
    finally:
        loader._cached = None

    assert child_error is not None
    assert "depth limit reached" in child_error
    assert root_error is None


async def test_limits_disabled_when_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_MAX_AGENTS", "0")
    monkeypatch.setenv("STRIX_MAX_AGENT_DEPTH", "0")
    loader._cached = None
    try:
        coordinator = await _graph(
            ("root", None), ("a", "root"), ("b", "a"), ("c", "b"), ("d", "c")
        )
        error = await _fan_out_limit_error(coordinator, "d")
    finally:
        loader._cached = None

    assert error is None
