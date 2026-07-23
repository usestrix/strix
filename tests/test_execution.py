"""Tests for the scan-wide budget-stop signal on the agent coordinator."""

from __future__ import annotations

import asyncio

import pytest

from strix.core.agents import AgentCoordinator
from strix.core.execution import run_agent_loop
from strix.core.hooks import BudgetExceededError, NoProgressExceededError


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


# --------------------------------------------------------------------------- #
# Scan-limit trigger provenance (which limit fired: budget vs no-progress)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_trigger_budget_stop_stashes_exception() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    assert coordinator.scan_limit_exc is None
    exc = NoProgressExceededError("stuck")
    await coordinator.trigger_budget_stop(exc)

    assert coordinator.budget_stopped is True
    assert coordinator.scan_limit_exc is exc


@pytest.mark.asyncio
async def test_trigger_budget_stop_first_writer_wins() -> None:
    """The first trigger records the stop reason; later triggers don't overwrite.

    A no-progress trip followed by a cascading budget signal must keep
    no-progress as the recorded reason so the runner writes the right report.
    """
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    first = NoProgressExceededError("no progress")
    second = BudgetExceededError("budget")
    await coordinator.trigger_budget_stop(first)
    await coordinator.trigger_budget_stop(second)

    assert coordinator.scan_limit_exc is first


@pytest.mark.asyncio
async def test_trigger_budget_stop_without_exc_leaves_stash_none() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    await coordinator.trigger_budget_stop()

    assert coordinator.budget_stopped is True
    assert coordinator.scan_limit_exc is None


# --------------------------------------------------------------------------- #
# Polling-station regression: a child tripping no-progress must surface as
# NoProgressExceededError at the root's polling exit (not a hardcoded
# BudgetExceededError), so the runner writes the no-progress early-stop report.
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_noninteractive_polling_raises_stashed_no_progress() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    # Simulate a child having already tripped the no-progress breaker: the
    # coordinator flag is set and the triggering exception is stashed.
    await coordinator.trigger_budget_stop(NoProgressExceededError("stuck"))

    with pytest.raises(NoProgressExceededError):
        await run_agent_loop(
            agent=object(),
            initial_input=[],
            run_config=object(),  # type: ignore[arg-type]  # short-circuited; never used
            context={},
            max_turns=5,
            coordinator=coordinator,
            agent_id="root",
            interactive=False,
        )

    assert coordinator.statuses["root"] == "stopped"


@pytest.mark.asyncio
async def test_noninteractive_polling_falls_back_to_budget_without_stash() -> None:
    """A plain budget stop (no stashed exception) still raises BudgetExceededError."""
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.trigger_budget_stop()

    with pytest.raises(BudgetExceededError):
        await run_agent_loop(
            agent=object(),
            initial_input=[],
            run_config=object(),  # type: ignore[arg-type]  # short-circuited; never used
            context={},
            max_turns=5,
            coordinator=coordinator,
            agent_id="root",
            interactive=False,
        )
