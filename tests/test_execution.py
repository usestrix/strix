"""Tests for the scan-wide budget-stop signal on the agent coordinator."""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

import pytest

from strix.core.agents import AgentCoordinator
from strix.core.execution import _notify_root_on_budget_reserve
from strix.tools.finish.tool import _blocking_active_agents


@pytest.mark.asyncio
async def test_reserve_stop_notifies_root_once(monkeypatch: pytest.MonkeyPatch) -> None:
    # All sub-agents trip the reserve together, but only a single scan-wide notice must
    # reach the root (not one message per stopped child).
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child-a", "recon", parent_id="root")
    await coordinator.register("child-b", "recon", parent_id="root")

    sent: list[tuple[str, dict[str, Any]]] = []

    async def _record(target_agent_id: str, message: dict[str, Any]) -> bool:
        sent.append((target_agent_id, message))
        return True

    monkeypatch.setattr(coordinator, "send", _record)

    # Both children stop at the reserve, but only the first notifies.
    await _notify_root_on_budget_reserve(coordinator)
    await _notify_root_on_budget_reserve(coordinator)

    assert len(sent) == 1
    target, message = sent[0]
    assert target == "root"
    assert message["type"] == "budget_reserve_stop"
    assert "finish_scan" in str(message["content"])


@pytest.mark.asyncio
async def test_concurrent_reserve_claims_yield_single_root() -> None:
    # All sub-agents trip the reserve at roughly the same time and race to notify; the
    # dedup must hand the root id to exactly one of them, no matter the interleaving.
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    for i in range(12):
        await coordinator.register(f"child-{i}", "recon", parent_id="root")

    results = await asyncio.gather(*(coordinator.claim_reserve_notification() for _ in range(12)))

    assert results.count("root") == 1
    assert all(r is None for r in results if r != "root")


@pytest.mark.asyncio
async def test_claim_reserve_sets_flag_and_wakes_parked_agents() -> None:
    # The first reserve claim must flip the scan-wide reserve flag and release any parked
    # sub-agent so it exits instead of sitting idle after the reserve is tripped.
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")

    flag_before = coordinator.reserve_stopped
    assert flag_before is False
    waiter = asyncio.create_task(coordinator.wait_for_message("child"))
    await asyncio.sleep(0)
    assert not waiter.done()

    await coordinator.claim_reserve_notification()

    flag_after = coordinator.reserve_stopped
    assert flag_after is True
    await asyncio.wait_for(waiter, timeout=1.0)


@pytest.mark.asyncio
async def test_finish_scan_bypasses_active_agent_guard_after_reserve() -> None:
    # After the reserve is tripped every sub-agent is force-stopped, so finish_scan must
    # not be blocked by lingering "running" siblings (each rejection burns reserved budget).
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    await coordinator.set_status("child", "running")

    # Before the reserve trips, a running sibling still blocks the root.
    assert await _blocking_active_agents(coordinator, "root", None) != []

    await coordinator.claim_reserve_notification()  # trips the reserve

    # After it trips, the same running sibling no longer blocks finishing.
    assert await _blocking_active_agents(coordinator, "root", None) == []


@pytest.mark.asyncio
async def test_finish_scan_gate_ignores_sub_agent_caller() -> None:
    # Only the root gates on siblings; a sub-agent caller never blocks (it uses agent_finish).
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    await coordinator.set_status("child", "running")

    assert await _blocking_active_agents(coordinator, "child", "root") == []


@pytest.mark.asyncio
async def test_reserve_stop_notify_noop_without_root(monkeypatch: pytest.MonkeyPatch) -> None:
    # With no root registered there is nobody to notify.
    coordinator = AgentCoordinator()
    await coordinator.register("child", "recon", parent_id="missing")

    sent: list[tuple[str, dict[str, Any]]] = []

    async def _record(target_agent_id: str, message: dict[str, Any]) -> bool:
        sent.append((target_agent_id, message))
        return True

    monkeypatch.setattr(coordinator, "send", _record)
    await _notify_root_on_budget_reserve(coordinator)

    assert sent == []


@pytest.mark.asyncio
async def test_snapshot_round_trip_preserves_stop_flags() -> None:
    # An interrupted scan that already tripped the cap/reserve must remember that on resume,
    # or respawned children get another paid response and the finish_scan blocker returns.
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.trigger_budget_stop()
    await coordinator.claim_reserve_notification()

    snap = await coordinator.snapshot()
    assert snap["budget_stopped"] is True
    assert snap["reserve_stopped"] is True

    restored = AgentCoordinator()
    await restored.restore(snap)
    assert restored.budget_stopped is True
    assert restored.reserve_stopped is True


@pytest.mark.asyncio
async def test_legacy_snapshot_without_stop_flags_defaults_to_false() -> None:
    # Snapshots written before the stop flags existed must restore safely.
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    snap = await coordinator.snapshot()
    del snap["budget_stopped"]
    del snap["reserve_stopped"]

    restored = AgentCoordinator()
    await restored.restore(snap)
    assert restored.budget_stopped is False
    assert restored.reserve_stopped is False


@pytest.mark.asyncio
async def test_randomized_reserve_claim_race_many_interleavings() -> None:
    # Fuzz the claim dedup across many randomized task interleavings: regardless of who
    # runs first or how the event loop schedules the claimants, exactly one claimant may
    # win the root id and every sub-agent must be released from wait_for_message.
    for seed in range(25):
        coordinator = AgentCoordinator()
        await coordinator.register("root", "strix", parent_id=None)
        child_ids = [f"child-{i}" for i in range(8)]
        for child_id in child_ids:
            await coordinator.register(child_id, "recon", parent_id="root")

        waiters = [asyncio.create_task(coordinator.wait_for_message(cid)) for cid in child_ids]
        await asyncio.sleep(0)  # let every waiter park

        async def _claim(delay: float, coord: AgentCoordinator = coordinator) -> str | None:
            await asyncio.sleep(delay)
            return await coord.claim_reserve_notification()

        # deterministic pseudo-shuffled delays, different for every seed
        delays = [((seed * 31 + i * 17) % 50) / 10_000 for i in range(len(child_ids))]
        results = await asyncio.gather(*(_claim(delay) for delay in delays))

        assert results.count("root") == 1, f"seed {seed}: expected exactly one winner"
        await asyncio.wait_for(asyncio.gather(*waiters), timeout=1.0)
        assert coordinator.reserve_stopped is True


@pytest.mark.asyncio
async def test_reserve_claim_never_loses_root_wake() -> None:
    # The claim wakes everyone (including a parked root) before the notice is sent; the
    # root must re-park and still be woken by the send itself — the wake carrying the
    # pending message must never be lost regardless of interleaving.
    for _ in range(10):
        coordinator = AgentCoordinator()
        await coordinator.register("root", "strix", parent_id=None)
        await coordinator.register("child", "recon", parent_id="root")

        root_waiter = asyncio.create_task(coordinator.wait_for_message("root"))
        await asyncio.sleep(0)
        assert not root_waiter.done()

        await coordinator.claim_reserve_notification()
        await asyncio.sleep(0)  # root wakes, sees no pending, re-parks

        # simulate the notice delivery bookkeeping (session-less direct increment)
        async with coordinator._lock:
            coordinator.pending_counts["root"] = 1
            coordinator.runtimes["root"].wake.set()

        await asyncio.wait_for(root_waiter, timeout=1.0)


@pytest.mark.asyncio
async def test_budget_stop_takes_precedence_over_reserve_for_all_roles() -> None:
    # With both flags set, wait_for_message releases every role and the run-loop guards
    # classify the stop as the scan-wide budget stop (checked first), not the reserve.
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    await coordinator.claim_reserve_notification()
    await coordinator.trigger_budget_stop()

    # both roles are released immediately
    await asyncio.wait_for(coordinator.wait_for_message("root"), timeout=1.0)
    await asyncio.wait_for(coordinator.wait_for_message("child"), timeout=1.0)
    assert coordinator.budget_stopped is True
    assert coordinator.reserve_stopped is True


@pytest.mark.asyncio
async def test_root_not_released_by_reserve_alone() -> None:
    # The reserve releases only sub-agents; the root keeps waiting until its notice (a
    # pending message) arrives, so it is not spun in a busy loop.
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")

    await coordinator.claim_reserve_notification()

    root_waiter = asyncio.create_task(coordinator.wait_for_message("root"))
    await asyncio.sleep(0.02)
    assert not root_waiter.done()  # still parked: reserve alone must not release the root

    root_waiter.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await root_waiter


@pytest.mark.asyncio
async def test_snapshot_during_concurrent_claims_is_consistent() -> None:
    # Snapshotting while claimants race must always capture a coherent boolean state and
    # restore to the same flags — never a partially-applied claim.
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    for i in range(6):
        await coordinator.register(f"child-{i}", "recon", parent_id="root")

    claims = [asyncio.create_task(coordinator.claim_reserve_notification()) for _ in range(6)]
    snap = await coordinator.snapshot()
    await asyncio.gather(*claims)

    assert isinstance(snap["reserve_stopped"], bool)
    final_snap = await coordinator.snapshot()
    assert final_snap["reserve_stopped"] is True

    restored = AgentCoordinator()
    await restored.restore(final_snap)
    assert restored.reserve_stopped is True
    # a restored coordinator never re-issues the root notification
    assert await restored.claim_reserve_notification() is None


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
