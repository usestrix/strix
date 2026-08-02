"""Tests for the scan-wide budget-stop signal on the agent coordinator."""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Any, cast
from unittest.mock import MagicMock

import pytest
from agents.exceptions import MaxTurnsExceeded
from agents.items import MessageOutputItem
from agents.memory import SQLiteSession
from agents.tool_context import ToolContext
from openai.types.responses import ResponseOutputMessage, ResponseOutputRefusal

from strix.core import execution
from strix.core.agents import AgentCoordinator
from strix.core.execution import (
    _notify_root_on_budget_reserve,
    notify_parent_on_terminal,
)
from strix.core.sessions import seed_initial_input
from strix.tools.agents_graph.tools import agent_finish, stop_agent
from strix.tools.finish.tool import finish_scan


_NO_STREAM_EVENTS: list[Any] = []


class _StructuredRefusalStream:
    def __init__(self, refusal: str) -> None:
        self.run_loop_exception: BaseException | None = None
        self.new_items = [
            MessageOutputItem(
                agent=MagicMock(),
                raw_item=ResponseOutputMessage(
                    id="msg-refusal",
                    content=[ResponseOutputRefusal(type="refusal", refusal=refusal)],
                    role="assistant",
                    status="completed",
                    type="message",
                ),
            )
        ]

    async def stream_events(self) -> Any:
        for event in _NO_STREAM_EVENTS:
            yield event

    def cancel(self, mode: str = "immediate") -> None:  # noqa: ARG002
        return


async def _call_finish_scan(
    coordinator: AgentCoordinator, agent_id: str, parent_id: str | None
) -> dict[str, Any]:
    ctx = ToolContext(
        context={"coordinator": coordinator, "agent_id": agent_id, "parent_id": parent_id},
        tool_name="finish_scan",
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    fields = ("executive_summary", "methodology", "technical_analysis", "recommendations")
    result: str = await finish_scan.on_invoke_tool(ctx, json.dumps(dict.fromkeys(fields, "x")))
    parsed: dict[str, Any] = json.loads(result)
    return parsed


async def _call_agent_finish(
    coordinator: AgentCoordinator,
    agent_id: str,
    parent_id: str | None,
    *,
    report_to_parent: bool,
) -> dict[str, Any]:
    ctx = ToolContext(
        context={"coordinator": coordinator, "agent_id": agent_id, "parent_id": parent_id},
        tool_name="agent_finish",
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    result: str = await agent_finish.on_invoke_tool(
        ctx,
        json.dumps({"result_summary": "done", "report_to_parent": report_to_parent}),
    )
    parsed: dict[str, Any] = json.loads(result)
    return parsed


async def _call_stop_agent(
    coordinator: AgentCoordinator, agent_id: str, target_agent_id: str
) -> dict[str, Any]:
    ctx = ToolContext(
        context={"coordinator": coordinator, "agent_id": agent_id},
        tool_name="stop_agent",
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    result: str = await stop_agent.on_invoke_tool(
        ctx, json.dumps({"target_agent_id": target_agent_id})
    )
    parsed: dict[str, Any] = json.loads(result)
    return parsed


@pytest.mark.asyncio
async def test_reserve_stop_notifies_root_once(monkeypatch: pytest.MonkeyPatch) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child-a", "recon", parent_id="root")
    await coordinator.register("child-b", "recon", parent_id="root")

    sent: list[tuple[str, dict[str, Any]]] = []

    async def _record(target_agent_id: str, message: dict[str, Any]) -> bool:
        sent.append((target_agent_id, message))
        return True

    monkeypatch.setattr(coordinator, "send", _record)

    await _notify_root_on_budget_reserve(coordinator)
    await _notify_root_on_budget_reserve(coordinator)

    assert len(sent) == 1
    target, message = sent[0]
    assert target == "root"
    assert message["type"] == "budget_reserve_stop"
    assert "finish_scan" in str(message["content"])


@pytest.mark.asyncio
async def test_concurrent_reserve_claims_yield_single_root() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    for i in range(12):
        await coordinator.register(f"child-{i}", "recon", parent_id="root")

    results = await asyncio.gather(*(coordinator.claim_reserve_notification() for _ in range(12)))

    assert results.count("root") == 1
    assert all(r is None for r in results if r != "root")


@pytest.mark.asyncio
async def test_claim_reserve_sets_flag_and_wakes_parked_agents() -> None:
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
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    await coordinator.set_status("child", "running")

    blocked = await _call_finish_scan(coordinator, "root", None)
    assert blocked["scan_completed"] is False
    assert blocked["active_agents"]

    await coordinator.claim_reserve_notification()

    finished = await _call_finish_scan(coordinator, "root", None)
    assert finished["scan_completed"] is True
    assert coordinator.statuses["root"] == "completed"


@pytest.mark.asyncio
async def test_finish_scan_gate_ignores_sub_agent_caller() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    await coordinator.set_status("child", "running")

    result = await _call_finish_scan(coordinator, "child", "root")
    assert "active_agents" not in result
    assert result["success"] is False
    assert "root" in result["error"]


@pytest.mark.asyncio
async def test_reserve_stop_notify_noop_without_root(monkeypatch: pytest.MonkeyPatch) -> None:
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
    for seed in range(25):
        coordinator = AgentCoordinator()
        await coordinator.register("root", "strix", parent_id=None)
        child_ids = [f"child-{i}" for i in range(8)]
        for child_id in child_ids:
            await coordinator.register(child_id, "recon", parent_id="root")

        waiters = [asyncio.create_task(coordinator.wait_for_message(cid)) for cid in child_ids]
        await asyncio.sleep(0)

        async def _claim(delay: float, coord: AgentCoordinator = coordinator) -> str | None:
            await asyncio.sleep(delay)
            return await coord.claim_reserve_notification()

        delays = [((seed * 31 + i * 17) % 50) / 10_000 for i in range(len(child_ids))]
        results = await asyncio.gather(*(_claim(delay) for delay in delays))

        assert results.count("root") == 1, f"seed {seed}: expected exactly one winner"
        await asyncio.wait_for(asyncio.gather(*waiters), timeout=1.0)
        assert coordinator.reserve_stopped is True


@pytest.mark.asyncio
async def test_reserve_claim_never_loses_root_wake() -> None:
    for _ in range(10):
        coordinator = AgentCoordinator()
        await coordinator.register("root", "strix", parent_id=None)
        await coordinator.register("child", "recon", parent_id="root")

        root_waiter = asyncio.create_task(coordinator.wait_for_message("root"))
        await asyncio.sleep(0)
        assert not root_waiter.done()

        await coordinator.claim_reserve_notification()
        await asyncio.sleep(0)

        async with coordinator._lock:
            coordinator.pending_counts["root"] = 1
            coordinator.runtimes["root"].wake.set()

        await asyncio.wait_for(root_waiter, timeout=1.0)


@pytest.mark.asyncio
async def test_budget_stop_takes_precedence_over_reserve_for_all_roles() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    await coordinator.claim_reserve_notification()
    await coordinator.trigger_budget_stop()

    await asyncio.wait_for(coordinator.wait_for_message("root"), timeout=1.0)
    await asyncio.wait_for(coordinator.wait_for_message("child"), timeout=1.0)
    assert coordinator.budget_stopped is True
    assert coordinator.reserve_stopped is True


@pytest.mark.asyncio
async def test_root_not_released_by_reserve_alone() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")

    await coordinator.claim_reserve_notification()

    root_waiter = asyncio.create_task(coordinator.wait_for_message("root"))
    await asyncio.sleep(0.02)
    assert not root_waiter.done()

    root_waiter.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await root_waiter


@pytest.mark.asyncio
async def test_snapshot_during_concurrent_claims_is_consistent() -> None:
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


@pytest.mark.asyncio
async def test_pause_for_budget_sets_flag_and_status() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    await coordinator.pause_for_budget("root")
    assert coordinator.budget_paused is True
    assert coordinator.statuses["root"] == "budget_paused"


@pytest.mark.asyncio
async def test_resume_from_budget_pause_extends_and_nudges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child-a", "recon", parent_id="root")
    await coordinator.register("child-b", "recon", parent_id="root")
    await coordinator.pause_for_budget("root")
    await coordinator.pause_for_budget("child-a")
    await coordinator.pause_for_budget("child-b")

    extensions: list[int] = []
    coordinator.set_budget_extender(lambda: extensions.append(1))

    sent: list[tuple[str, dict[str, Any]]] = []

    async def _record(target_agent_id: str, message: dict[str, Any]) -> bool:
        sent.append((target_agent_id, message))
        return True

    monkeypatch.setattr(coordinator, "send", _record)

    await coordinator.resume_from_budget_pause(exclude="root")

    assert coordinator.budget_paused is False
    assert len(extensions) == 1
    assert all(coordinator.statuses[aid] == "waiting" for aid in ("root", "child-a", "child-b"))
    assert sorted(target for target, _ in sent) == ["child-a", "child-b"]
    assert all(message["type"] == "budget_extended" for _, message in sent)

    await coordinator.resume_from_budget_pause(exclude="root")
    assert len(extensions) == 1


@pytest.mark.asyncio
async def test_user_send_resumes_budget_pause(tmp_path: Any) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    session = SQLiteSession("root", tmp_path / "agents.db")
    await coordinator.attach_runtime("root", session=session)
    await coordinator.pause_for_budget("root")

    extensions: list[int] = []
    coordinator.set_budget_extender(lambda: extensions.append(1))

    delivered = await coordinator.send("root", {"from": "user", "content": "keep going"})

    assert delivered is True
    assert coordinator.budget_paused is False
    assert len(extensions) == 1
    assert coordinator.statuses["root"] == "waiting"
    assert coordinator.pending_counts["root"] == 1
    session.close()


@pytest.mark.asyncio
async def test_non_user_send_does_not_resume_budget_pause(tmp_path: Any) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    session = SQLiteSession("root", tmp_path / "agents.db")
    await coordinator.attach_runtime("root", session=session)
    await coordinator.pause_for_budget("root")

    extensions: list[int] = []
    coordinator.set_budget_extender(lambda: extensions.append(1))

    await coordinator.send("root", {"from": "system", "content": "status"})

    assert coordinator.budget_paused is True
    assert extensions == []
    assert coordinator.statuses["root"] == "budget_paused"
    session.close()


@pytest.mark.asyncio
async def test_reset_budget_stops_clears_pause_and_normalizes_statuses() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.trigger_budget_stop()
    await coordinator.claim_reserve_notification()
    await coordinator.pause_for_budget("root")

    await coordinator.reset_budget_stops(budget_stopped=False, reserve_stopped=False)

    assert coordinator.budget_stopped is False
    assert coordinator.reserve_stopped is False
    assert coordinator.budget_paused is False
    assert coordinator.statuses["root"] == "waiting"


@pytest.mark.asyncio
async def test_reset_budget_stops_can_preserve_pause() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.pause_for_budget("root")

    await coordinator.reset_budget_stops(
        budget_stopped=False, reserve_stopped=False, budget_paused=True
    )

    assert coordinator.budget_paused is True
    assert coordinator.statuses["root"] == "budget_paused"


@pytest.mark.asyncio
async def test_snapshot_round_trip_preserves_budget_pause() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.pause_for_budget("root")

    snap = await coordinator.snapshot()
    assert snap["budget_paused"] is True

    restored = AgentCoordinator()
    await restored.restore(snap)
    assert restored.budget_paused is True
    assert restored.statuses["root"] == "budget_paused"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["completed", "stopped", "failed", "crashed"])
async def test_terminal_child_wakes_parked_parent(tmp_path: Any, status: str) -> None:
    # Regression for #870 and #947: a child reaching any terminal state - including a
    # plain "completed" - must wake the parent parked in wait_for_agents, so the root
    # can finalize the scan instead of hanging for a report that never arrives.
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "SQL Injection", parent_id="root")
    session = SQLiteSession("root", tmp_path / "agents.db")
    await coordinator.attach_runtime("root", session=session)

    root_waiter = asyncio.create_task(coordinator.wait_for_message("root"))
    await asyncio.sleep(0)
    assert not root_waiter.done()

    await coordinator.set_status("child", status, error="Max turns (500) exceeded")
    await notify_parent_on_terminal(coordinator, "child", status)

    await asyncio.wait_for(root_waiter, timeout=1.0)
    assert coordinator.pending_counts.get("root", 0) > 0
    session.close()


@pytest.mark.asyncio
async def test_agent_finish_without_report_still_wakes_parent(tmp_path: Any) -> None:
    # Regression for #947: a child that completes with report_to_parent=False owes its
    # parent a terminal notice, otherwise the parent waits out its full timeout.
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    session = SQLiteSession("root", tmp_path / "agents.db")
    await coordinator.attach_runtime("root", session=session)

    root_waiter = asyncio.create_task(coordinator.wait_for_message("root"))
    await asyncio.sleep(0)

    await _call_agent_finish(coordinator, "child", "root", report_to_parent=False)

    await asyncio.wait_for(root_waiter, timeout=1.0)
    assert coordinator.statuses["child"] == "completed"
    assert coordinator.pending_counts.get("root", 0) == 1
    session.close()


@pytest.mark.asyncio
async def test_agent_finish_report_suppresses_the_terminal_notice(tmp_path: Any) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    session = SQLiteSession("root", tmp_path / "agents.db")
    await coordinator.attach_runtime("root", session=session)

    await _call_agent_finish(coordinator, "child", "root", report_to_parent=True)
    # The exit backstop must not duplicate the report the child already delivered.
    await execution._notify_parent_on_exit(coordinator, "child")

    assert coordinator.pending_counts.get("root", 0) == 1
    session.close()


@pytest.mark.asyncio
async def test_stop_agent_notifies_a_parent_that_is_not_the_stopper(tmp_path: Any) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    await coordinator.register("grandchild", "sqli", parent_id="child")
    session = SQLiteSession("child", tmp_path / "agents.db")
    await coordinator.attach_runtime("child", session=session)

    await _call_stop_agent(coordinator, "root", "grandchild")

    assert coordinator.statuses["grandchild"] == "stopped"
    assert coordinator.pending_counts.get("child", 0) == 1
    # The stopper already knows; only the waiting parent needs telling.
    assert coordinator.pending_counts.get("root", 0) == 0
    session.close()


@pytest.mark.asyncio
async def test_stop_agent_does_not_notify_the_stopping_parent(tmp_path: Any) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    session = SQLiteSession("root", tmp_path / "agents.db")
    await coordinator.attach_runtime("root", session=session)

    await _call_stop_agent(coordinator, "root", "child")

    assert coordinator.pending_counts.get("root", 0) == 0
    session.close()


@pytest.mark.asyncio
async def test_notify_parent_on_terminal_ignores_non_terminal_status(tmp_path: Any) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    session = SQLiteSession("root", tmp_path / "agents.db")
    await coordinator.attach_runtime("root", session=session)

    await notify_parent_on_terminal(coordinator, "child", "waiting")

    assert coordinator.pending_counts.get("root", 0) == 0
    session.close()


class _RecordingStream:
    def __init__(self) -> None:
        self.cancelled = False
        self.cancel_mode: str | None = None

    def cancel(self, mode: str = "immediate") -> None:
        self.cancelled = True
        self.cancel_mode = mode


@pytest.mark.asyncio
async def test_terminal_notice_does_not_cancel_parent_stream(tmp_path: Any) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    session = SQLiteSession("root", tmp_path / "agents.db")
    stream = _RecordingStream()
    await coordinator.attach_runtime("root", session=session, interrupt_on_message=True)
    await coordinator.attach_stream("root", stream)

    await notify_parent_on_terminal(coordinator, "child", "crashed")

    assert stream.cancelled is False
    assert coordinator.pending_counts.get("root", 0) > 0
    session.close()


@pytest.mark.asyncio
async def test_send_queues_without_session_and_drains_on_consume(tmp_path: Any) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    assert await coordinator.send("root", {"from": "user", "content": "hello"}) is True
    assert coordinator.pending_counts["root"] == 1

    session = SQLiteSession("root", tmp_path / "agents.db")
    await coordinator.attach_runtime("root", session=session)

    count, items = await coordinator.consume_pending("root", include_items=True)
    assert count == 1
    assert items[0]["content"] == "hello"
    stored = await session.get_items()
    last = cast("dict[str, Any]", stored[-1])
    assert last["content"] == "hello"
    session.close()


@pytest.mark.asyncio
async def test_error_parked_agent_only_released_by_user_message(tmp_path: Any) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    session = SQLiteSession("child", tmp_path / "agents.db")
    await coordinator.attach_runtime("child", session=session)
    await coordinator.set_status("child", "crashed", error="boom")

    await coordinator.send("child", {"from": "root", "content": "peer nudge"})
    waiter = asyncio.create_task(coordinator.wait_for_message("child"))
    await asyncio.sleep(0.05)
    assert not waiter.done()

    await coordinator.send("child", {"from": "user", "content": "wake up"})
    assert await asyncio.wait_for(waiter, timeout=1.0) is True

    count, items = await coordinator.consume_pending("child", include_items=True)
    assert count == 2
    assert items[0]["content"].endswith("peer nudge")
    assert items[1]["content"] == "wake up"
    session.close()


@pytest.mark.asyncio
async def test_wait_for_message_timeout_returns_false() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("child", "recon", parent_id="root")

    assert await coordinator.wait_for_message("child", timeout=0.05) is False


@pytest.mark.asyncio
async def test_snapshot_round_trip_preserves_mailboxes() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.send("root", {"from": "user", "content": "queued"})

    snap = await coordinator.snapshot()
    restored = AgentCoordinator()
    await restored.restore(snap)

    assert restored.pending_counts["root"] == 1
    assert restored.runtimes["root"].mailbox == [{"from": "user", "content": "queued"}]


@pytest.mark.asyncio
async def test_run_cycle_parked_parks_instead_of_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("unexpected explosion")

    monkeypatch.setattr(execution, "_run_cycle", _boom)

    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    result = await execution._run_cycle_parked(
        object(),
        coordinator,
        "root",
        input_data=[],
        run_config=None,  # type: ignore[arg-type]
        context={},
        max_turns=5,
        session=None,
        event_sink=None,
        hooks=None,
    )

    assert result is None
    assert coordinator.statuses["root"] == "failed"
    assert coordinator.errors["root"] == "unexpected explosion"


class _SalvageStream:
    def __init__(self, replay: list[dict[str, Any]]) -> None:
        self._replay = replay

    def to_input_list(self) -> list[dict[str, Any]]:
        return self._replay


@pytest.mark.asyncio
async def test_salvage_stream_to_session_preserves_full_history(tmp_path: Any) -> None:
    session = SQLiteSession("child", tmp_path / "agents.db")
    await session.add_items([{"role": "user", "content": "identity + task"}])
    pre_run = list(await session.get_items())

    # A crash mid-run: the stream produced two turns the SDK never committed.
    stream = _SalvageStream(
        [
            {"role": "assistant", "content": "recon turn 1"},
            {"role": "assistant", "content": "recon turn 2"},
        ]
    )
    await execution._salvage_stream_to_session(session, pre_run, stream, "child")

    stored = [cast("dict[str, Any]", i) for i in await session.get_items()]
    assert [i["content"] for i in stored] == [
        "identity + task",
        "recon turn 1",
        "recon turn 2",
    ]

    # A crash with nothing new to salvage leaves the session untouched.
    await execution._salvage_stream_to_session(
        session, list(await session.get_items()), _SalvageStream([]), "child"
    )
    assert len(await session.get_items()) == 3
    session.close()


@pytest.mark.asyncio
async def test_seed_initial_input_persists_and_is_idempotent(tmp_path: Any) -> None:
    session = SQLiteSession("child", tmp_path / "agents.db")
    identity = [{"role": "user", "content": "You are agent recon (abc); do X."}]

    assert await seed_initial_input(session, identity) is True
    assert len(await session.get_items()) == 1

    # A populated session is left untouched (no duplicate identity message).
    assert await seed_initial_input(session, identity) is False
    assert len(await session.get_items()) == 1

    assert await seed_initial_input(session, []) is False
    session.close()


@pytest.mark.asyncio
async def test_structured_provider_refusal_fails_interactive_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal = "This request was blocked under the provider's usage policy."
    stream = _StructuredRefusalStream(refusal)
    monkeypatch.setattr(
        "strix.core.execution.Runner.run_streamed", lambda *_args, **_kwargs: stream
    )
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    result = await execution._run_cycle(
        MagicMock(),
        coordinator,
        "root",
        input_data="task",
        run_config=MagicMock(),
        context={},
        max_turns=5,
        session=None,
        interactive=True,
        event_sink=None,
        hooks=None,
    )

    assert result is None
    assert coordinator.statuses["root"] == "failed"
    assert coordinator.errors["root"] == refusal


@pytest.mark.asyncio
async def test_structured_provider_refusal_fails_noninteractive_child(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal = "This request was blocked under the provider's usage policy."
    stream = _StructuredRefusalStream(refusal)
    monkeypatch.setattr(
        "strix.core.execution.Runner.run_streamed", lambda *_args, **_kwargs: stream
    )
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    session = SQLiteSession("root", tmp_path / "agents.db")
    await coordinator.attach_runtime("root", session=session)

    result = await execution._run_cycle(
        MagicMock(),
        coordinator,
        "child",
        input_data="task",
        run_config=MagicMock(),
        context={"parent_id": "root"},
        max_turns=5,
        session=None,
        interactive=False,
        event_sink=None,
        hooks=None,
    )

    assert result is None
    assert coordinator.statuses["child"] == "failed"
    assert coordinator.errors["child"] == refusal
    assert coordinator.pending_counts.get("root", 0) > 0
    session.close()


@pytest.mark.asyncio
async def test_run_agent_loop_seeds_identity_before_first_cycle(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("child", "recon", parent_id="root")
    session = SQLiteSession("child", tmp_path / "agents.db")

    captured: dict[str, Any] = {}

    async def _crash_first_turn(*_args: Any, **kwargs: Any) -> Any:
        captured["input_data"] = kwargs.get("input_data")
        captured["items_at_start"] = await session.get_items()
        raise RuntimeError("first-turn crash")

    monkeypatch.setattr(execution, "_run_cycle", _crash_first_turn)

    identity = [{"role": "user", "content": "You are agent recon (abc); maintain your identity."}]
    with pytest.raises(RuntimeError, match="first-turn crash"):
        await execution.run_agent_loop(
            agent=object(),
            initial_input=identity,
            run_config=None,  # type: ignore[arg-type]
            context={"agent_id": "child", "parent_id": "root"},
            max_turns=5,
            coordinator=coordinator,
            agent_id="child",
            interactive=False,
            session=session,
        )

    # The first cycle ran with an empty input against the pre-seeded session.
    assert captured["input_data"] == []
    assert captured["items_at_start"]
    # The identity/task survives the first-turn crash, so a revival can resume it.
    stored = await session.get_items()
    assert any("recon" in str(cast("dict[str, Any]", i).get("content", "")) for i in stored)
    session.close()


def _scripted_cycle(
    coordinator: AgentCoordinator,
    agent_id: str,
    statuses: list[str],
    calls: list[Any],
) -> Any:
    """Fake run cycle that leaves ``agent_id`` in a scripted status per call."""

    async def _cycle(*_args: Any, **kwargs: Any) -> Any:
        calls.append(kwargs.get("input_data"))
        status = statuses[min(len(calls) - 1, len(statuses) - 1)]
        await coordinator.set_status(agent_id, status)
        return MagicMock(final_output="plain text, no tool call")

    return _cycle


async def _drive(
    coordinator: AgentCoordinator,
    agent_id: str,
    *,
    interactive: bool,
    max_turns: int = 5,
) -> Any:
    return await execution._run_until_lifecycle(
        MagicMock(),
        coordinator,
        agent_id,
        initial_input=[],
        run_config=MagicMock(),
        context={"agent_id": agent_id, "parent_id": None},
        max_turns=max_turns,
        session=None,
        interactive=interactive,
        event_sink=None,
        hooks=None,
    )


@pytest.mark.asyncio
async def test_interactive_text_only_turn_is_nudged_instead_of_parking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A no-tool-call turn must not silently hand control back to the user."""
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    calls: list[Any] = []
    monkeypatch.setattr(
        execution,
        "_run_cycle_parked",
        _scripted_cycle(coordinator, "root", ["running", "completed"], calls),
    )

    await _drive(coordinator, "root", interactive=True)

    assert len(calls) == 2
    # The retry carries an explicit "call a tool" nudge rather than empty input.
    nudge = calls[1][0]["content"]
    assert "without a tool call" in nudge
    assert "respond_to_user" in nudge
    assert coordinator.statuses["root"] == "completed"


@pytest.mark.asyncio
async def test_interactive_explicit_park_gets_no_nudge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``waiting`` is only reachable via respond_to_user / wait_for_agents."""
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    calls: list[Any] = []
    monkeypatch.setattr(
        execution,
        "_run_cycle_parked",
        _scripted_cycle(coordinator, "root", ["waiting"], calls),
    )

    await _drive(coordinator, "root", interactive=True)

    assert len(calls) == 1
    assert coordinator.statuses["root"] == "waiting"


@pytest.mark.asyncio
async def test_interactive_recovery_exhaustion_parks_instead_of_crashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A human can resume an interactive scan, so exhaustion parks rather than dies."""
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    calls: list[Any] = []
    monkeypatch.setattr(
        execution,
        "_run_cycle_parked",
        _scripted_cycle(coordinator, "root", ["running"], calls),
    )

    await _drive(coordinator, "root", interactive=True)

    assert len(calls) == execution._INTERACTIVE_TOOL_RECOVERY_LIMIT
    assert coordinator.statuses["root"] == "waiting"


@pytest.mark.asyncio
async def test_interactive_subagent_exhaustion_tells_its_parent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A parked child must report up so its parent stops waiting on it.

    The parent is an agent, not a watching human, so a parent blocked in
    wait_for_agents otherwise burns its whole timeout on a completion
    report the child can no longer send.
    """
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    calls: list[Any] = []
    monkeypatch.setattr(
        execution,
        "_run_cycle_parked",
        _scripted_cycle(coordinator, "child", ["running"], calls),
    )

    await _drive(coordinator, "child", interactive=True)

    assert coordinator.statuses["child"] == "waiting"
    pending, items = await coordinator.consume_pending("root", include_items=True)
    assert pending == 1
    notice = str(items[0])
    assert "child" in notice
    assert "parked" in notice


@pytest.mark.asyncio
async def test_interactive_root_exhaustion_notifies_nobody(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The root has no parent to report to, so parking stays silent."""
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    monkeypatch.setattr(
        execution,
        "_run_cycle_parked",
        _scripted_cycle(coordinator, "root", ["running"], []),
    )

    await _drive(coordinator, "root", interactive=True)

    pending, _ = await coordinator.consume_pending("root")
    assert pending == 0


@pytest.mark.asyncio
async def test_noninteractive_recovery_exhaustion_crashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No user is present to resume an autonomous run, so it still fails loudly."""
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    calls: list[Any] = []
    monkeypatch.setattr(
        execution,
        "_run_cycle",
        _scripted_cycle(coordinator, "root", ["running"], calls),
    )

    with pytest.raises(MaxTurnsExceeded):
        await _drive(coordinator, "root", interactive=False, max_turns=2)

    assert len(calls) == 2
    assert coordinator.statuses["root"] == "crashed"


@pytest.mark.asyncio
async def test_tool_required_message_is_persisted_to_the_session(tmp_path: Any) -> None:
    session = SQLiteSession("root", tmp_path / "agents.db")

    assert (
        await execution._append_tool_required_message(
            session=session,
            context={"parent_id": None},
            attempt=1,
            limit=3,
            interactive=True,
        )
        == []
    )

    stored = [cast("dict[str, Any]", i) for i in await session.get_items()]
    assert "finish_scan" in stored[0]["content"]
    assert "respond_to_user" in stored[0]["content"]
    session.close()


@pytest.mark.asyncio
async def test_recovery_count_survives_a_snapshot_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A resumed agent must not earn a fresh nudge budget and loop forever."""
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    calls: list[Any] = []
    monkeypatch.setattr(
        execution,
        "_run_cycle_parked",
        _scripted_cycle(coordinator, "root", ["running"], calls),
    )

    await _drive(coordinator, "root", interactive=True)
    assert coordinator.recovery_counts["root"] == execution._INTERACTIVE_TOOL_RECOVERY_LIMIT

    restored = AgentCoordinator()
    await restored.restore(await coordinator.snapshot())
    assert restored.recovery_counts["root"] == execution._INTERACTIVE_TOOL_RECOVERY_LIMIT

    # The restored agent is already at its cap, so it parks after a single
    # further text-only cycle instead of starting the whole budget over.
    resumed_calls: list[Any] = []
    monkeypatch.setattr(
        execution,
        "_run_cycle_parked",
        _scripted_cycle(restored, "root", ["running"], resumed_calls),
    )
    await _drive(restored, "root", interactive=True)

    assert len(resumed_calls) == 1
    assert restored.statuses["root"] == "waiting"


@pytest.mark.asyncio
async def test_recovery_count_is_cleared_by_a_lifecycle_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    calls: list[Any] = []
    monkeypatch.setattr(
        execution,
        "_run_cycle_parked",
        _scripted_cycle(coordinator, "root", ["running", "completed"], calls),
    )

    await _drive(coordinator, "root", interactive=True)

    assert "root" not in coordinator.recovery_counts


@pytest.mark.asyncio
async def test_agent_awaiting_a_human_is_never_auto_resumed() -> None:
    """The user can message any agent, so parking for one is not root-only."""
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")

    for agent_id in ("root", "child"):
        await coordinator.park_waiting(agent_id, wait_kind="user")
        assert await execution._plain_waiting_timeout(coordinator, agent_id) is None


@pytest.mark.asyncio
async def test_agent_awaiting_other_agents_is_re_checked_on_a_timer() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.park_waiting("root", wait_kind="agents")

    timeout = await execution._plain_waiting_timeout(coordinator, "root")
    assert timeout == execution._WAITING_AUTO_RESUME_TIMEOUT_S


@pytest.mark.asyncio
async def test_idle_auto_resumes_stop_after_their_budget() -> None:
    """A wedged agent must not burn a model turn per timeout for the whole scan."""
    coordinator = AgentCoordinator()
    await coordinator.register("child", "recon", parent_id="root")
    await coordinator.park_waiting("child", wait_kind="agents")

    for _ in range(execution._MAX_IDLE_AUTO_RESUMES):
        assert await execution._plain_waiting_timeout(coordinator, "child") is not None
        await coordinator.record_idle_resume("child")

    assert await execution._plain_waiting_timeout(coordinator, "child") is None

    # A real message is real progress, so the budget starts over.
    await coordinator.reset_idle_resumes("child")
    assert await execution._plain_waiting_timeout(coordinator, "child") is not None


@pytest.mark.asyncio
async def test_wait_kind_survives_a_snapshot_round_trip() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.park_waiting("root", wait_kind="user")
    await coordinator.record_idle_resume("root")

    restored = AgentCoordinator()
    await restored.restore(await coordinator.snapshot())

    assert restored.wait_kinds["root"] == "user"
    assert restored.idle_resume_counts["root"] == 1
    assert await execution._plain_waiting_timeout(restored, "root") is None
