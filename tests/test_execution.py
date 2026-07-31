"""Tests for the scan-wide budget-stop signal on the agent coordinator."""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from agents.items import MessageOutputItem
from agents.memory import SQLiteSession
from agents.tool_context import ToolContext
from openai.types.responses import ResponseOutputMessage, ResponseOutputRefusal

from strix.config import codex
from strix.core import execution
from strix.core.agents import AgentCoordinator
from strix.core.execution import (
    _handle_content_guardrail,
    _notify_parent_on_terminal,
    _notify_root_on_budget_reserve,
    respawn_subagents,
)
from strix.tools.finish.tool import finish_scan


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
        if False:
            yield None

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
@pytest.mark.parametrize("status", ["stopped", "failed", "crashed"])
async def test_terminal_child_wakes_parked_parent(tmp_path: Any, status: str) -> None:
    # Regression for #870: a child reaching a terminal state (e.g. MaxTurnsExceeded
    # -> "stopped") must wake the parent parked in wait_for_message, so the root can
    # finalize the scan instead of hanging for a completion report that never arrives.
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "SQL Injection", parent_id="root")
    session = SQLiteSession("root", tmp_path / "agents.db")
    await coordinator.attach_runtime("root", session=session)

    root_waiter = asyncio.create_task(coordinator.wait_for_message("root"))
    await asyncio.sleep(0)
    assert not root_waiter.done()

    await coordinator.set_status("child", status, error="Max turns (500) exceeded")
    await _notify_parent_on_terminal(coordinator, "child", status)

    await asyncio.wait_for(root_waiter, timeout=1.0)
    assert coordinator.pending_counts.get("root", 0) > 0
    session.close()


@pytest.mark.asyncio
async def test_notify_parent_on_terminal_ignores_non_terminal_status(tmp_path: Any) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    session = SQLiteSession("root", tmp_path / "agents.db")
    await coordinator.attach_runtime("root", session=session)

    await _notify_parent_on_terminal(coordinator, "child", "waiting")

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

    await _notify_parent_on_terminal(coordinator, "child", "crashed")

    assert stream.cancelled is False
    assert coordinator.pending_counts.get("root", 0) > 0
    session.close()


@pytest.mark.asyncio
async def test_guardrail_interactive_parks_agent_wakeable(tmp_path: Any) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    exc = codex.CodexContentGuardrailError("chatgpt/gpt-5.6-sol")

    result = await _handle_content_guardrail(coordinator, "child", exc, interactive=True)

    assert result is None
    assert coordinator.statuses["child"] == "waiting"
    assert "STRIX_LLM" in coordinator.errors["child"]

    waiter = asyncio.create_task(coordinator.wait_for_message("child"))
    await asyncio.sleep(0)
    assert not waiter.done()
    session = SQLiteSession("child", tmp_path / "agents.db")
    await coordinator.attach_runtime("child", session=session)
    await coordinator.send("child", {"from": "user", "content": "switched model, resume"})
    await asyncio.wait_for(waiter, timeout=1.0)
    session.close()


@pytest.mark.asyncio
async def test_guardrail_noninteractive_fails_only_blocked_agent(tmp_path: Any) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    session = SQLiteSession("root", tmp_path / "agents.db")
    await coordinator.attach_runtime("root", session=session)
    exc = codex.CodexContentGuardrailError("chatgpt/gpt-5.6-sol")

    result = await _handle_content_guardrail(coordinator, "child", exc, interactive=False)

    assert result is None
    assert coordinator.statuses["child"] == "failed"
    assert "STRIX_LLM" in coordinator.errors["child"]
    assert coordinator.statuses["root"] == "running"
    assert coordinator.pending_counts.get("root", 0) > 0
    session.close()


@pytest.mark.asyncio
async def test_structured_provider_refusal_fails_interactive_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal = "This request was blocked under the provider's usage policy."
    stream = _StructuredRefusalStream(refusal)
    monkeypatch.setattr(execution.Runner, "run_streamed", lambda *_args, **_kwargs: stream)
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
    monkeypatch.setattr(execution.Runner, "run_streamed", lambda *_args, **_kwargs: stream)
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
async def test_resume_revives_guardrail_parked_child_but_not_plain_waiting(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("blocked", "recon", parent_id="root")
    await coordinator.register("peer_waiter", "recon", parent_id="root")
    await coordinator.set_status("blocked", "waiting", error="STRIX_LLM guardrail")
    await coordinator.set_status("peer_waiter", "waiting")

    parked: dict[str, bool] = {}

    async def _fake_start_child_runner(**kwargs: Any) -> None:
        parked[kwargs["child_id"]] = bool(kwargs["start_parked"])

    monkeypatch.setattr(execution, "_start_child_runner", _fake_start_child_runner)

    await respawn_subagents(
        coordinator=coordinator,
        factory=lambda **_kwargs: object(),
        agents_db_path=tmp_path / "agents.db",
        sessions_to_close=[],
        run_config=MagicMock(),
        max_turns=10,
        interactive=True,
        parent_ctx={"agent_id": "root", "parent_id": None},
        root_id="root",
    )

    assert parked["blocked"] is False
    assert parked["peer_waiter"] is True
