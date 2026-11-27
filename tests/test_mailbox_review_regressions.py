"""Offline regressions for completion persistence and interactive mailbox delivery."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
from agents import RunConfig
from agents.memory import SQLiteSession
from agents.tool_context import ToolContext

from strix.core import execution
from strix.core.agents import AgentCoordinator
from strix.report import state as state_module
from strix.report.state import ReportState
from strix.tools.finish.tool import finish_scan
from strix.tools.wait_for_user.tool import wait_for_user


if TYPE_CHECKING:
    from pathlib import Path


async def _call(tool: Any, context: dict[str, Any], arguments: dict[str, Any]) -> dict[str, Any]:
    raw = json.dumps(arguments)
    ctx = ToolContext(context=context, tool_name=tool.name, tool_call_id="call", tool_arguments=raw)
    return json.loads(await tool.on_invoke_tool(ctx, raw))


@pytest.mark.parametrize("after_rejection", ["retry", "failed", "interrupted"])
async def test_rejected_finish_does_not_persist_completion_or_send_telemetry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_rejection: str
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root", parent_id=None)
    await coordinator.attach_runtime("root", resumable=False)
    state = ReportState("offline-finish-race")
    state._run_dir = tmp_path
    monkeypatch.setattr(state_module, "get_global_report_state", lambda: state)
    posthog_end, scarf_end = Mock(), Mock()
    monkeypatch.setattr(state_module.posthog, "end", posthog_end)
    monkeypatch.setattr(state_module.scarf, "end", scarf_end)
    loop = asyncio.get_running_loop()
    original_save = state.save_run_data
    inject = True

    def save(*args: Any, **kwargs: Any) -> None:
        nonlocal inject
        original_save(*args, **kwargs)
        if inject:
            inject = False
            accepted = asyncio.run_coroutine_threadsafe(
                coordinator.send("root", {"from": "reviewer", "content": "Recheck summary"}),
                loop,
            ).result(timeout=5)
            assert accepted

    monkeypatch.setattr(state, "save_run_data", save)
    context = {"coordinator": coordinator, "agent_id": "root", "parent_id": None}
    arguments = dict.fromkeys(
        ("executive_summary", "methodology", "technical_analysis", "recommendations"), "Reviewed"
    )
    result = await _call(finish_scan, context, arguments)
    assert result["success"] is False
    assert result["scan_completed"] is False
    record = json.loads((tmp_path / "run.json").read_text())
    assert record["status"] == "running"
    assert record["end_time"] is None
    assert record["scan_results"]["scan_completed"] is False
    assert coordinator.statuses["root"] == "running"
    posthog_end.assert_not_called()
    scarf_end.assert_not_called()

    if after_rejection == "retry":
        await coordinator.consume_pending("root", include_items=True)
        result = await _call(finish_scan, context, arguments)
        assert result["success"] and result["scan_completed"]
        assert coordinator.statuses["root"] == "completed"
        record = json.loads((tmp_path / "run.json").read_text())
        assert record["status"] == "completed"
        assert record["scan_results"]["scan_completed"] is True
        assert record["end_time"] is not None
        posthog_end.assert_called_once_with(state, exit_reason="finished_by_tool")
        scarf_end.assert_called_once_with(state, exit_reason="finished_by_tool")
    else:
        state.save_run_data(status=after_rejection)
        record = json.loads((tmp_path / "run.json").read_text())
        assert record["status"] == after_rejection
        assert record["scan_results"]["scan_completed"] is False
        posthog_end.assert_not_called()
        scarf_end.assert_not_called()


async def test_wait_for_user_delivers_sessionless_messages_in_tool_result() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root", parent_id=None)
    await coordinator.send("root", {"from": "user", "content": "Recheck the result"})
    result = await _call(
        wait_for_user,
        {"coordinator": coordinator, "agent_id": "root", "interactive": True},
        {},
    )
    assert result["wait_outcome"] == "message_arrived"
    assert result["messages"] == [{"role": "user", "content": "Recheck the result"}]
    assert not await coordinator.has_pending("root")
    assert coordinator.statuses["root"] == "running"


@pytest.mark.parametrize("with_session", [False, True])
@pytest.mark.parametrize("start_parked", [False, True])
async def test_interactive_wake_delivers_messages_once_and_waits_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_session: bool, start_parked: bool
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root", parent_id=None)
    session = SQLiteSession("root", tmp_path / "agents.db") if with_session else None
    history = [{"role": "user", "content": "Original task"}]
    calls: list[Any] = []
    woke = asyncio.Event()
    waiting_again = asyncio.Event()
    waits = 0
    original_wait = coordinator.wait_for_message

    async def wait(*args: Any, **kwargs: Any) -> bool:
        nonlocal waits
        waits += 1
        if waits == 2:
            waiting_again.set()
        assert waits <= 2, "An acknowledged message must not wake the agent again"
        return await original_wait(*args, **kwargs)

    async def cycle(*_args: Any, **kwargs: Any) -> Any:
        items = await session.get_items() if session is not None else kwargs["initial_input"]
        calls.append(items)
        is_wake = start_parked or len(calls) > 1
        if is_wake:
            rendered = json.dumps(items)
            assert rendered.count("New instruction") == 1
            assert rendered.count("Original task") == 1
            assert not await coordinator.has_pending("root")
            woke.set()
        await coordinator.park_waiting("root", wait_kind="user")
        return SimpleNamespace(to_input_list=lambda: history)

    monkeypatch.setattr(execution, "_run_until_lifecycle", cycle)
    monkeypatch.setattr(coordinator, "wait_for_message", wait)
    await coordinator.send("root", {"from": "user", "content": "New instruction"})
    # A restored session already holds its opening task when starting parked.
    if start_parked and session is not None:
        await session.add_items(history)
    task = asyncio.create_task(
        execution.run_agent_loop(
            agent=SimpleNamespace(name="Root"),
            initial_input=history,
            run_config=RunConfig(tracing_disabled=True),
            context={"agent_id": "root"},
            max_turns=4,
            coordinator=coordinator,
            agent_id="root",
            interactive=True,
            session=session,
            start_parked=start_parked,
        )
    )
    try:
        done, _ = await asyncio.wait(
            [task, waiter := asyncio.create_task(waiting_again.wait())],
            timeout=5,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if task in done:
            await task
        assert waiting_again.is_set() and woke.is_set()
        assert not task.done()
        assert len(calls) == (1 if start_parked else 2)
    finally:
        task.cancel()
        waiter.cancel()
        await asyncio.gather(task, waiter, return_exceptions=True)
        if session is not None:
            session.close()
