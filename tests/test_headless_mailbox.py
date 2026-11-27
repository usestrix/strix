"""Offline SDK regressions for headless agents with pending inbox messages."""

from __future__ import annotations

import asyncio
import copy
import json
from typing import TYPE_CHECKING, Any

import pytest
from agents import Agent, RunConfig, function_tool
from agents.exceptions import MaxTurnsExceeded
from agents.memory import SQLiteSession
from agents.models.interface import Model
from agents.run_config import CallModelData, ModelInputData
from agents.tool_context import ToolContext
from openai.types.responses import Response, ResponseCompletedEvent, ResponseFunctionToolCall

from strix.agents.factory import _finish_tool_use_behavior
from strix.core import execution
from strix.core.agents import AgentCoordinator
from strix.core.execution import run_agent_loop
from strix.tools.agents_graph.tools import agent_finish
from strix.tools.finish import tool as finish_module
from strix.tools.finish.tool import finish_scan


if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path


# Synthetic instructions sent at successive model/finish boundaries.
# No provider, target application, or historical run data is needed.
_MESSAGES = [
    {"id": "msg_hold", "from": "root", "content": "HOLD filing; reassess first."},
    {"id": "msg_reassess", "from": "root", "content": "Review the counterevidence."},
    {"id": "msg_quality", "from": "root", "content": "Apply the reporting quality gate."},
    {"id": "msg_decision", "from": "root", "content": "Final decision: do not file."},
]


async def _graph() -> AgentCoordinator:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root", parent_id=None)
    await coordinator.register("child", "Reporter", parent_id="root")
    await coordinator.attach_runtime("root", resumable=False)
    await coordinator.attach_runtime("child", resumable=False)
    return coordinator


class _MailboxModel(Model):
    def __init__(self, coordinator: AgentCoordinator) -> None:
        self.coordinator = coordinator
        self.inputs: list[list[Any]] = []

    async def get_response(self, *_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("Expected the streaming SDK path")

    async def stream_response(self, *_args: Any, **_kwargs: Any) -> AsyncIterator[Any]:
        self.inputs.append(copy.deepcopy(_args[1]))
        turn = len(self.inputs)
        assert turn <= 4, "Mailbox handling must not loop or replay completed turns"
        # Send after the request started. The next request must see the messages;
        # finishing from this in-flight request must not strand them.
        arrivals = _MESSAGES[:2] if turn == 1 else _MESSAGES[turn : turn + 1]
        for message in arrivals:
            assert await self.coordinator.send("child", message)
        name = "work" if turn == 1 else "agent_finish"
        arguments = {} if turn == 1 else {"result_summary": "done"}
        response = Response(
            id=f"response-{turn}",
            created_at=0,
            model="offline-mailbox-model",
            object="response",
            parallel_tool_calls=False,
            tool_choice="auto",
            tools=[],
            output=[
                ResponseFunctionToolCall(
                    id=f"fc-{turn}",
                    call_id=f"call-{turn}",
                    type="function_call",
                    name=name,
                    arguments=json.dumps(arguments),
                    status="completed",
                )
            ],
        )
        yield ResponseCompletedEvent(
            response=response, sequence_number=1, type="response.completed"
        )


@pytest.mark.parametrize("with_session", [True, False])
async def test_headless_messages_reach_next_request_and_block_stale_finish(
    tmp_path: Path,
    with_session: bool,
) -> None:
    coordinator = await _graph()
    model = _MailboxModel(coordinator)
    work_calls: list[str] = []

    @function_tool
    async def work() -> str:
        work_calls.append("work")
        return "work completed"

    agent = Agent(
        name="Reporter",
        model=model,
        tools=[work, agent_finish],
        tool_use_behavior=_finish_tool_use_behavior,
    )
    session = SQLiteSession("child", tmp_path / "agents.db") if with_session else None
    try:
        await run_agent_loop(
            agent=agent,
            initial_input="Review the evidence.",
            run_config=RunConfig(tracing_disabled=True),
            context={"coordinator": coordinator, "agent_id": "child", "parent_id": "root"},
            max_turns=4,
            coordinator=coordinator,
            agent_id="child",
            interactive=False,
            session=session,
        )
        assert len(model.inputs) == 4
        assert work_calls == ["work"]
        for index, items in enumerate(model.inputs[1:], start=2):
            text = json.dumps(items)
            for message in _MESSAGES[:index]:
                assert text.count(message["content"]) == 1
        assert coordinator.statuses["child"] == "completed"
        assert coordinator.pending_counts["child"] == 0
        assert coordinator.runtimes["child"].mailbox == []
        assert len(coordinator.runtimes["root"].mailbox) == 1
        if session is not None:
            persisted = json.dumps(await session.get_items())
            for message in _MESSAGES:
                assert persisted.count(message["content"]) == 1
    finally:
        if session is not None:
            session.close()


async def test_message_checkpoints_do_not_reset_sdk_turn_limit(tmp_path: Path) -> None:
    coordinator = await _graph()
    model = _MailboxModel(coordinator)

    @function_tool
    async def work() -> str:
        return "done"

    session = SQLiteSession("child", tmp_path / "agents.db")
    try:
        with pytest.raises(MaxTurnsExceeded):
            await run_agent_loop(
                agent=Agent(
                    name="Reporter",
                    model=model,
                    tools=[work, agent_finish],
                    tool_use_behavior=_finish_tool_use_behavior,
                ),
                initial_input="Review the evidence.",
                run_config=RunConfig(tracing_disabled=True),
                context={"coordinator": coordinator, "agent_id": "child", "parent_id": "root"},
                max_turns=2,
                coordinator=coordinator,
                agent_id="child",
                interactive=False,
                session=session,
            )
        assert len(model.inputs) == 2
        assert coordinator.statuses["child"] == "stopped"
    finally:
        session.close()


async def test_finish_does_not_notify_parent_with_unread_messages() -> None:
    coordinator = await _graph()
    await coordinator.send("child", _MESSAGES[0])
    ctx = ToolContext(
        context={"coordinator": coordinator, "agent_id": "child", "parent_id": "root"},
        tool_name="agent_finish",
        tool_call_id="finish",
        tool_arguments="{}",
    )
    result = json.loads(await agent_finish.on_invoke_tool(ctx, '{"result_summary":"done"}'))
    assert result["success"] is False
    assert result["agent_completed"] is False
    assert coordinator.statuses["child"] == "running"
    assert coordinator.runtimes["root"].mailbox == []


async def test_failed_mailbox_write_retains_messages_for_retry(tmp_path: Path) -> None:
    coordinator = await _graph()
    session = SQLiteSession("child", tmp_path / "agents.db")
    await coordinator.attach_runtime("child", session=session)
    original_add = session.add_items

    async def fail(_items: Any) -> None:
        raise OSError("injected session write failure")

    try:
        await coordinator.send("child", _MESSAGES[0])
        session.add_items = fail  # type: ignore[method-assign]
        assert await coordinator.consume_pending("child", include_items=True) == (0, [])
        assert coordinator.pending_counts["child"] == 1
        assert coordinator.runtimes["child"].mailbox == [_MESSAGES[0]]
        session.add_items = original_add  # type: ignore[method-assign]
        count, items = await coordinator.consume_pending("child", include_items=True)
        assert count == 1
        assert items == await session.get_items()
    finally:
        session.close()


@pytest.mark.parametrize("send_first", [True, False])
async def test_send_and_completion_are_serialized(send_first: bool) -> None:
    coordinator = await _graph()
    async with coordinator._lock:
        operations = [
            lambda: coordinator.send("child", _MESSAGES[0]),
            lambda: coordinator.complete_if_no_pending("child"),
        ]
        if not send_first:
            operations.reverse()
        tasks = [asyncio.create_task(operation()) for operation in operations]
        await asyncio.sleep(0)
    results = await asyncio.gather(*tasks)
    if not send_first:
        results.reverse()
    accepted, (completed, _) = results
    assert accepted is send_first
    assert completed is not send_first
    assert not (accepted and coordinator.statuses["child"] == "completed")


async def test_completion_report_is_queued_before_parent_sees_terminal_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator = await _graph()
    observed: list[bool] = []

    async def snapshot() -> None:
        if coordinator.statuses["child"] == "completed":
            observed.append(await coordinator.has_pending("root"))

    monkeypatch.setattr(coordinator, "_maybe_snapshot", snapshot)
    completed, notified = await coordinator.complete_if_no_pending(
        "child", parent_message={"from": "child", "content": "done"}
    )
    assert completed and notified
    assert observed == [True]
    assert await coordinator.complete_if_no_pending("root") == (False, False)


async def test_concurrent_drains_preserve_arrivals_during_write(tmp_path: Path) -> None:
    coordinator = await _graph()
    session = SQLiteSession("child", tmp_path / "agents.db")
    await coordinator.attach_runtime("child", session=session)
    original_add = session.add_items
    entered, release = asyncio.Event(), asyncio.Event()

    async def delayed(items: Any) -> None:
        entered.set()
        await release.wait()
        await original_add(items)

    session.add_items = delayed  # type: ignore[method-assign]
    try:
        await coordinator.send("child", _MESSAGES[0])
        first = asyncio.create_task(coordinator.consume_pending("child", include_items=True))
        await asyncio.wait_for(entered.wait(), 5)
        await coordinator.send("child", _MESSAGES[1])
        second = asyncio.create_task(coordinator.consume_pending("child", include_items=True))
        assert await coordinator.complete_if_no_pending("child") == (False, False)
        release.set()
        batches = await asyncio.gather(first, second)
        assert [count for count, _ in batches] == [1, 1]
        persisted = await session.get_items()
        assert len(persisted) == 2
        assert _MESSAGES[0]["content"] in str(persisted[0])
        assert _MESSAGES[1]["content"] in str(persisted[1])
    finally:
        release.set()
        session.close()


@pytest.mark.parametrize("during_persistence", [False, True])
async def test_root_cannot_finish_with_unread_messages(
    monkeypatch: pytest.MonkeyPatch,
    during_persistence: bool,
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root", parent_id=None)
    await coordinator.attach_runtime("root", resumable=False)
    persisted: list[bool] = []

    async def persist(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        persisted.append(True)
        await coordinator.send("root", {"from": "reviewer", "content": "Check the conclusion"})
        return {"success": True, "scan_completed": True}

    monkeypatch.setattr(finish_module.asyncio, "to_thread", persist)
    if not during_persistence:
        await coordinator.send("root", {"from": "reviewer", "content": "Check the conclusion"})
    ctx = ToolContext(
        context={"coordinator": coordinator, "agent_id": "root", "parent_id": None},
        tool_name="finish_scan",
        tool_call_id="finish",
        tool_arguments="{}",
    )
    result = json.loads(
        await finish_scan.on_invoke_tool(
            ctx,
            json.dumps(
                dict.fromkeys(
                    ("executive_summary", "methodology", "technical_analysis", "recommendations"),
                    "Reviewed",
                )
            ),
        )
    )
    assert result["success"] is False
    assert result["scan_completed"] is False
    assert coordinator.statuses["root"] == "running"
    assert bool(persisted) is during_persistence


async def test_checkpoint_preserves_an_existing_model_input_filter() -> None:
    coordinator = await _graph()
    calls: list[bool] = []

    async def original(data: Any) -> Any:
        calls.append(True)
        return data.model_data

    config = RunConfig(call_model_input_filter=original)
    wrapped = execution._with_mailbox_checkpoint(config, coordinator, "child")
    data = CallModelData(
        model_data=ModelInputData(input=[{"role": "user", "content": "task"}], instructions=None),
        agent=Agent(name="Reporter"),
        context={},
    )
    assert wrapped.call_model_input_filter is not None
    result = await wrapped.call_model_input_filter(data)
    assert result == data.model_data
    assert calls == [True]
    assert config.call_model_input_filter is original
