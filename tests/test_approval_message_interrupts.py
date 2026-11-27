"""Message interruptions preserve pending approval results and queued reports."""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from agents import Agent, RunConfig
from agents.memory import SQLiteSession
from agents.models.interface import Model
from agents.tool import FunctionTool
from agents.tool_context import ToolContext
from openai.types.responses import (
    Response,
    ResponseCompletedEvent,
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from strix.config.settings import ActionApprovalSettings
from strix.core import execution
from strix.core.action_approvals import ActionApprovalGuard, guard_function_tool
from strix.core.agents import AgentCoordinator
from strix.tools.agents_graph.tools import agent_finish, wait_for_agents


if TYPE_CHECKING:
    from collections.abc import AsyncIterator


async def _complete_child(coordinator: AgentCoordinator) -> None:
    ctx = ToolContext(
        context={"coordinator": coordinator, "agent_id": "child", "parent_id": "root"},
        tool_name="agent_finish",
        tool_call_id="complete",
        tool_arguments="{}",
    )
    await agent_finish.on_invoke_tool(
        ctx, json.dumps({"result_summary": "done", "report_to_parent": True})
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "pending_agent,interrupt,interactive,expected",
    [
        (None, True, True, "immediate"),
        ("child", True, True, "immediate"),
        ("root", True, True, "after_turn"),
        ("root", False, True, None),
        ("root", True, False, None),
    ],
)
async def test_send_interrupts_only_defer_for_the_targets_pending_approval(
    pending_agent: str | None, interrupt: bool, interactive: bool, expected: str | None
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Parent", parent_id=None)
    guard = MagicMock(spec=ActionApprovalGuard)
    guard.pending.return_value = [] if pending_agent is None else [{"agent_id": pending_agent}]
    coordinator.action_approvals = guard
    stream = MagicMock()
    await coordinator.attach_runtime("root", interrupt_on_message=interactive)
    await coordinator.attach_stream("root", stream)

    assert await coordinator.send(
        "root", {"from": "child", "type": "completion", "content": "done"}, interrupt=interrupt
    )

    if expected is None:
        stream.cancel.assert_not_called()
    else:
        stream.cancel.assert_called_once_with(mode=expected)
    assert coordinator.pending_counts["root"] == 1
    assert coordinator.statuses["root"] == "running"


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", ["timed_out", "approved", "denied"])
async def test_child_completion_preserves_pending_approval_result_and_processes_message(  # noqa: PLR0915
    tmp_path: Any, decision: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Parent", parent_id=None)
    await coordinator.register("child", "Observer", parent_id="root")
    events: list[dict[str, Any]] = []
    guard = ActionApprovalGuard(
        ActionApprovalSettings.model_validate(
            {"enabled": True, "mode": "ask", "timeout_seconds": 0.2}
        ),
        event_sink=events.append,
    )
    monkeypatch.setattr(
        guard, "_evaluate", AsyncMock(return_value=(0.9, "deletes_data", "Deletes a fixture row"))
    )
    coordinator.action_approvals = guard
    execute = AsyncMock(return_value="Executed fixture action")
    tool = guard_function_tool(
        FunctionTool(
            name="exec_command",
            description="Fixture action",
            params_json_schema={"type": "object", "properties": {}, "additionalProperties": False},
            on_invoke_tool=execute,
        )
    )
    outputs: list[ResponseFunctionToolCall | ResponseOutputMessage] = [
        ResponseFunctionToolCall(
            type="function_call", name="exec_command", call_id="action", arguments="{}"
        ),
        ResponseFunctionToolCall(
            type="function_call", name="wait_for_agents", call_id="wait", arguments="{}"
        ),
        ResponseOutputMessage(
            id="message",
            type="message",
            role="assistant",
            status="completed",
            content=[
                ResponseOutputText(type="output_text", text="Continuing work", annotations=[])
            ],
        ),
    ]
    model_inputs: list[Any] = []

    async def stream_response(*args: Any, **_kwargs: Any) -> AsyncIterator[ResponseCompletedEvent]:
        model_inputs.append(args[1])
        response = Response(
            id=f"response-{len(model_inputs)}",
            created_at=0,
            model="fixture",
            object="response",
            output=[outputs.pop(0)],
            parallel_tool_calls=False,
            tool_choice="auto",
            tools=[],
        )
        yield ResponseCompletedEvent(
            type="response.completed", response=response, sequence_number=1
        )

    model = MagicMock(spec=Model)
    model.stream_response = stream_response
    agent = Agent(name="Parent", model=model, tools=[tool, wait_for_agents])
    session = SQLiteSession("root", tmp_path / "agents.db")
    await coordinator.attach_runtime("root", session=session, interrupt_on_message=True)

    async def run_cycle(input_data: Any) -> Any:
        return await execution._run_cycle(
            agent,
            coordinator,
            "root",
            input_data=input_data,
            run_config=RunConfig(tracing_disabled=True),
            context={"coordinator": coordinator, "agent_id": "root", "interactive": True},
            max_turns=5,
            session=session,
            interactive=True,
            event_sink=None,
            hooks=None,
        )

    task = asyncio.create_task(
        run_cycle("Perform the fixture action, then read the observer report")
    )
    try:
        async with asyncio.timeout(5):
            while not guard.pending():
                await asyncio.sleep(0)
        approval_id = guard.pending()[0]["approval_id"]
        await _complete_child(coordinator)
        assert not task.done()
        assert guard.pending()[0]["approval_id"] == approval_id
        assert coordinator.statuses["root"] == "running"
        if decision != "timed_out":
            assert guard.resolve(approval_id, approved=decision == "approved")
        await asyncio.wait_for(task, timeout=5)

        assert [e["decision"] for e in events if e["type"] == "resolved"] == [decision]
        assert coordinator.statuses["root"] == "running"
        assert coordinator.pending_counts["root"] == 1
        stored = cast("list[dict[str, Any]]", await session.get_items())
        action_result = next(item for item in stored if item.get("type") == "function_call_output")
        assert action_result["call_id"] == "action"
        if decision == "approved":
            assert action_result["output"] == "Executed fixture action"
            execute.assert_awaited_once()
        else:
            assert ("no answer within" if decision == "timed_out" else "denied by a person") in str(
                action_result["output"]
            )
            assert "agent or scan stopped" not in str(action_result["output"])
            execute.assert_not_awaited()

        await run_cycle([])

        assert coordinator.pending_counts["root"] == 0
        assert coordinator.statuses["root"] == "running"
        stored = cast("list[dict[str, Any]]", await session.get_items())
        report_index = next(
            i
            for i, item in enumerate(stored)
            if item.get("role") == "user" and "Observer" in str(item.get("content"))
        )
        assert stored.index(action_result) < report_index
        assert "Observer" in str(model_inputs[-1])
        assert "message_arrived" in str(model_inputs[-1])
        assert not outputs
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        session.close()
