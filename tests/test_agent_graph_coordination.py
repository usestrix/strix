"""Tests for parent/child coordination once a non-interactive child has finished.

A non-interactive agent's loop returns after its terminal state, so nothing will
ever read a message sent to it afterwards. Messaging it must say so instead of
reporting delivery, waiting on it must return at once, and its completion report
must carry the ids of the reports it actually filed so the parent does not have
to go asking.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents.tool_context import ToolContext

from strix.core.agents import AgentCoordinator
from strix.report.state import ReportState, set_global_report_state
from strix.tools.agents_graph.tools import agent_finish, send_message_to_agent, wait_for_agents


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ReportState]:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="test-run")
    set_global_report_state(state)
    yield state
    set_global_report_state(None)


async def _graph(*, interactive: bool) -> AgentCoordinator:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "Validator", parent_id="root")
    await coordinator.attach_runtime("root", resumable=interactive)
    await coordinator.attach_runtime("child", resumable=interactive)
    return coordinator


async def _call(
    tool: Any, coordinator: AgentCoordinator, agent_id: str, args: dict[str, Any], **extra: Any
) -> dict[str, Any]:
    ctx = ToolContext(
        context={"coordinator": coordinator, "agent_id": agent_id, **extra},
        tool_name=tool.name,
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    raw: str = await tool.on_invoke_tool(ctx, json.dumps(args))
    return cast("dict[str, Any]", json.loads(raw))


# --- send_message_to_agent -------------------------------------------------------


@pytest.mark.asyncio
async def test_message_to_finished_non_interactive_child_is_not_delivered() -> None:
    coordinator = await _graph(interactive=False)
    await coordinator.set_status("child", "completed")

    result = await _call(
        send_message_to_agent,
        coordinator,
        "root",
        {"target_agent_id": "child", "message": "did you file it?", "message_type": "query"},
    )

    assert result["success"] is False
    assert result["delivery_status"] == "not_delivered"
    assert result["target_status"] == "completed"
    assert "list_reports" in result["error"]
    assert coordinator.pending_counts.get("child", 0) == 0
    assert coordinator.runtimes["child"].mailbox == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["stopped", "failed", "crashed"])
async def test_every_terminal_non_interactive_status_is_unreachable(status: str) -> None:
    coordinator = await _graph(interactive=False)
    await coordinator.set_status("child", status)

    assert await coordinator.send("child", {"from": "root", "content": "hi"}) is False
    assert await coordinator.reachability("child") == (False, status)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["running", "waiting"])
async def test_message_to_live_child_is_delivered(status: str) -> None:
    coordinator = await _graph(interactive=False)
    await coordinator.set_status("child", status)

    result = await _call(
        send_message_to_agent,
        coordinator,
        "root",
        {"target_agent_id": "child", "message": "wrap up"},
    )

    assert result["success"] is True
    assert result["delivery_status"] == "delivered"
    assert coordinator.pending_counts["child"] == 1


@pytest.mark.asyncio
async def test_message_to_finished_interactive_child_still_wakes_it() -> None:
    # An interactive loop parks after finishing and resumes on a message.
    coordinator = await _graph(interactive=True)
    await coordinator.set_status("child", "completed")

    result = await _call(
        send_message_to_agent,
        coordinator,
        "root",
        {"target_agent_id": "child", "message": "one more thing"},
    )

    assert result["success"] is True
    assert coordinator.pending_counts["child"] == 1


@pytest.mark.asyncio
async def test_unknown_target_is_reported_as_not_found() -> None:
    coordinator = await _graph(interactive=False)

    result = await _call(
        send_message_to_agent,
        coordinator,
        "root",
        {"target_agent_id": "ghost", "message": "hello"},
    )

    assert result["success"] is False
    assert result["target_status"] is None
    assert "not found" in result["error"]


# --- wait_for_agents -------------------------------------------------------------


@pytest.mark.asyncio
async def test_wait_returns_at_once_when_no_child_can_answer() -> None:
    coordinator = await _graph(interactive=False)
    await coordinator.set_status("child", "completed")
    # The completion report was already consumed in an earlier turn.

    result = await _call(
        wait_for_agents,
        coordinator,
        "root",
        {"reason": "waiting for validator", "timeout_seconds": 240},
    )

    assert result["wait_outcome"] == "no_active_agents"
    assert result["agents"] == [{"agent_id": "child", "name": "Validator", "status": "completed"}]
    assert coordinator.statuses["root"] == "running"


@pytest.mark.asyncio
async def test_wait_delivers_a_pending_report_before_checking_liveness() -> None:
    coordinator = await _graph(interactive=False)
    await coordinator.send("root", {"from": "child", "type": "completion", "content": "done"})
    await coordinator.set_status("child", "completed")

    result = await _call(wait_for_agents, coordinator, "root", {"timeout_seconds": 5})

    assert result["wait_outcome"] == "message_arrived"
    assert result["pending_messages"] == 1


@pytest.mark.asyncio
async def test_wait_still_parks_while_a_child_is_running() -> None:
    coordinator = await _graph(interactive=False)

    result = await _call(wait_for_agents, coordinator, "root", {"timeout_seconds": 1})

    assert result["wait_outcome"] == "timeout"


@pytest.mark.asyncio
async def test_interactive_wait_parks_even_without_active_children() -> None:
    # In an interactive run a finished child can be woken later, so parking is
    # legitimate; the run loop's own auto-resume bounds the wait.
    coordinator = await _graph(interactive=True)
    await coordinator.set_status("child", "completed")

    result = await _call(
        wait_for_agents, coordinator, "root", {"timeout_seconds": 5}, interactive=True
    )

    assert result["wait_outcome"] == "waiting"


# --- agent_finish ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_finish_lists_the_reports_the_child_filed(report_state: ReportState) -> None:
    coordinator = await _graph(interactive=False)
    mine = report_state.add_vulnerability_report(
        title="IDOR on /api/audits", severity="high", agent_id="child", agent_name="Validator"
    )
    report_state.add_vulnerability_report(title="Root's own", severity="low", agent_id="root")

    result = await _call(
        agent_finish,
        coordinator,
        "child",
        {"result_summary": "confirmed", "findings": ["IDOR confirmed"]},
        parent_id="root",
    )

    assert result["filed_report_ids"] == [mine]
    delivered = coordinator.runtimes["root"].mailbox
    assert len(delivered) == 1
    assert delivered[0]["filed_report_ids"] == [mine]
    body = delivered[0]["content"]
    assert f"- {mine} [HIGH] IDOR on /api/audits" in body
    assert "Root's own" not in body


@pytest.mark.asyncio
async def test_agent_finish_states_explicitly_when_nothing_was_filed(
    report_state: ReportState,
) -> None:
    coordinator = await _graph(interactive=False)
    report_state.add_vulnerability_report(title="Someone else's", severity="low", agent_id="root")

    result = await _call(
        agent_finish,
        coordinator,
        "child",
        {"result_summary": "nothing exploitable", "findings": ["ruled out X"]},
        parent_id="root",
    )

    assert result["filed_report_ids"] == []
    body = coordinator.runtimes["root"].mailbox[0]["content"]
    assert "Vulnerability reports filed by this agent" in body
    assert body.index("filed by this agent") < body.index("- (none)")


@pytest.mark.asyncio
async def test_agent_finish_without_report_state_still_completes() -> None:
    set_global_report_state(None)
    coordinator = await _graph(interactive=False)

    result = await _call(
        agent_finish, coordinator, "child", {"result_summary": "done"}, parent_id="root"
    )

    assert result["success"] is True
    assert result["filed_report_ids"] == []
