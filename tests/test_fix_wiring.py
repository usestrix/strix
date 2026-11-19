"""Tests for the hooks that connect the fix controller to a scan."""

from __future__ import annotations

import importlib
import json
import sys
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents.tool_context import ToolContext

from strix.agents.factory import build_fix_agent
from strix.core.agents import AgentCoordinator
from strix.core.execution import respawn_subagents
from strix.report.state import ReportState, set_global_report_state
from strix.tools.agents_graph.tools import agent_finish
from strix.tools.finish.tool import finish_scan
from strix.tools.reporting.tool import _schedule_fix


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture
def state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ReportState]:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="test-run")
    set_global_report_state(state)
    yield state
    set_global_report_state(None)


class _Controller:
    def __init__(self) -> None:
        self.scheduled: list[dict[str, Any]] = []

    def schedule(self, report: dict[str, Any]) -> bool:
        self.scheduled.append(report)
        return True

    def pending(self) -> list[str]:
        return [str(report["id"]) for report in self.scheduled]


def _ctx(**context: Any) -> ToolContext[Any]:
    return ToolContext(context=context, tool_name="t", tool_call_id="call-1", tool_arguments="{}")


def test_stored_finding_is_handed_to_the_fix_controller(state: ReportState) -> None:
    report = {"id": "vuln-0001", "title": "IDOR"}
    state.vulnerability_reports.append(report)
    fix_controller = _Controller()
    ctx = _ctx(fix_controller=fix_controller)

    _schedule_fix(ctx, {"success": True, "report_id": "vuln-0001"})
    _schedule_fix(ctx, {"success": False, "report_id": "vuln-0001"})
    _schedule_fix(ctx, {"success": True, "report_id": "vuln-9999"})

    assert fix_controller.scheduled == [report]


def test_scan_without_a_fix_controller_schedules_nothing(state: ReportState) -> None:
    state.vulnerability_reports.append({"id": "vuln-0001"})
    _schedule_fix(_ctx(), {"success": True, "report_id": "vuln-0001"})


async def test_fix_agent_verdict_goes_to_the_controller_not_the_root_agent() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("fixer", "Fix reviewer", parent_id="root")
    ctx = ToolContext(
        context={
            "coordinator": coordinator,
            "agent_id": "fixer",
            "parent_id": "root",
            "fix_agent": True,
        },
        tool_name=agent_finish.name,
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    raw: str = await agent_finish.on_invoke_tool(
        ctx,
        json.dumps(
            {
                "result_summary": "The export route is still open.",
                "open_items": ["GET /orders/export"],
                "success": False,
            }
        ),
    )
    result = cast("dict[str, Any]", json.loads(raw))

    assert result["agent_completed"] is True
    assert result["task_succeeded"] is False
    assert result["summary"] == "The export route is still open."
    assert result["open_items"] == ["GET /orders/export"]
    assert list(coordinator.runtimes["root"].mailbox) == []


async def test_resume_does_not_restart_fix_agents_as_scan_agents(tmp_path: Path) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("fixer", "Fix agent", parent_id="root")
    coordinator.metadata["fixer"]["fix_agent"] = True

    def factory(**_: Any) -> Any:
        raise AssertionError("a fix agent was respawned")

    await respawn_subagents(
        coordinator=coordinator,
        factory=factory,
        agents_db_path=tmp_path / "agents.db",
        sessions_to_close=[],
        run_config=cast("Any", None),
        max_turns=10,
        interactive=False,
        parent_ctx={},
        root_id="root",
    )

    assert coordinator.statuses["fixer"] == "stopped"


def test_fix_agent_cannot_file_findings_or_start_agents() -> None:
    agent = build_fix_agent(name="Fix agent", instructions="Fix it.")

    names = {tool.name for tool in agent.tools}
    assert "agent_finish" in names
    assert not names & {
        "create_vulnerability_report",
        "update_vulnerability_report",
        "delete_vulnerability_report",
        "create_agent",
        "finish_scan",
    }
    assert agent.instructions == "Fix it."


def test_no_auto_fix_flag_turns_fixing_off(monkeypatch: pytest.MonkeyPatch) -> None:
    cli_main = importlib.import_module("strix.interface.main")
    monkeypatch.setattr(
        cli_main,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(max_local_copy_mb=1024)),
    )

    monkeypatch.setattr(sys, "argv", ["strix", "-t", "https://test.com/", "-n"])
    assert cli_main.parse_arguments().auto_fix is True

    monkeypatch.setattr(sys, "argv", ["strix", "-t", "https://test.com/", "-n", "--no-auto-fix"])
    assert cli_main.parse_arguments().auto_fix is False


async def test_scan_cannot_finish_between_the_fix_agent_and_its_reviewer() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    fix_controller = _Controller()
    fix_controller.scheduled.append({"id": "vuln-0001"})
    ctx = ToolContext(
        context={"coordinator": coordinator, "agent_id": "root", "fix_controller": fix_controller},
        tool_name=finish_scan.name,
        tool_call_id="call-1",
        tool_arguments="{}",
    )

    raw: str = await finish_scan.on_invoke_tool(
        ctx,
        json.dumps(
            {
                "executive_summary": "s",
                "methodology": "m",
                "technical_analysis": "t",
                "recommendations": "r",
            }
        ),
    )
    result = cast("dict[str, Any]", json.loads(raw))

    assert result["scan_completed"] is False
    assert result["findings_being_fixed"] == ["vuln-0001"]
