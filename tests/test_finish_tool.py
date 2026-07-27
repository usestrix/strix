"""Tests for root scan completion and the opt-in completion nudge."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from agents.run_context import RunContextWrapper
from agents.tool import FunctionToolResult
from agents.tool_context import ToolContext

from strix.agents.factory import _finish_tool_use_behavior
from strix.core.agents import AgentCoordinator
from strix.report.state import ReportState, set_global_report_state
from strix.tools.finish.tool import finish_scan


if TYPE_CHECKING:
    from pathlib import Path


DRAFT = {
    "executive_summary": "Draft executive summary",
    "methodology": "Draft methodology",
    "technical_analysis": "Draft-only technical analysis",
    "recommendations": "Draft recommendations",
}
REVISED = {
    "executive_summary": "Revised executive summary",
    "methodology": "Revised methodology",
    "technical_analysis": "Revised technical analysis",
    "recommendations": "Revised recommendations",
}


def _tool_context(context: dict[str, Any], payload: dict[str, str]) -> ToolContext[dict[str, Any]]:
    arguments = json.dumps(payload)
    return ToolContext(
        context,
        tool_name="finish_scan",
        tool_call_id="finish-call",
        tool_arguments=arguments,
    )


async def _invoke(context: dict[str, Any], payload: dict[str, str]) -> dict[str, Any]:
    result = await finish_scan.on_invoke_tool(
        _tool_context(context, payload),
        json.dumps(payload),
    )
    return json.loads(result)


def _report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.setattr("strix.report.state.run_dir_for", lambda _run_name: tmp_path)
    state = ReportState("finish-test")
    set_global_report_state(state)
    return state


@pytest.mark.asyncio
async def test_flag_disabled_completes_first_valid_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _report_state(tmp_path, monkeypatch)
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    context = {
        "coordinator": coordinator,
        "agent_id": "root",
        "parent_id": None,
        "completion_nudge": False,
    }

    result = await _invoke(context, DRAFT)

    assert result["scan_completed"] is True
    assert state.scan_results == {**DRAFT, "success": True, "scan_completed": True}
    assert coordinator.statuses["root"] == "completed"


@pytest.mark.asyncio
async def test_enabled_nudge_then_persists_only_revised_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _report_state(tmp_path, monkeypatch)
    callback_count = 0

    def on_nudge() -> None:
        nonlocal callback_count
        callback_count += 1

    state.completion_nudge_callback = on_nudge
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    context = {
        "coordinator": coordinator,
        "agent_id": "root",
        "parent_id": None,
        "completion_nudge": True,
    }

    first = await _invoke(context, DRAFT)

    assert first["success"] is True
    assert first["scan_completed"] is False
    assert first["completion_nudge"] is True
    assert "identify concrete leads" in first["message"]
    assert callback_count == 1
    assert state.scan_results is None
    assert coordinator.statuses["root"] == "running"
    assert not (tmp_path / "penetration_test_report.md").exists()

    second = await _invoke(context, REVISED)

    assert second["scan_completed"] is True
    assert callback_count == 1
    assert state.scan_results == {**REVISED, "success": True, "scan_completed": True}
    assert coordinator.statuses["root"] == "completed"
    report = (tmp_path / "penetration_test_report.md").read_text(encoding="utf-8")
    assert "Revised technical analysis" in report
    assert "Draft-only technical analysis" not in report


@pytest.mark.asyncio
async def test_invalid_first_report_does_not_consume_nudge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _report_state(tmp_path, monkeypatch)
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    context = {
        "coordinator": coordinator,
        "agent_id": "root",
        "parent_id": None,
        "completion_nudge": True,
    }

    invalid = await _invoke(context, {**DRAFT, "executive_summary": ""})
    assert "completion_nudge_started" not in coordinator.metadata["root"]
    valid = await _invoke(context, DRAFT)

    assert invalid == {
        "success": False,
        "error": "Validation failed",
        "errors": ["Executive summary cannot be empty"],
    }
    assert valid["completion_nudge"] is True


@pytest.mark.asyncio
async def test_active_child_does_not_consume_nudge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _report_state(tmp_path, monkeypatch)
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    context = {
        "coordinator": coordinator,
        "agent_id": "root",
        "parent_id": None,
        "completion_nudge": True,
    }

    blocked = await _invoke(context, DRAFT)
    await coordinator.set_status("child", "completed")
    valid = await _invoke(context, DRAFT)

    assert blocked["success"] is False
    assert blocked["scan_completed"] is False
    assert "child agents are still active" in blocked["error"]
    assert valid["completion_nudge"] is True


@pytest.mark.asyncio
async def test_context_fallback_nudges_once_then_completes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _report_state(tmp_path, monkeypatch)
    context = {"parent_id": None, "completion_nudge": True}

    first = await _invoke(context, DRAFT)
    second = await _invoke(context, REVISED)

    assert first["completion_nudge"] is True
    assert context["completion_nudge_started"] is True
    assert second["scan_completed"] is True
    assert state.scan_results == {**REVISED, "success": True, "scan_completed": True}


def test_completion_nudge_is_nonterminal_but_completion_is_terminal() -> None:
    context = RunContextWrapper({"interactive": False})
    nudge = FunctionToolResult(
        tool=finish_scan,
        output=json.dumps(
            {
                "success": True,
                "scan_completed": False,
                "completion_nudge": True,
            }
        ),
        run_item=None,
    )
    completed = FunctionToolResult(
        tool=finish_scan,
        output=json.dumps({"success": True, "scan_completed": True}),
        run_item=None,
    )

    nudge_result = _finish_tool_use_behavior(context, [nudge])
    completed_result = _finish_tool_use_behavior(context, [completed])

    assert nudge_result.is_final_output is False
    assert completed_result.is_final_output is True
