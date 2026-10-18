"""finish_scan confronts the root agent with the coverage the runtime can see."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from agents.tool_context import ToolContext

from strix.core.agents import AgentCoordinator
from strix.tools.coverage.tools import (
    MAX_FOLLOW_UP_RETRIES,
    _record_impl,
    _update_impl,
    hydrate_coverage_from_disk,
)
from strix.tools.finish.tool import _coverage_summary, finish_scan


if TYPE_CHECKING:
    from pathlib import Path


_GRAPH = {
    "statuses": {"agent-1": "completed"},
    "names": {"agent-1": "injection-tester"},
    "metadata": {"agent-1": {"skills": ["sql_injection", "xss"]}},
}


@pytest.fixture(autouse=True)
def _empty_ledger(tmp_path: Path) -> None:
    hydrate_coverage_from_disk(tmp_path)


def _record(risk_area: str) -> None:
    _record_impl(
        surface="POST /api/orders/{id}",
        risk_area=risk_area,
        outcome="no_issue_found",
        evidence="Parameters fuzzed; no anomalies.",
        agent_id="agent-1",
        agent_name="injection-tester",
    )


def test_unrecorded_risk_class_is_reported_back_to_the_root_agent() -> None:
    _record("SQL injection")

    summary = _coverage_summary(_GRAPH)

    assert summary["coverage_recorded"] == 1
    assert len(summary["coverage_gaps"]) == 1
    assert "xss" in summary["coverage_gaps"][0]
    assert "unexamined" in summary["coverage_gap_warning"]


def test_fully_accounted_coverage_raises_no_gap_warning() -> None:
    _record("SQL injection")
    _record("cross-site scripting")

    summary = _coverage_summary(_GRAPH)

    assert "coverage_gaps" not in summary
    assert "coverage_gap_warning" not in summary


def test_an_empty_ledger_still_warns_first() -> None:
    summary = _coverage_summary(_GRAPH)

    assert summary["coverage_recorded"] == 0
    assert "No coverage was recorded" in summary["coverage_warning"]


async def _finish(coordinator: AgentCoordinator) -> dict[str, Any]:
    ctx = ToolContext(
        context={"coordinator": coordinator, "agent_id": "root", "parent_id": None},
        tool_name="finish_scan",
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    fields = ("executive_summary", "methodology", "technical_analysis", "recommendations")
    result: dict[str, Any] = json.loads(
        await finish_scan.on_invoke_tool(ctx, json.dumps(dict.fromkeys(fields, "x")))
    )
    return result


def _record_follow_up(surface: str) -> None:
    _record_impl(
        surface=surface,
        risk_area="RCE",
        outcome="needs_follow_up",
        evidence="Could not confirm which constructor fields resolve imports.",
        agent_id="agent-1",
        agent_name="injection-tester",
    )


@pytest.mark.asyncio
async def test_open_follow_ups_block_finish_until_each_has_used_its_retries() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    _record_follow_up("load_agent_from_repository")

    for retry in range(1, MAX_FOLLOW_UP_RETRIES + 1):
        blocked = await _finish(coordinator)
        assert blocked["scan_completed"] is False
        assert blocked["follow_ups"][0]["retry"] == retry
        assert blocked["follow_ups"][0]["evidence"]

    finished = await _finish(coordinator)
    assert finished["scan_completed"] is True


@pytest.mark.asyncio
async def test_a_resolved_follow_up_stops_blocking() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    _record_follow_up("load_agent_from_repository")

    blocked = await _finish(coordinator)
    _update_impl(
        entry_id=blocked["follow_ups"][0]["entry_id"],
        outcome="reported",
        evidence="ImportString field resolves os.system.",
        agent_id="agent-2",
        agent_name="follow-up",
    )

    assert (await _finish(coordinator))["scan_completed"] is True


@pytest.mark.asyncio
async def test_follow_ups_do_not_block_once_the_budget_reserve_is_hit() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    _record_follow_up("load_agent_from_repository")
    await coordinator.claim_reserve_notification()

    assert (await _finish(coordinator))["scan_completed"] is True
