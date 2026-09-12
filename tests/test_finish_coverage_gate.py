"""finish_scan confronts the root agent with the coverage the runtime can see."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.tools.coverage.tools import _record_impl, hydrate_coverage_from_disk
from strix.tools.finish.tool import _coverage_summary, _do_finish


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


@pytest.mark.parametrize(
    ("field_name", "placeholder"),
    [
        ("executive_summary", "Business-level summary for leadership."),
        ("methodology", "Frameworks, scope, and approach."),
        ("technical_analysis", "Consolidated findings + systemic themes."),
        ("recommendations", "Prioritized, actionable remediation."),
    ],
)
def test_finish_rejects_schema_description_placeholders(
    field_name: str, placeholder: str
) -> None:
    report_fields = {
        "executive_summary": "No material exposure was confirmed.",
        "methodology": "The scoped paths were reviewed and exercised.",
        "technical_analysis": "Observed controls held under the tested cases.",
        "recommendations": "Retest after material changes.",
    }
    report_fields[field_name] = f" \n{placeholder}\t"

    result = _do_finish(parent_id=None, agent_graph={}, **report_fields)

    assert result["success"] is False
    assert "placeholder" in " ".join(result["errors"]).lower()
