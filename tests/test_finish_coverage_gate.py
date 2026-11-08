"""finish_scan confronts the root agent with the coverage the runtime can see."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.tools.coverage.tools import _record_impl, hydrate_coverage_from_disk
from strix.tools.finish.tool import _coverage_summary, _narrative_reconciliation


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


def test_narrative_describing_weaknesses_with_zero_findings_is_flagged() -> None:
    summary = _narrative_reconciliation(
        vuln_count=0,
        executive_summary="The host exposes an unsecured Docker Registry.",
        technical_analysis="Missing security headers were observed on all responses.",
    )

    assert "narrative_warning" in summary
    assert set(summary["narrative_weakness_markers"]) >= {
        "unsecured",
        "missing security header",
    }


def test_zero_findings_with_clean_narrative_raises_no_warning() -> None:
    summary = _narrative_reconciliation(
        vuln_count=0,
        executive_summary="The assessed surfaces were reviewed and no issues were found.",
        technical_analysis="All tested endpoints enforced authentication correctly.",
    )

    assert summary == {}


def test_filed_findings_suppress_narrative_warning() -> None:
    summary = _narrative_reconciliation(
        vuln_count=3,
        executive_summary="An unauthenticated registry was exposed.",
        technical_analysis="Multiple vulnerabilities confirmed.",
    )

    assert summary == {}
