"""coverage.json is a deliverable artifact, not runtime state."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from strix.core.paths import runtime_state_dir
from strix.report.state import ReportState
from strix.tools.coverage.tools import _record_impl, hydrate_coverage_from_disk


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.chdir(tmp_path)
    report_state = ReportState(run_name="run-1")
    hydrate_coverage_from_disk(runtime_state_dir(report_state.get_run_dir()))
    return report_state


def _record_a_cleared_surface() -> None:
    _record_impl(
        surface="POST /api/orders/{id}",
        risk_area="SQL injection",
        outcome="no_issue_found",
        evidence="14 parameters fuzzed; every query parameterized.",
        agent_id="agent-1",
        agent_name="injection-tester",
    )


def test_coverage_is_written_beside_the_other_artifacts(state: ReportState) -> None:
    _record_a_cleared_surface()

    state._save_artifacts()

    document = json.loads((state.get_run_dir() / "coverage.json").read_text(encoding="utf-8"))
    assert document["entries"][0]["risk_area"] == "SQL injection"
    assert document["summary"]["surfaces_reviewed"] == 1


def test_cleared_surfaces_reach_sarif(state: ReportState) -> None:
    _record_a_cleared_surface()

    state._save_artifacts()

    sarif = json.loads((state.get_run_dir() / "findings.sarif").read_text(encoding="utf-8"))
    results = sarif["runs"][0]["results"]
    assert [result["kind"] for result in results] == ["pass"]


def test_artifacts_still_land_when_coverage_is_empty(state: ReportState) -> None:
    state.final_scan_result = "Scan complete."

    state._save_artifacts()

    run_dir = state.get_run_dir()
    assert (run_dir / "penetration_test_report.md").is_file()
    document = json.loads((run_dir / "coverage.json").read_text(encoding="utf-8"))
    assert document["entries"] == []
