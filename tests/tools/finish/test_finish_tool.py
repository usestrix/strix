"""Regression tests for finish_scan partial-report persistence (issue #294)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.report.state import ReportState, set_global_report_state
from strix.telemetry import posthog, scarf
from strix.tools.finish.tool import _NOT_PROVIDED, _do_finish


if TYPE_CHECKING:
    from pathlib import Path


def _noop(*args: object, **kwargs: object) -> None:
    return None


@pytest.fixture
def state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(posthog, "end", _noop)
    monkeypatch.setattr(scarf, "end", _noop)
    rs = ReportState(run_name="test-run")
    set_global_report_state(rs)
    return rs


def test_partial_report_is_saved_with_placeholder(state: ReportState) -> None:
    result = _do_finish(
        parent_id=None,
        executive_summary="Critical exposure found.",
        methodology="",
        technical_analysis="SQLi via id parameter.",
        recommendations="Parameterize queries.",
    )

    assert result["success"] is True
    assert result["scan_completed"] is True
    assert "methodology" in result["warning"]

    assert state.scan_results is not None
    assert state.scan_results["methodology"] == _NOT_PROVIDED
    assert state.scan_results["executive_summary"] == "Critical exposure found."

    report_path = state.get_run_dir() / "penetration_test_report.md"
    assert report_path.exists()
    assert _NOT_PROVIDED in report_path.read_text(encoding="utf-8")


def test_complete_report_has_no_warning(state: ReportState) -> None:
    result = _do_finish(
        parent_id=None,
        executive_summary="Summary.",
        methodology="OWASP WSTG.",
        technical_analysis="Findings.",
        recommendations="Remediation.",
    )

    assert result["success"] is True
    assert "warning" not in result
    assert state.scan_results is not None
    assert state.scan_results["methodology"] == "OWASP WSTG."


def test_all_empty_sections_still_complete(state: ReportState) -> None:
    result = _do_finish(
        parent_id=None,
        executive_summary="   ",
        methodology="",
        technical_analysis="",
        recommendations="",
    )

    assert result["success"] is True
    assert result["scan_completed"] is True
    assert state.scan_results is not None
    assert all(
        state.scan_results[field] == _NOT_PROVIDED
        for field in ("executive_summary", "methodology", "technical_analysis", "recommendations")
    )


def test_subagent_cannot_finish() -> None:
    result = _do_finish(
        parent_id="parent-1",
        executive_summary="x",
        methodology="x",
        technical_analysis="x",
        recommendations="x",
    )

    assert result["success"] is False
    assert "agent_finish" in result["error"]
