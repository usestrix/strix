"""Assessment completion must not claim that pending fixes are ready."""

from __future__ import annotations

import argparse
import importlib
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from rich.console import Console

from strix.report import state
from strix.tools.finish.tool import _do_finish


@pytest.mark.parametrize("pending", [False, True])
def test_finish_result_distinguishes_assessment_from_fix_completion(
    monkeypatch: pytest.MonkeyPatch, pending: bool
) -> None:
    report = SimpleNamespace(
        defer_completion=pending,
        vulnerability_reports=[],
        update_scan_final_fields=lambda **_: None,
    )
    monkeypatch.setattr(state, "get_global_report_state", lambda: report)
    result = _do_finish(
        parent_id=None,
        executive_summary="Summary",
        methodology="Method",
        technical_analysis="Analysis",
        recommendations="Recommendations",
        agent_graph={},
    )
    assert result["scan_completed"] is True
    assert bool(result.get("fixes_pending")) is pending
    if pending:
        assert "still being prepared" in result["message"]


def test_final_summary_shows_branches_and_unavailable_fixes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    main: Any = importlib.import_module("strix.interface.main")
    report = SimpleNamespace(
        run_record={"status": "completed"},
        scan_results={
            "fix_branches": [
                {"title": "Export", "branch": "strix/fix-export", "source_path": "/workspace/repo"}
            ],
            "fix_branch_errors": [{"title": "Import", "error": "Reviewer rejected the fix"}],
        },
    )
    output = StringIO()
    monkeypatch.setattr(state, "get_global_report_state", lambda: report)
    monkeypatch.setattr(main, "Console", lambda: Console(file=output, width=120, color_system=None))
    monkeypatch.setattr(main, "build_final_stats_text", lambda _: main.Text())
    main.display_completion_message(
        argparse.Namespace(
            targets_info=[{"original": "/workspace/repo"}],
            run_name="scan",
            non_interactive=True,
        ),
        Path("/workspace/results"),
    )
    assert "strix/fix-export" in output.getvalue()
    assert "/workspace/repo" in output.getvalue()
    assert "Fix unavailable" in output.getvalue()
    assert "Reviewer rejected the fix" in output.getvalue()
