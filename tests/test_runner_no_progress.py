"""Tests for the no-progress circuit breaker end-to-end handling in run_strix_scan.

These tests exercise the runner's ``except ScanLimitError`` path: when the
agent loop raises ``NoProgressExceededError`` the scan stops cleanly (root ->
``stopped``), a stub executive report is written, and the run record reflects
the early stop. A budget regression test confirms ``BudgetExceededError``
still routes through the same handler after the ``ScanLimitError`` refactor.
"""

from __future__ import annotations

import logging
import types
from typing import Any

import pytest

import strix.tools.notes.tools as notes_tools
import strix.tools.todo.tools as todo_tools
from strix.core import runner
from strix.core.agents import AgentCoordinator
from strix.core.hooks import BudgetExceededError, NoProgressExceededError
from strix.report.state import ReportState, set_global_report_state


def _patch_engine_scaffold(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """Stub everything run_strix_scan touches except the exception path under test."""
    monkeypatch.setattr(runner, "run_dir_for", lambda _scan_id: tmp_path)
    monkeypatch.setattr(runner, "runtime_state_dir", lambda _run_dir: tmp_path)
    monkeypatch.setattr(runner, "setup_scan_logging", lambda _run_dir: lambda: None)
    monkeypatch.setattr(runner, "set_scan_id", lambda _scan_id: None)

    settings = types.SimpleNamespace(
        llm=types.SimpleNamespace(
            model="openai/gpt-4o",
            reasoning_effort="high",
            force_required_tool_choice=False,
        ),
        runtime=types.SimpleNamespace(max_context_images=3),
        runner=types.SimpleNamespace(no_progress_max_turns=40, no_progress_breaker_enabled=True),
    )
    monkeypatch.setattr(runner, "load_settings", lambda: settings)
    monkeypatch.setattr(runner, "configure_sdk_model_defaults", lambda _settings: None)
    monkeypatch.setattr(
        runner, "uses_chat_completions_tool_schema", lambda _model, _settings: False
    )

    monkeypatch.setattr(todo_tools, "hydrate_todos_from_disk", lambda _state_dir: None)
    monkeypatch.setattr(notes_tools, "hydrate_notes_from_disk", lambda _state_dir: None)

    async def _create_or_reuse(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"client": object(), "session": object(), "caido_client": None}

    async def _cleanup(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(runner.session_manager, "create_or_reuse", _create_or_reuse)  # type: ignore[attr-defined]
    monkeypatch.setattr(runner.session_manager, "cleanup", _cleanup)  # type: ignore[attr-defined]

    monkeypatch.setattr(runner, "build_root_task", lambda _scan_config: "task")
    monkeypatch.setattr(runner, "build_scope_context", lambda _scan_config: "")
    monkeypatch.setattr(runner, "make_model_settings", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(runner, "build_strix_agent", lambda **_kwargs: object())
    monkeypatch.setattr(runner, "make_child_factory", lambda **_kwargs: lambda **_k: object())
    monkeypatch.setattr(runner, "open_agent_session", lambda _root_id, _db: object())


def _install_report_state(tmp_path: Any) -> ReportState:
    report_state = ReportState(run_name="scan-test")
    report_state._run_dir = tmp_path  # type: ignore[attr-defined]  # bypass run_dir_for()
    set_global_report_state(report_state)
    return report_state


@pytest.mark.asyncio
async def test_no_progress_writes_early_stop_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, caplog: pytest.LogCaptureFixture
) -> None:
    _patch_engine_scaffold(monkeypatch, tmp_path)
    report_state = _install_report_state(tmp_path)
    # Simulate one finding already recorded before the breaker tripped.
    report_state.vulnerability_reports.append(
        {
            "id": "vuln-0001",
            "title": "Demo finding",
            "severity": "high",
            "timestamp": "2026-07-20 00:00:00 UTC",
            "file": "vulnerabilities/vuln-0001.md",
        }
    )

    async def _raise_no_progress(*_args: Any, **_kwargs: Any) -> None:
        raise NoProgressExceededError(
            "No new findings or notes in the last 40 LLM turn(s) (threshold=40); "
            "findings=1, notes=0."
        )

    monkeypatch.setattr(runner, "run_agent_loop", _raise_no_progress)

    coordinator = AgentCoordinator()

    with caplog.at_level(logging.INFO):
        result = await runner.run_strix_scan(
            scan_config={"targets": [], "scan_mode": "deep"},
            scan_id="scan-test",
            image="img",
            coordinator=coordinator,
            no_progress_max_turns=40,
        )

    # Runner returned None and marked the root stopped.
    assert result is None
    root_ids = [aid for aid, parent in coordinator.parent_of.items() if parent is None]
    assert len(root_ids) == 1
    assert coordinator.statuses[root_ids[0]] == "stopped"

    # A stub executive report was written and flags the early stop.
    report_md = tmp_path / "penetration_test_report.md"
    assert report_md.exists()
    report_text = report_md.read_text(encoding="utf-8")
    assert "no_progress" in report_text
    assert "terminated early" in report_text
    assert "Demo finding" in report_text  # the preserved finding is listed

    # The run record reflects the stop, not "completed".
    run_json = (tmp_path / "run.json").read_text(encoding="utf-8")
    assert '"status": "stopped"' in run_json
    assert '"stop_reason": "no_progress"' in run_json

    # The early-stop was logged.
    assert "no-progress early-stop report" in caplog.text


@pytest.mark.asyncio
async def test_budget_exceeded_still_routes_through_scan_limit_handler(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """Regression: BudgetExceededError (now a ScanLimitError subclass) still stops cleanly."""
    _patch_engine_scaffold(monkeypatch, tmp_path)
    _install_report_state(tmp_path)

    async def _raise_budget(*_args: Any, **_kwargs: Any) -> None:
        raise BudgetExceededError("Token budget of $5.00 exceeded (spent $5.0001)")

    monkeypatch.setattr(runner, "run_agent_loop", _raise_budget)

    coordinator = AgentCoordinator()
    result = await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-test",
        image="img",
        coordinator=coordinator,
        no_progress_max_turns=40,
    )

    assert result is None
    root_ids = [aid for aid, parent in coordinator.parent_of.items() if parent is None]
    assert len(root_ids) == 1
    assert coordinator.statuses[root_ids[0]] == "stopped"
