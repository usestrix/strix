"""The content-guardrail stop records a surfaced reason and stops gracefully."""

from __future__ import annotations

import json
import types
from typing import Any

import pytest

import strix.report.state as report_state_mod
import strix.tools.notes.tools as notes_tools
import strix.tools.todo.tools as todo_tools
from strix.config import codex
from strix.core import runner
from strix.core.agents import AgentCoordinator
from strix.core.paths import run_record_path
from strix.report.state import ReportState
from strix.runtime import session_manager
from strix.viewer.transcript import read_run_summary


@pytest.mark.asyncio
async def test_content_guardrail_stops_gracefully_and_records_reason(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """A guardrail block stops the scan (root -> 'stopped'), doesn't raise, and
    records a human-readable stop reason on the run record for the UIs."""
    monkeypatch.setattr(runner, "run_dir_for", lambda _scan_id: tmp_path)
    monkeypatch.setattr(runner, "runtime_state_dir", lambda _run_dir: tmp_path)
    monkeypatch.setattr(runner, "setup_scan_logging", lambda _run_dir: lambda: None)
    monkeypatch.setattr(runner, "set_scan_id", lambda _scan_id: None)

    settings = types.SimpleNamespace(
        llm=types.SimpleNamespace(
            model="chatgpt/gpt-5.6-sol",
            reasoning_effort="high",
            force_required_tool_choice=False,
            timeout=300,
        ),
        runtime=types.SimpleNamespace(max_context_images=3),
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

    monkeypatch.setattr(session_manager, "create_or_reuse", _create_or_reuse)
    monkeypatch.setattr(session_manager, "cleanup", _cleanup)
    monkeypatch.setattr(runner, "build_root_task", lambda _scan_config: "task")
    monkeypatch.setattr(runner, "build_scope_context", lambda _scan_config: "")
    monkeypatch.setattr(runner, "make_model_settings", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(runner, "build_strix_agent", lambda **_kwargs: object())
    monkeypatch.setattr(runner, "make_child_factory", lambda **_kwargs: lambda **_k: object())
    monkeypatch.setattr(runner, "open_agent_session", lambda _root_id, _db: object())

    async def _raise_guardrail(*_args: Any, **_kwargs: Any) -> None:
        raise codex.CodexContentGuardrailError("gpt-5.6-sol")

    monkeypatch.setattr(runner, "run_agent_loop", _raise_guardrail)

    # A real report state, made global so the runner records onto it. Disk writes
    # are stubbed so the assertion runs on the in-memory record only.
    report_state = ReportState("scan-test")
    monkeypatch.setattr(report_state, "save_run_data", lambda *_a, **_k: None)
    monkeypatch.setattr(report_state_mod, "_global_report_state", report_state)

    coordinator = AgentCoordinator()
    result = await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-test",
        image="img",
        coordinator=coordinator,
    )

    assert result is None
    root_ids = [aid for aid, parent in coordinator.parent_of.items() if parent is None]
    assert len(root_ids) == 1
    assert coordinator.statuses[root_ids[0]] == "stopped"
    reason = report_state.run_record.get("stop_reason")
    assert reason is not None
    assert "gpt-5.6-sol" in reason
    assert report_state.run_record.get("stop_reason_category") == "content_guardrail"


def test_read_run_summary_passes_stop_reason(tmp_path: Any) -> None:
    """The viewer's /api/run payload carries stop_reason through to the web UI."""
    run_record_path(tmp_path).write_text(
        json.dumps({"status": "stopped", "end_time": "t", "stop_reason": "blocked by guardrail"}),
        encoding="utf-8",
    )
    summary = read_run_summary(tmp_path)
    assert summary["stop_reason"] == "blocked by guardrail"
    assert summary["finished"] is True
