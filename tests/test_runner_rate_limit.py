"""Tests for graceful handling of persistent RateLimitError in run_strix_scan."""

from __future__ import annotations

import logging
import types
from typing import Any

import httpx
import pytest
from openai import RateLimitError

import strix.tools.notes.tools as notes_tools
import strix.tools.todo.tools as todo_tools
from strix.core import runner
from strix.core.agents import AgentCoordinator


def _make_rate_limit_error() -> RateLimitError:
    request = httpx.Request("POST", "https://api.openai.com/v1/responses")
    response = httpx.Response(status_code=429, request=request)
    return RateLimitError("rate limited", response=response, body=None)


@pytest.mark.asyncio
async def test_persistent_rate_limit_stops_gracefully(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """A persistent RateLimitError stops the scan (root -> 'stopped') without raising."""
    monkeypatch.setattr(runner, "run_dir_for", lambda _scan_id: tmp_path)
    monkeypatch.setattr(runner, "runtime_state_dir", lambda _run_dir: tmp_path)
    monkeypatch.setattr(runner, "setup_scan_logging", lambda _run_dir: lambda: None)
    monkeypatch.setattr(runner, "set_scan_id", lambda _scan_id: None)

    settings = types.SimpleNamespace(
        llm=types.SimpleNamespace(model="openai/gpt-4o", reasoning_effort="high")
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

    monkeypatch.setattr(runner.session_manager, "create_or_reuse", _create_or_reuse)
    monkeypatch.setattr(runner.session_manager, "cleanup", _cleanup)

    monkeypatch.setattr(runner, "build_root_task", lambda _scan_config: "task")
    monkeypatch.setattr(runner, "build_scope_context", lambda _scan_config: "")
    monkeypatch.setattr(runner, "make_model_settings", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(runner, "build_strix_agent", lambda **_kwargs: object())
    monkeypatch.setattr(runner, "make_child_factory", lambda **_kwargs: lambda **_k: object())
    monkeypatch.setattr(runner, "open_agent_session", lambda _root_id, _db: object())

    async def _raise_rate_limit(*_args: Any, **_kwargs: Any) -> None:
        raise _make_rate_limit_error()

    monkeypatch.setattr(runner, "run_agent_loop", _raise_rate_limit)

    coordinator = AgentCoordinator()

    with caplog.at_level(logging.WARNING):
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
    # the resume hint must carry the real scan id, not a literal placeholder
    assert "strix --resume scan-test" in caplog.text
    assert "<run_name>" not in caplog.text
