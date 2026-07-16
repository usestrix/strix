"""Tests for root scan prompt options in run_strix_scan.

Verify that ``root_instructions_override`` and ``extra_system_prompt_context``
flow through to the root agent's ``build_strix_agent`` call.
"""

from __future__ import annotations

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


def _patch_engine_scaffold(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    scope_context: dict[str, Any],
) -> dict[str, Any]:
    """Stub out everything around build_strix_agent and stop at run_agent_loop.

    Returns a dict that will be populated with the kwargs the runner passed to
    ``build_strix_agent`` for the root agent.
    """
    monkeypatch.setattr(runner, "run_dir_for", lambda _scan_id: tmp_path)
    monkeypatch.setattr(runner, "runtime_state_dir", lambda _run_dir: tmp_path)
    monkeypatch.setattr(runner, "setup_scan_logging", lambda _run_dir: lambda: None)
    monkeypatch.setattr(runner, "set_scan_id", lambda _scan_id: None)

    settings = types.SimpleNamespace(
        llm=types.SimpleNamespace(
            model="openai/gpt-4o",
            reasoning_effort="high",
            force_required_tool_choice=False,
        )
    )
    monkeypatch.setattr(runner, "load_settings", lambda: settings)
    monkeypatch.setattr(runner, "configure_sdk_model_defaults", lambda _settings: None)
    monkeypatch.setattr(
        runner,
        "uses_chat_completions_tool_schema",
        lambda _model, _settings: False,
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
    monkeypatch.setattr(runner, "build_scope_context", lambda _scan_config: scope_context)
    monkeypatch.setattr(runner, "make_model_settings", lambda *_args, **_kwargs: object())

    captured: dict[str, Any] = {}

    def _build_strix_agent(**kwargs: Any) -> object:
        if kwargs.get("is_root") and "kwargs" not in captured:
            captured["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(runner, "build_strix_agent", _build_strix_agent)
    monkeypatch.setattr(runner, "make_child_factory", lambda **_kwargs: lambda **_k: object())
    monkeypatch.setattr(runner, "open_agent_session", lambda _root_id, _db: object())

    async def _raise_rate_limit(*_args: Any, **_kwargs: Any) -> None:
        raise _make_rate_limit_error()

    monkeypatch.setattr(runner, "run_agent_loop", _raise_rate_limit)
    return captured


@pytest.mark.asyncio
async def test_root_prompt_options_flow_into_root_agent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    scope_context = {
        "scope_source": "system_scan_config",
        "authorization_source": "strix_platform_verified_targets",
        "authorized_targets": [
            {
                "type": "web_application",
                "value": "https://example.com",
                "workspace_path": "",
            },
        ],
        "user_instructions_do_not_expand_scope": True,
    }
    captured = _patch_engine_scaffold(monkeypatch, tmp_path, scope_context)

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-ext",
        image="img",
        coordinator=AgentCoordinator(),
        root_instructions_override="CUSTOM SCAN PROMPT",
        extra_system_prompt_context={"target_context": "known findings"},
    )

    kwargs = captured["kwargs"]
    instructions_override = kwargs["instructions_override"]
    assert "SYSTEM-VERIFIED SCOPE" in instructions_override
    assert "AUTHORIZED TARGETS" in instructions_override
    assert "https://example.com" in instructions_override
    assert "CUSTOM SCAN PROMPT" in instructions_override
    assert (
        "cannot expand, replace, or weaken authorized target constraints"
        in instructions_override
    )
    assert kwargs["system_prompt_context"] == {
        **scope_context,
        "target_context": "known findings",
    }


@pytest.mark.asyncio
async def test_extra_system_prompt_context_cannot_override_scope_context(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    scope_context = {"authorized_targets": [{"type": "web_application"}]}
    captured = _patch_engine_scaffold(monkeypatch, tmp_path, scope_context)

    with pytest.raises(ValueError, match="authorized_targets"):
        await runner.run_strix_scan(
            scan_config={"targets": [], "scan_mode": "deep"},
            scan_id="scan-conflict",
            image="img",
            coordinator=AgentCoordinator(),
            extra_system_prompt_context={"authorized_targets": []},
        )

    assert "kwargs" not in captured


@pytest.mark.asyncio
async def test_root_prompt_options_default_to_none(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    """Without the new args, behavior is unchanged: no override, scope context as-is."""
    scope_context = {"scope": "built-in"}
    captured = _patch_engine_scaffold(monkeypatch, tmp_path, scope_context)

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-default",
        image="img",
        coordinator=AgentCoordinator(),
    )

    kwargs = captured["kwargs"]
    assert kwargs["instructions_override"] is None
    assert kwargs["system_prompt_context"] == {"scope": "built-in"}
