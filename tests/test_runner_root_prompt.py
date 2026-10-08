"""Tests for root scan prompt options in run_strix_scan.

Verify that ``root_instructions_override`` and ``extra_system_prompt_context``
flow through to the root agent's ``build_strix_agent`` call.
"""

from __future__ import annotations

import importlib
import os
import types
from typing import Any

import httpx
import pytest
from agents import ModelSettings
from agents.tool_context import ToolContext
from openai import RateLimitError

import strix.tools.mcp as mcp_pkg
import strix.tools.notes.tools as notes_tools
import strix.tools.todo.tools as todo_tools
from strix.agents.prompt import render_system_prompt
from strix.config.models import _split_cached_prefix
from strix.core import runner
from strix.core.agents import AgentCoordinator
from strix.core.inputs import make_model_settings
from strix.runtime import session_manager
from strix.tools.load_skill.tool import load_skill
from strix.tools.mcp import BearerAuth, McpConnectionConfig, McpConnectionRequest
from strix.tools.mcp import client as mcp_client


_test_mcp_client = importlib.import_module("tests.test_mcp_client")
FakeMCPServer: Any = _test_mcp_client.FakeMCPServer


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
            timeout=300,
            prompt_cache=True,
            extra_headers=None,
        ),
        runtime=types.SimpleNamespace(max_context_images=3),
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

    monkeypatch.setattr(session_manager, "create_or_reuse", _create_or_reuse)
    monkeypatch.setattr(session_manager, "cleanup", _cleanup)

    monkeypatch.setattr(runner, "build_root_task", lambda _scan_config: "task")
    monkeypatch.setattr(runner, "build_scope_context", lambda _scan_config: scope_context)
    monkeypatch.setattr(runner, "make_model_settings", lambda *_args, **_kwargs: ModelSettings())
    monkeypatch.setattr(
        mcp_client,
        "_build_server",
        lambda config: mcp_client.BuiltMcpServer(FakeMCPServer(config.name, []), None),
    )

    captured: dict[str, Any] = {}

    def _build_strix_agent(**kwargs: Any) -> object:
        if kwargs.get("is_root") and "kwargs" not in captured:
            captured["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(runner, "build_strix_agent", _build_strix_agent)
    monkeypatch.setattr(runner, "make_child_factory", lambda **_kwargs: lambda **_k: object())
    monkeypatch.setattr(runner, "open_agent_session", lambda _root_id, _db: object())

    async def _raise_rate_limit(*_args: Any, **kwargs: Any) -> None:
        captured["run_config"] = kwargs.get("run_config")
        raise _make_rate_limit_error()

    monkeypatch.setattr(runner, "run_agent_loop", _raise_rate_limit)
    return captured


@pytest.mark.asyncio
async def test_root_prompt_options_flow_into_root_agent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    scope_context = {
        "scope_source": "user_scan_config",
        "authorized_targets": [
            {
                "type": "web_application",
                "value": "https://example.com",
                "workspace_path": "",
            },
        ],
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
    assert "SCOPE:" in instructions_override
    assert "AUTHORIZED TARGETS" in instructions_override
    assert "https://example.com" in instructions_override
    assert "CUSTOM SCAN PROMPT" in instructions_override
    assert instructions_override.count("SCOPE:") == 1
    assert instructions_override.index("CUSTOM SCAN PROMPT") < instructions_override.index("SCOPE:")
    assert (
        "The following root scan instructions describe the task configuration."
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


@pytest.mark.asyncio
async def test_mcp_available_flag_set_when_a_connection_attaches(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    """When at least one MCP connection attaches, the runner sets ``mcp_available``
    plus a named ``mcp_connections`` inventory into the scan context that reaches
    every agent, so each agent sees which connections exist at the start while
    still being able to re-list them at run time via list_mcps."""
    scope_context: dict[str, Any] = {"scope": "built-in"}
    captured = _patch_engine_scaffold(monkeypatch, tmp_path, scope_context)

    request = McpConnectionRequest(
        config=McpConnectionConfig(
            name="fs",
            url="https://mcp.example.com",
            auth=BearerAuth(token="run-token"),
            notes="local files",
        )
    )

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-mcp-available",
        image="img",
        coordinator=AgentCoordinator(),
        mcp_connection_requests=[request],
    )

    kwargs = captured["kwargs"]
    assert kwargs["system_prompt_context"]["mcp_available"] is True
    # The named inventory names each connected server for the prompt.
    assert kwargs["system_prompt_context"]["mcp_connections"] == [
        {
            "name": "fs",
            "purpose": "local files",
            "tool_count": 0,
            "state": "catalog_ready",
        }
    ]


@pytest.mark.asyncio
async def test_mcp_available_flag_absent_without_a_connection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    """With no MCP connection, the scan context carries no MCP key at all, so the
    prompt's MCP section stays off."""
    scope_context: dict[str, Any] = {"scope": "built-in"}
    captured = _patch_engine_scaffold(monkeypatch, tmp_path, scope_context)

    monkeypatch.setattr(mcp_pkg, "load_user_mcp_configs", list)

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-mcp-absent",
        image="img",
        coordinator=AgentCoordinator(),
    )

    kwargs = captured["kwargs"]
    assert "mcp_available" not in kwargs["system_prompt_context"]
    assert "mcp_connections" not in kwargs["system_prompt_context"]


@pytest.mark.asyncio
async def test_unknown_tool_calls_are_returned_to_the_model(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    """A hallucinated tool name must not end the scan."""
    captured = _patch_engine_scaffold(monkeypatch, tmp_path, {})

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-unknown-tool",
        image="img",
        coordinator=AgentCoordinator(),
    )

    assert captured["run_config"].tool_not_found_behavior == "return_error_to_model"


def test_scope_is_rendered_once_at_the_end_of_the_prompt() -> None:
    prompt = render_system_prompt(
        system_prompt_context={
            "authorized_targets": [{"type": "web_application", "value": "https://example.com"}],
        },
    )

    assert prompt.count("SCOPE:") == 1
    assert prompt.index("</available_skills>") < prompt.index("SCOPE:")


def test_requested_skills_follow_the_shared_prefix() -> None:
    xss = render_system_prompt(skills=["xss"], include_scope=False)
    sqli = render_system_prompt(skills=["sql_injection"], include_scope=False)

    shared = os.path.commonprefix([xss, sqli])
    assert "</available_skills>" in shared
    assert shared.count("<cache_point>") == 1
    assert "<xss>" in xss.split("<cache_point>")[1]


def test_text_only_prompt_drops_screenshot_guidance() -> None:
    assert "view_image" in render_system_prompt(include_scope=False)

    prompt = render_system_prompt(include_scope=False, supports_images=False)
    assert "view_image" not in prompt
    assert "text-only model and cannot view images" in prompt
    assert "<!--" not in prompt


@pytest.mark.asyncio
async def test_text_only_load_skill_drops_screenshot_guidance() -> None:
    ctx = ToolContext(
        context={"supports_images": False},
        tool_name="load_skill",
        tool_call_id="call-1",
        tool_arguments="{}",
    )

    out = await load_skill.on_invoke_tool(ctx, '{"skills": ["agent_browser"]}')
    assert "view_image" not in out
    assert "text-only model" in out


def test_scope_is_sent_as_its_own_system_message_on_cache_point_routes() -> None:
    settings = make_model_settings(None, model_name="anthropic/claude-sonnet-5-5")
    prompt = render_system_prompt(
        system_prompt_context={
            "authorized_targets": [{"type": "web_application", "value": "https://target.invalid"}],
        },
    )

    system, model_input = _split_cached_prefix(prompt, "go", settings)

    assert system is None
    assert isinstance(model_input, list)
    assert [item["role"] for item in model_input] == ["system", "system", "user"]
    assert "https://target.invalid" not in model_input[0]["content"]
    assert "https://target.invalid" in model_input[1]["content"]
    assert "<cache_point>" not in model_input[0]["content"] + model_input[1]["content"]


def test_cache_point_marker_is_removed_without_cache_points() -> None:
    settings = make_model_settings(None, model_name="openai/gpt-5")
    prompt = "shared\n<cache_point>\ntargets"

    assert _split_cached_prefix(prompt, "go", settings) == ("shared\n\ntargets", "go")
