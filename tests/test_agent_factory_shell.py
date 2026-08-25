"""Tests for the shell tool adapters in the agent factory."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents.tool import CustomTool, FunctionTool

from strix.agents import factory
from strix.config import load_settings
from strix.config.settings import SafetySettings
from strix.safety.runtime import SafetyRuntime


if TYPE_CHECKING:
    from pathlib import Path


def _capturing_exec_tool(captured: dict[str, str]) -> FunctionTool:
    async def invoke(_ctx: Any, raw_input: str) -> str:
        captured["raw_input"] = raw_input
        return "ok"

    return FunctionTool(
        name="exec_command",
        description="test tool",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=invoke,
    )


@pytest.mark.asyncio
async def test_wrap_exec_command_defaults_shell_to_bash() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_capturing_exec_tool(captured))

    result = await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"cmd": "source /tmp/env"}))

    assert result == "ok"
    parsed = json.loads(captured["raw_input"])
    assert parsed["cmd"] == "source /tmp/env"
    assert parsed["shell"] == "bash"
    expected_cap = load_settings().context.tool_output_max_tokens
    assert parsed["max_output_tokens"] == expected_cap


@pytest.mark.asyncio
async def test_wrap_exec_command_preserves_smaller_explicit_output_cap() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_capturing_exec_tool(captured))

    await wrapped.on_invoke_tool(
        cast("Any", None), json.dumps({"cmd": "echo hi", "max_output_tokens": 42})
    )

    assert json.loads(captured["raw_input"])["max_output_tokens"] == 42


@pytest.mark.asyncio
async def test_wrap_exec_command_clamps_oversized_explicit_output_cap() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_capturing_exec_tool(captured))
    ceiling = load_settings().context.tool_output_max_tokens

    await wrapped.on_invoke_tool(
        cast("Any", None),
        json.dumps({"cmd": "echo hi", "max_output_tokens": ceiling * 100}),
    )

    assert json.loads(captured["raw_input"])["max_output_tokens"] == ceiling


@pytest.mark.asyncio
@pytest.mark.parametrize("shell", ["/bin/zsh", ""])
async def test_wrap_exec_command_preserves_explicit_shell(shell: str) -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_capturing_exec_tool(captured))

    await wrapped.on_invoke_tool(
        cast("Any", None), json.dumps({"cmd": "echo test", "shell": shell})
    )

    assert json.loads(captured["raw_input"])["shell"] == shell


@pytest.mark.asyncio
async def test_responses_filesystem_custom_tool_output_is_bounded() -> None:
    async def invoke(_ctx: Any, _inp: str) -> str:
        return "line\n" * 50_000

    toolset = SimpleNamespace(
        read_file=CustomTool(name="read_file", description="read", on_invoke_tool=invoke)
    )
    factory._configure_filesystem_tools(toolset, chat_completions=False)

    assert isinstance(toolset.read_file, CustomTool)
    result = await toolset.read_file.on_invoke_tool(cast("Any", None), "{}")

    assert "truncated" in result
    assert len(result) < len("line\n" * 50_000)


@pytest.mark.asyncio
async def test_chat_completions_filesystem_custom_tool_becomes_function_tool() -> None:
    async def invoke(_ctx: Any, _inp: str) -> str:
        return "ok"

    toolset = SimpleNamespace(
        read_file=CustomTool(name="read_file", description="read", on_invoke_tool=invoke)
    )
    factory._configure_filesystem_tools(toolset, chat_completions=True)

    assert isinstance(toolset.read_file, FunctionTool)


def test_function_tools_are_result_bounded() -> None:
    agent = factory.build_strix_agent(is_root=True)
    by_name = {t.name: t for t in agent.tools}

    assert getattr(by_name["think"], "_strix_bounded", False) is True


def test_only_effectful_static_tools_are_safety_guarded() -> None:
    # Pins the safety classification of the base tool set: the one effectful
    # static function tool is guarded for pre-execution review, while internal
    # bookkeeping and read-only tools run unreviewed. Guarding a read-only tool
    # would serialize it on the workspace lock and churn other agents' review
    # epochs, so a new effectful tool must be added to _MUTATING_STATIC_TOOLS.
    agent = factory.build_strix_agent(is_root=True)
    by_name = {t.name: t for t in agent.tools}

    assert getattr(by_name["repeat_request"], "_strix_safety_guarded", False) is True
    for name in ("think", "web_search", "list_requests", "create_note", "view_agent_graph"):
        assert getattr(by_name[name], "_strix_safety_guarded", False) is False, name


def test_safety_guard_honors_the_sdk_needs_approval_signal() -> None:
    async def invoke(_ctx: Any, _raw: str) -> str:
        return "ok"

    future_tool = FunctionTool(
        name="some_future_effectful_tool",
        description="test tool",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=invoke,
        needs_approval=True,
    )

    guarded = factory._with_safety_guard(future_tool)

    assert getattr(guarded, "_strix_safety_guarded", False) is True


def _capturing_stdin_tool(captured: dict[str, str]) -> FunctionTool:
    async def invoke(_ctx: Any, raw_input: str) -> str:
        captured["raw_input"] = raw_input
        return "typed"

    return FunctionTool(
        name="write_stdin",
        description="test tool",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=invoke,
    )


class _InspectionRunner:
    async def run(self, *, evidence_dir: str, script: str) -> str:
        return f"unused: {evidence_dir} {script}"


def _guarded_runtime(tmp_path: Path) -> SafetyRuntime:
    return SafetyRuntime(
        scan_id="scan-1",
        mode="guarded",
        scope={},
        user_instruction="",
        settings=SafetySettings(),
        run_dir=tmp_path,
        sandbox_image="image",
        inspection_runner=_InspectionRunner(),
    )


@pytest.mark.asyncio
async def test_write_stdin_is_routed_through_the_safety_runtime(tmp_path: Path) -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_write_stdin(_capturing_stdin_tool(captured))
    ctx = SimpleNamespace(
        context={"safety_runtime": _guarded_runtime(tmp_path), "agent_id": "agent-1"},
        tool_call_id="call-1",
    )

    result = await wrapped.on_invoke_tool(
        cast("Any", ctx),
        json.dumps({"session_id": "s", "chars": "rm -rf /workspace\\n"}),
    )

    payload = json.loads(result)
    assert payload["status"] == "blocked"
    assert "write_stdin is blocked" in payload["safety"]["reason"]
    assert captured == {}


@pytest.mark.asyncio
async def test_write_stdin_runs_directly_without_a_safety_runtime() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_write_stdin(_capturing_stdin_tool(captured))
    ctx = SimpleNamespace(context={}, tool_call_id="call-1")

    result = await wrapped.on_invoke_tool(
        cast("Any", ctx), json.dumps({"session_id": "s", "chars": "y\\n"})
    )

    assert result == "typed"
    assert json.loads(captured["raw_input"])["chars"] == "y\n"
