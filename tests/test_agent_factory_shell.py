"""Tests for the shell tool adapters in the agent factory."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast

import pytest
from agents.tool import CustomTool, FunctionTool

from strix.agents import factory
from strix.config import load_settings


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


def _running_exec_tool(result: str) -> FunctionTool:
    async def invoke(_ctx: Any, _raw_input: str) -> str:
        return result

    return FunctionTool(
        name="exec_command",
        description="Runs a command.",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=invoke,
    )


_RUNNING_RESULT = (
    "Chunk ID: abc123\nWall time: 30.0012 seconds\nProcess running with session ID 7\nOutput:\n"
)


def test_wrap_exec_command_describes_the_yield_cap() -> None:
    wrapped = factory._wrap_exec_command(_running_exec_tool("ok"))

    assert wrapped.description.startswith("Runs a command. The wait for output is capped at 30 s")
    assert "cannot be read later" in wrapped.description
    assert "tty=true" in wrapped.description


@pytest.mark.asyncio
async def test_wrap_exec_command_flags_a_running_non_tty_process() -> None:
    wrapped = factory._wrap_exec_command(_running_exec_tool(_RUNNING_RESULT))

    result = await wrapped.on_invoke_tool(
        cast("Any", None), json.dumps({"cmd": "sleep 60; curl x", "yield_time_ms": 90000})
    )

    assert result == (
        "Chunk ID: abc123\nWall time: 30.0012 seconds\n"
        "Process running with session ID 7\nOutput:\n"
        "Note: yield_time_ms=90000 was capped at 30000 (30 s). this non-TTY process cannot be "
        "polled and its later output is lost. Rerun it in the background "
        "(`cmd > /tmp/out.log 2>&1 &`, then read the log) or with tty=true.\n"
    )


@pytest.mark.asyncio
async def test_wrap_exec_command_flags_a_running_non_tty_process_within_the_cap() -> None:
    wrapped = factory._wrap_exec_command(_running_exec_tool(_RUNNING_RESULT))

    result = await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"cmd": "sleep 60"}))

    assert "Note: this non-TTY process cannot be polled" in result
    assert "was capped" not in result


@pytest.mark.asyncio
async def test_wrap_exec_command_leaves_a_running_tty_process_alone() -> None:
    wrapped = factory._wrap_exec_command(_running_exec_tool(_RUNNING_RESULT))

    result = await wrapped.on_invoke_tool(
        cast("Any", None), json.dumps({"cmd": "python3 -m http.server", "tty": True})
    )

    assert result == _RUNNING_RESULT


@pytest.mark.asyncio
async def test_wrap_exec_command_leaves_an_exited_process_alone() -> None:
    exited = "Chunk ID: abc123\nWall time: 0.1 seconds\nProcess exited with code 0\nOutput:\nhi"
    wrapped = factory._wrap_exec_command(_running_exec_tool(exited))

    result = await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"cmd": "echo hi"}))

    assert result == exited


@pytest.mark.asyncio
async def test_wrap_exec_command_ignores_the_running_marker_inside_command_output() -> None:
    exited = (
        "Chunk ID: abc123\nWall time: 0.2 seconds\nProcess exited with code 0\nOutput:\n"
        "Process running with session ID 7\nOutput:\n"
    )
    wrapped = factory._wrap_exec_command(_running_exec_tool(exited))

    result = await wrapped.on_invoke_tool(
        cast("Any", None), json.dumps({"cmd": "cat transcript.txt"})
    )

    assert result == exited


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


@pytest.mark.parametrize(("supports_images", "has_view_image"), [(True, True), (False, False)])
def test_view_image_is_left_out_for_text_only_models(
    supports_images: bool, has_view_image: bool
) -> None:
    agent = factory.build_strix_agent(is_root=True, supports_images=supports_images)
    filesystem = agent.capabilities[0]
    filesystem.bind(cast("Any", object()))

    view_image = next(tool for tool in filesystem.tools() if tool.name == "view_image")
    assert cast("FunctionTool", view_image).is_enabled is has_view_image
