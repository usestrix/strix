"""Tests for the shell tool adapters in the agent factory."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast

import pytest
from agents.sandbox.errors import InvalidManifestPathError
from agents.sandbox.session.pty_types import PTY_YIELD_TIME_MS_MAX
from agents.tool import CustomTool, FunctionTool
from pydantic import BaseModel, ValidationError

from strix.agents import factory
from strix.config import ShellSettings, load_settings


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


def _capturing_write_stdin_tool(captured: dict[str, str]) -> FunctionTool:
    async def invoke(_ctx: Any, raw_input: str) -> str:
        captured["raw_input"] = raw_input
        return "ok"

    return FunctionTool(
        name="write_stdin",
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


# --- yield-time defaults: exec_command --------------------------------------


@pytest.mark.asyncio
async def test_wrap_exec_command_raises_default_yield_when_omitted() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_capturing_exec_tool(captured))

    await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"cmd": "echo ok"}))

    expected = load_settings().shell_tools.exec_yield_ms
    assert json.loads(captured["raw_input"])["yield_time_ms"] == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cmd",
    ["nmap -sV example.com", "sudo nmap -sV example.com", "PROXY=1 ffuf -u http://x"],
)
async def test_wrap_exec_command_default_does_not_depend_on_the_binary(cmd: str) -> None:
    """The wrapper never guesses a command's runtime: the agent asks for a
    longer yield itself when it expects one."""
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_capturing_exec_tool(captured))

    await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"cmd": cmd}))

    expected = load_settings().shell_tools.exec_yield_ms
    assert json.loads(captured["raw_input"])["yield_time_ms"] == expected


@pytest.mark.asyncio
async def test_wrap_exec_command_preserves_longer_explicit_yield() -> None:
    """A slow command gets the yield the agent asked for, not a guessed one.

    The SDK's PTY layer clamps anything above 30s, so a longer wait than that
    cannot be bought with a bigger argument."""
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_capturing_exec_tool(captured))

    await wrapped.on_invoke_tool(
        cast("Any", None),
        json.dumps({"cmd": "nmap -p- example.com", "yield_time_ms": 25_000}),
    )

    assert json.loads(captured["raw_input"])["yield_time_ms"] == 25_000


@pytest.mark.asyncio
async def test_wrap_exec_command_preserves_explicit_yield() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_capturing_exec_tool(captured))

    await wrapped.on_invoke_tool(
        cast("Any", None), json.dumps({"cmd": "nmap example.com", "yield_time_ms": 500})
    )

    assert json.loads(captured["raw_input"])["yield_time_ms"] == 500


@pytest.mark.asyncio
async def test_wrap_exec_command_unparsable_command_still_gets_the_default() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_capturing_exec_tool(captured))

    await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"cmd": 'nmap "unterminated'}))

    expected = load_settings().shell_tools.exec_yield_ms
    assert json.loads(captured["raw_input"])["yield_time_ms"] == expected


# --- sleep guard -------------------------------------------------------------


@pytest.mark.asyncio
async def test_wrap_exec_command_caps_absurd_sleep_and_hints() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_capturing_exec_tool(captured))
    cap = load_settings().shell_tools.max_sleep_seconds

    result = await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"cmd": "sleep 3600"}))

    assert json.loads(captured["raw_input"])["cmd"] == f"sleep {cap}"
    assert isinstance(result, str)
    assert "write_stdin" in result


@pytest.mark.asyncio
async def test_wrap_exec_command_short_sleep_kept_but_hinted() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_capturing_exec_tool(captured))

    result = await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"cmd": "sleep 5"}))

    assert json.loads(captured["raw_input"])["cmd"] == "sleep 5"
    assert isinstance(result, str)
    assert "write_stdin" in result


@pytest.mark.asyncio
async def test_wrap_exec_command_leaves_compound_sleep_untouched() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_capturing_exec_tool(captured))

    result = await wrapped.on_invoke_tool(
        cast("Any", None), json.dumps({"cmd": "sleep 3600 && curl http://x"})
    )

    assert json.loads(captured["raw_input"])["cmd"] == "sleep 3600 && curl http://x"
    assert result == "ok"


@pytest.mark.asyncio
async def test_wrap_exec_command_malformed_input_passes_through() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_capturing_exec_tool(captured))

    assert await wrapped.on_invoke_tool(cast("Any", None), "not json") == "ok"
    assert captured["raw_input"] == "not json"


# --- yield-time defaults: write_stdin ---------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [{"session_id": 1}, {"session_id": 1, "chars": ""}])
async def test_wrap_write_stdin_empty_poll_gets_raised_default(payload: dict[str, Any]) -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_write_stdin(_capturing_write_stdin_tool(captured))

    await wrapped.on_invoke_tool(cast("Any", None), json.dumps(payload))

    expected = load_settings().shell_tools.write_stdin_poll_yield_ms
    assert json.loads(captured["raw_input"])["yield_time_ms"] == expected


@pytest.mark.asyncio
async def test_wrap_write_stdin_empty_poll_preserves_explicit_yield() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_write_stdin(_capturing_write_stdin_tool(captured))

    await wrapped.on_invoke_tool(
        cast("Any", None), json.dumps({"session_id": 1, "chars": "", "yield_time_ms": 250})
    )

    assert json.loads(captured["raw_input"])["yield_time_ms"] == 250


@pytest.mark.asyncio
async def test_wrap_write_stdin_non_empty_chars_keeps_snappy() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_write_stdin(_capturing_write_stdin_tool(captured))

    await wrapped.on_invoke_tool(
        cast("Any", None), json.dumps({"session_id": 1, "chars": "print(1)\\n"})
    )

    parsed = json.loads(captured["raw_input"])
    assert "yield_time_ms" not in parsed
    assert parsed["chars"] == "print(1)\n"


@pytest.mark.asyncio
async def test_wrap_write_stdin_non_empty_chars_preserves_explicit_yield() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_write_stdin(_capturing_write_stdin_tool(captured))

    await wrapped.on_invoke_tool(
        cast("Any", None), json.dumps({"session_id": 1, "chars": "y\\n", "yield_time_ms": 100})
    )

    assert json.loads(captured["raw_input"])["yield_time_ms"] == 100


@pytest.mark.asyncio
async def test_wrap_write_stdin_malformed_input_passes_through() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_write_stdin(_capturing_write_stdin_tool(captured))

    assert await wrapped.on_invoke_tool(cast("Any", None), "not json") == "ok"
    assert captured["raw_input"] == "not json"


# --- error formatting --------------------------------------------------------


class _ExecArgs(BaseModel):
    cmd: str


def _raising_tool(name: str, exc: Exception) -> FunctionTool:
    async def invoke(_ctx: Any, _raw_input: str) -> str:
        raise exc

    return FunctionTool(
        name=name,
        description="test tool",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=invoke,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "wrap"),
    [("exec_command", factory._wrap_exec_command), ("write_stdin", factory._wrap_write_stdin)],
)
async def test_validation_error_is_rendered_as_a_message(name: str, wrap: Any) -> None:
    try:
        _ExecArgs.model_validate({})
    except ValidationError as exc:
        validation_error = exc

    wrapped = wrap(_raising_tool(name, validation_error))
    result = await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"cmd": "echo hi"}))

    assert isinstance(result, str)
    assert result.startswith(f"{name}: invalid arguments — ")
    assert "cmd" in result


@pytest.mark.asyncio
async def test_invalid_workdir_is_rendered_as_a_message() -> None:
    exc = InvalidManifestPathError(rel="../etc", reason="escape_root")
    wrapped = factory._wrap_exec_command(_raising_tool("exec_command", exc))

    result = await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"cmd": "ls"}))

    assert isinstance(result, str)
    assert "workdir must be a path inside /workspace" in result
    assert "'../etc'" in result


@pytest.mark.parametrize("field", ["exec_yield_ms", "write_stdin_poll_yield_ms"])
def test_shell_settings_reject_a_yield_above_the_pty_ceiling(field: str) -> None:
    """A yield the PTY layer would clamp is a misconfiguration, not a longer wait."""
    with pytest.raises(ValidationError):
        ShellSettings(**{field: PTY_YIELD_TIME_MS_MAX + 1})

    assert getattr(ShellSettings(**{field: PTY_YIELD_TIME_MS_MAX}), field) == PTY_YIELD_TIME_MS_MAX
