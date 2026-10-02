"""Repetition warnings reach native agents without blocking testing or process polling."""

from __future__ import annotations

import json
from typing import Any

import pytest
from agents import Agent
from agents.tool_context import ToolContext

from strix.fix import PreparationState
from strix.fix.runtime import _FixHooks
from tests.test_fix_completion import ScriptedModel, finish, patch, scenario, shell, suite_commands
from tests.test_fix_reliability import environment


@pytest.mark.asyncio
async def test_repeated_native_command_warns_then_agent_can_finish(tmp_path, monkeypatch):
    # Interleaved commands and different SDK chunk IDs must not hide the repeated read.
    repeated = [
        shell("cat app.py"),
        shell("pwd"),
        shell("cat app.py"),
        shell("ls tests"),
        shell("cat app.py"),
    ]
    model = ScriptedModel([*patch(), *repeated, *suite_commands(), finish("done")])
    result, _ = await scenario(tmp_path, monkeypatch, model)
    assert result.state is PreparationState.READY, result.model_dump_json()
    assert any("[Repeated command]" in json.dumps(turn) for turn in model.inputs["repair"])
    # The warning does not rewrite command evidence or replace required test execution.
    assert all(check.exit_code == 0 for check in result.checks)
    assert all("Ran 1 test" in check.output for check in result.checks[-2:])


async def tool_result(
    hooks: _FixHooks,
    tool: str = "exec_command",
    *,
    output: str = "unchanged",
    code: int | None = 0,
    workdir: str | None = None,
    session_id: int = 42,
) -> None:
    arguments: dict[str, Any] = {"cmd": "cat state.txt", "workdir": workdir}
    if tool == "write_stdin":
        arguments = {"session_id": session_id, "chars": ""}
    context = ToolContext(
        context={"agent_id": "repair"},
        tool_name=tool,
        tool_call_id="call",
        tool_arguments=json.dumps(arguments),
    )
    state = (
        f"Process exited with code {code}"
        if code is not None
        else f"Process running with session ID {session_id}"
    )
    result = f"Chunk ID: chunk\nWall time: 0.1 seconds\n{state}\nOutput:\n{output}"
    await hooks.on_tool_end(context, Agent(name="repair"), None, result)


@pytest.mark.asyncio
async def test_running_commands_and_polling_never_trigger_repetition(tmp_path):
    hooks = _FixHooks(environment(tmp_path / "repository", tmp_path))
    for _ in range(5):
        await tool_result(hooks, code=None)
        await tool_result(hooks, "write_stdin", code=None)
        await tool_result(hooks, "write_stdin", code=0)
    assert not hooks._repetition_warning
    assert len(hooks.environment.repair_checks) == 15


@pytest.mark.asyncio
async def test_changed_output_status_or_directory_is_not_repetition(tmp_path):
    hooks = _FixHooks(environment(tmp_path / "repository", tmp_path))
    for output, code, workdir in [
        ("old", 0, None),
        ("old", 0, None),
        ("new", 0, None),
        ("new", 0, None),
        ("old", 0, None),
        ("old", 0, None),
        ("old", 1, None),
        ("old", 1, None),
        ("old", 1, "/another-component"),
        ("old", 1, "/another-component"),
    ]:
        await tool_result(hooks, output=output, code=code, workdir=workdir)
        assert not hooks._repetition_warning


@pytest.mark.asyncio
async def test_native_patch_resets_repetition_before_revalidation(tmp_path):
    hooks = _FixHooks(environment(tmp_path / "repository", tmp_path))
    for _ in range(3):
        await tool_result(hooks)
    assert hooks._repetition_warning
    await tool_result(hooks, "apply_patch")
    for _ in range(2):
        await tool_result(hooks)
    assert not hooks._repetition_warning
