"""Tests for forcing tty=true on exec_command on Windows (GH issue #727).

On native Windows, docker-py talks to Docker Desktop over a named pipe
(``NpipeSocket``). exec_command's non-tty path demultiplexes stdout/stderr
with a blocking 8-byte frame-header read (docker.utils.socket.frames_iter_no_tty);
over the named-pipe transport this routinely returns no data within the
tool's yield window, so commands hang with empty output. The tty path
(frames_iter_tty) is a single raw read and unaffected. Reproduced directly
against the pinned SDK on a real Windows 11 + Docker Desktop host: tty=True
returned real output instantly, tty=False (the exec_command default)
returned empty output with no exception.
"""

from __future__ import annotations

import json
import sys
from typing import Any, cast

import pytest

from strix.agents import factory


@pytest.fixture(autouse=True)
def _clear_force_tty_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deterministic tests must not inherit a dev machine's env override."""
    monkeypatch.delenv("STRIX_EXEC_FORCE_TTY", raising=False)


def _fake_tool(captured: dict[str, str]) -> Any:
    async def on_invoke_tool(_ctx: Any, raw_input: str) -> str:
        captured["raw_input"] = raw_input
        return "ok"

    class _Tool:
        name = "exec_command"

    tool = _Tool()
    tool.on_invoke_tool = on_invoke_tool  # type: ignore[attr-defined]
    return tool


def test_force_exec_tty_injects_true_when_absent() -> None:
    result = factory._force_exec_tty(json.dumps({"cmd": "ls"}))
    assert json.loads(result) == {"cmd": "ls", "tty": True}


def test_force_exec_tty_overrides_explicit_false() -> None:
    result = factory._force_exec_tty(json.dumps({"cmd": "ls", "tty": False}))
    assert json.loads(result)["tty"] is True


def test_force_exec_tty_leaves_malformed_json_untouched() -> None:
    assert factory._force_exec_tty("not json") == "not json"


def test_force_exec_tty_leaves_non_dict_json_untouched() -> None:
    raw = json.dumps(["cmd", "ls"])
    assert factory._force_exec_tty(raw) == raw


@pytest.mark.asyncio
async def test_wrap_exec_command_forces_tty_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_fake_tool(captured))

    result = await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"cmd": "echo test"}))

    assert result == "ok"
    assert json.loads(captured["raw_input"]) == {"cmd": "echo test", "tty": True}


@pytest.mark.asyncio
async def test_wrap_exec_command_does_not_force_tty_on_linux(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_fake_tool(captured))

    await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"cmd": "echo test"}))

    assert json.loads(captured["raw_input"]) == {"cmd": "echo test"}


@pytest.mark.asyncio
async def test_wrap_exec_command_respects_explicit_tty_false_on_linux(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_fake_tool(captured))

    await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"cmd": "echo test", "tty": False}))

    assert json.loads(captured["raw_input"])["tty"] is False


def test_should_force_exec_tty_defaults_true_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    assert factory._should_force_exec_tty() is True


def test_should_force_exec_tty_defaults_false_on_linux(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert factory._should_force_exec_tty() is False


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_should_force_exec_tty_env_var_forces_on_non_windows(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("STRIX_EXEC_FORCE_TTY", value)
    assert factory._should_force_exec_tty() is True


@pytest.mark.parametrize("value", ["0", "false", "FALSE", "no", "off"])
def test_should_force_exec_tty_env_var_forces_off_on_windows(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("STRIX_EXEC_FORCE_TTY", value)
    assert factory._should_force_exec_tty() is False


@pytest.mark.asyncio
async def test_wrap_exec_command_env_var_disables_force_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("STRIX_EXEC_FORCE_TTY", "0")
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_fake_tool(captured))

    await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"cmd": "echo test"}))

    assert json.loads(captured["raw_input"]) == {"cmd": "echo test"}
