"""``_ClaudeCodeModel`` translation, routing, and subprocess transport."""

from __future__ import annotations

import asyncio
import subprocess
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from openai.types.responses import ResponseCompletedEvent

from strix.config import claude_code, claude_process, codex, loader
from strix.config.loader import load_settings
from strix.config.models import (
    StrixProvider,
    _ClaudeCodeModel,
    _NonStreamingModel,
    _TurnGuardModel,
    uses_chat_completions_tool_schema,
)


if TYPE_CHECKING:
    from collections.abc import Iterator


FIXTURES = Path(__file__).parent / "fixtures" / "claude_code"


@pytest.fixture
def _reset_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in ("STRIX_LLM", "LLM_DISABLE_STREAMING", "STRIX_CLAUDE_CODE_MAX_PROCS"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)
    yield


async def _drive(model: _ClaudeCodeModel) -> list[Any]:
    return [
        event
        async for event in model.stream_response(
            "sys",
            [{"role": "user", "content": "go"}],
            model_settings=ModelSettings(),
            tools=[],
            output_schema=None,
            handoffs=[],
            tracing=ModelTracing.DISABLED,
            previous_response_id=None,
            conversation_id=None,
            prompt=None,
        )
    ]


def test_stream_response_yields_one_completed_event(monkeypatch: pytest.MonkeyPatch) -> None:
    result_line = (FIXTURES / "simple_text.jsonl").read_text(encoding="utf-8").splitlines()[-1]

    async def _fake_run_turn(slug: str, prompt: str, **_: Any) -> str:
        assert slug == "claude-opus-4-8"
        assert "go" in prompt
        return result_line

    monkeypatch.setattr(claude_process, "run_turn", _fake_run_turn)
    model = _ClaudeCodeModel("claude-opus-4-8", reasoning_effort="high")

    events = asyncio.run(_drive(model))
    assert len(events) == 1
    assert isinstance(events[0], ResponseCompletedEvent)
    response = events[0].response
    assert response.output[0].content[0].text.startswith("Reconnaissance")
    assert response.usage.input_tokens == 1200


def test_get_response_returns_model_response(monkeypatch: pytest.MonkeyPatch) -> None:
    result_line = (FIXTURES / "tool_request.jsonl").read_text(encoding="utf-8").splitlines()[-1]

    async def _fake_run_turn(_slug: str, _prompt: str, **_: Any) -> str:
        return result_line

    monkeypatch.setattr(claude_process, "run_turn", _fake_run_turn)
    model = _ClaudeCodeModel("claude-opus-4-8")

    response = asyncio.run(
        model.get_response(
            "sys",
            [{"role": "user", "content": "go"}],
            ModelSettings(),
            [],
            None,
            [],
            ModelTracing.DISABLED,
            previous_response_id=None,
            conversation_id=None,
            prompt=None,
        )
    )
    calls = [i for i in response.output if getattr(i, "type", None) == "function_call"]
    assert [c.name for c in calls] == ["shell", "browser"]


def test_reasoning_effort_becomes_extra_args() -> None:
    model = _ClaudeCodeModel("claude-opus-4-8", reasoning_effort="max")
    assert model._extra_args() == ["--effort", "max"]
    assert model.model == "claude-code/claude-opus-4-8"


# --------------------------------------------------------------------------- #
# Routing
# --------------------------------------------------------------------------- #


def test_get_model_routes_claude_code(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    monkeypatch.setenv("STRIX_LLM", "claude-code/claude-opus-4-8")
    monkeypatch.setenv("LLM_DISABLE_STREAMING", "true")
    load_settings()

    model = StrixProvider().get_model("claude-code/claude-opus-4-8")
    assert isinstance(model, _TurnGuardModel)
    assert isinstance(model._inner, _ClaudeCodeModel)
    # Subscription backends are never wrapped in the non-streaming shim.
    assert not isinstance(model._inner, _NonStreamingModel)


def test_get_model_leaves_api_key_path_untouched(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    sentinel = object()
    monkeypatch.setattr("strix.config.models.MultiProvider.get_model", lambda *_: sentinel)
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-8")
    load_settings()

    model = StrixProvider().get_model("anthropic/claude-opus-4-8")
    assert isinstance(model, _TurnGuardModel)
    assert model._inner is sentinel


def test_claude_code_uses_json_function_tools() -> None:
    # The bridge renders tools as JSON function schemas and reads back
    # {name, arguments}, so special tool types (apply_patch) must be converted to
    # plain function tools — i.e. chat-completions schema mode, not the native
    # Responses path the ChatGPT backend uses.
    settings = load_settings()
    assert uses_chat_completions_tool_schema("claude-code/claude-opus-4-8", settings) is True
    assert uses_chat_completions_tool_schema("chatgpt/gpt-5.4", settings) is False


def test_claude_code_takes_priority_over_codex(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    # If both resolvers somehow matched, the claude-code branch wins.
    monkeypatch.setattr(codex, "subscription_model", lambda *_: "gpt-5.5")
    monkeypatch.setenv("STRIX_LLM", "claude-code/claude-opus-4-8")
    load_settings()

    model = StrixProvider().get_model("claude-code/claude-opus-4-8")
    assert isinstance(model._inner, _ClaudeCodeModel)


# --------------------------------------------------------------------------- #
# Subprocess transport
# --------------------------------------------------------------------------- #


def test_extract_result_line_picks_the_result() -> None:
    lines = [
        "Shell cwd was reset to C:\\dev",
        '{"type": "system", "subtype": "init"}',
        "not json",
        '{"type": "assistant", "message": {}}',
        '{"type": "result", "subtype": "success", "is_error": false}',
    ]
    line = claude_process._extract_result_line("\n".join(lines))
    assert line is not None
    assert '"type": "result"' in line


def _completed(stdout: str, returncode: int, stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["claude"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def _patch_run(
    monkeypatch: pytest.MonkeyPatch, completed: subprocess.CompletedProcess[str]
) -> None:
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")
    monkeypatch.setattr(claude_process, "_run_blocking", lambda *_a, **_k: completed)


def test_run_turn_returns_result_line(monkeypatch: pytest.MonkeyPatch) -> None:
    stdout = (
        '{"type": "system", "subtype": "init"}\n'
        '{"type": "result", "subtype": "success", "is_error": false, "result": "{}"}\n'
    )
    _patch_run(monkeypatch, _completed(stdout, 0))
    line = asyncio.run(claude_process.run_turn("claude-opus-4-8", "prompt"))
    assert '"type": "result"' in line


def test_run_turn_nonzero_exit_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _completed("", 1, "boom on stderr"))
    with pytest.raises(claude_code.ClaudeCodeError, match="exited with code 1"):
        asyncio.run(claude_process.run_turn("claude-opus-4-8", "prompt"))


def test_run_turn_no_result_line_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _completed('{"type": "system"}\n', 0))
    with pytest.raises(claude_code.ClaudeCodeError, match="no result line"):
        asyncio.run(claude_process.run_turn("claude-opus-4-8", "prompt"))


def test_run_turn_timeout_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")

    def _boom(*_a: Any, **_k: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd="claude", timeout=1.0)

    monkeypatch.setattr(claude_process, "_run_blocking", _boom)
    with pytest.raises(claude_code.ClaudeCodeError, match="timed out"):
        asyncio.run(claude_process.run_turn("claude-opus-4-8", "prompt"))


def test_missing_binary_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_code, "binary_path", lambda: None)
    with pytest.raises(claude_code.ClaudeCodeError, match="on PATH"):
        asyncio.run(claude_process.run_turn("claude-opus-4-8", "prompt"))


def test_run_turn_works_under_selector_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    # Regression: on Windows Strix forces a SelectorEventLoop, which cannot spawn
    # subprocesses via asyncio. The threaded blocking call must still work.
    stdout = '{"type": "result", "is_error": false, "result": "{}"}\n'
    _patch_run(monkeypatch, _completed(stdout, 0))

    async def _drive_once() -> str:
        return await claude_process.run_turn("claude-opus-4-8", "prompt")

    loop = asyncio.SelectorEventLoop()
    try:
        line = loop.run_until_complete(_drive_once())
    finally:
        loop.close()
    assert '"type": "result"' in line


def test_semaphore_bounds_concurrency(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_CLAUDE_CODE_MAX_PROCS", "2")
    monkeypatch.setitem(claude_process._sem_state, "semaphore", None)
    monkeypatch.setitem(claude_process._sem_state, "size", None)
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")

    lock = threading.Lock()
    live = 0
    peak = 0

    def _slow(*_a: Any, **_k: Any) -> subprocess.CompletedProcess[str]:
        nonlocal live, peak
        with lock:
            live += 1
            peak = max(peak, live)
        time.sleep(0.02)
        with lock:
            live -= 1
        return _completed('{"type": "result", "is_error": false, "result": "{}"}\n', 0)

    monkeypatch.setattr(claude_process, "_run_blocking", _slow)

    async def _run_all() -> None:
        await asyncio.gather(*[claude_process.run_turn("claude-opus-4-8", "p") for _ in range(8)])

    asyncio.run(_run_all())
    assert peak <= 2
