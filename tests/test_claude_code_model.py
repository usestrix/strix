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

from strix.config import claude_bridge, claude_code, claude_process, codex, loader
from strix.config.loader import load_settings
from strix.config.models import (
    StrixProvider,
    _ClaudeCodeModel,
    _NonStreamingModel,
    _TurnGuardModel,
    uses_chat_completions_tool_schema,
)
from strix.report import state as report_state


if TYPE_CHECKING:
    from collections.abc import Iterator


FIXTURES = Path(__file__).parent / "fixtures" / "claude_code"


@pytest.fixture
def _reset_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in ("STRIX_LLM", "LLM_DISABLE_STREAMING", "STRIX_CLAUDE_CODE_MAX_PROCS"):
        monkeypatch.delenv(key, raising=False)
    loader._cached = None
    loader._override = None
    yield
    # load_settings() memoizes into loader._cached by direct assignment, which
    # monkeypatch does not track; reset it so a claude-code model doesn't leak
    # into an unrelated test's ReportState (which would then report $0 cost).
    loader._cached = None
    loader._override = None


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


def _result_event(fixture: str) -> dict[str, Any]:
    lines = (FIXTURES / fixture).read_text(encoding="utf-8").splitlines()
    return claude_bridge.parse_transcript(lines)


def test_stream_response_yields_one_completed_event(monkeypatch: pytest.MonkeyPatch) -> None:
    event = _result_event("simple_text.jsonl")

    async def _fake_run_turn(slug: str, prompt: str, **_: Any) -> dict[str, Any]:
        assert slug == "claude-opus-4-8"
        assert "go" in prompt
        return event

    monkeypatch.setattr(claude_process, "run_turn", _fake_run_turn)
    model = _ClaudeCodeModel("claude-opus-4-8", reasoning_effort="high")

    events = asyncio.run(_drive(model))
    assert len(events) == 1
    assert isinstance(events[0], ResponseCompletedEvent)
    response = events[0].response
    assert response.output[0].content[0].text.startswith("Reconnaissance")
    # 1200 raw input + 29225 cache reads + 24303 cache writes, as _decode_usage folds them.
    assert response.usage.input_tokens == 54_728


def _costs_recorded_for(monkeypatch: pytest.MonkeyPatch, fixture: str) -> list[float]:
    """Drive one turn off ``fixture`` and return what reached the cost ledger."""
    event = _result_event(fixture)
    recorded: list[float] = []

    class _Recorder:
        def record_observed_llm_cost(self, cost: float) -> None:
            recorded.append(cost)

    async def _fake_run_turn(_slug: str, _prompt: str, **_kwargs: Any) -> dict[str, Any]:
        return event

    monkeypatch.setattr(claude_process, "run_turn", _fake_run_turn)
    monkeypatch.setattr(report_state, "get_global_report_state", _Recorder)

    asyncio.run(_drive(_ClaudeCodeModel("claude-opus-4-8")))
    return recorded


def test_turn_hands_the_cli_reported_cost_to_the_ledger(monkeypatch: pytest.MonkeyPatch) -> None:
    # This backend never reaches LiteLLM, so litellm_cost_callback -- the hook every
    # metered route relies on -- never fires for it. Without this the ledger sees no
    # cost at all on an API-key session and the budget guard has nothing to stop.
    assert _costs_recorded_for(monkeypatch, "simple_text.jsonl") == [0.15]


def test_turn_records_nothing_when_the_cli_reports_no_cost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _costs_recorded_for(monkeypatch, "noisy.jsonl") == []


def test_get_response_returns_model_response(monkeypatch: pytest.MonkeyPatch) -> None:
    event = _result_event("tool_request.jsonl")

    async def _fake_run_turn(_slug: str, _prompt: str, **_: Any) -> dict[str, Any]:
        return event

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
    # plain function tools, i.e. chat-completions schema mode, not the native
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


def _completed(stdout: str, returncode: int, stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["claude"], returncode=returncode, stdout=stdout, stderr=stderr
    )


class _FakeProcess:
    """Stand-in for Popen: run_turn only needs poll()/kill() for its cleanup path.

    Defaults to already-exited, which is the state a real child is in once
    communicate() has returned, so the cleanup kill is a no-op on the happy path.
    """

    def __init__(self, *, running: bool = False) -> None:
        self.killed = False
        self._running = running

    def poll(self) -> int | None:
        return None if self._running else 0

    def kill(self) -> None:
        self.killed = True
        self._running = False


def _patch_run(
    monkeypatch: pytest.MonkeyPatch, completed: subprocess.CompletedProcess[str]
) -> None:
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")
    monkeypatch.setattr(claude_process, "_spawn", lambda *_a, **_k: _FakeProcess())
    monkeypatch.setattr(claude_process, "_communicate", lambda *_a, **_k: completed)


def test_argv_carries_the_schema_only_for_agent_turns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")
    assert "--json-schema" in claude_process._build_argv("claude-opus-4-8", [])
    assert "--json-schema" not in claude_process._build_argv(
        "claude-opus-4-8", [], structured=False
    )


def test_toolless_turn_requests_an_unstructured_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    # tools=[] means a one-shot completion (dedupe, preflight): the caller parses
    # the reply itself, so the envelope must not be forced onto it.
    seen: list[bool] = []

    async def _fake_run_turn(_slug: str, _prompt: str, **kwargs: Any) -> dict[str, Any]:
        seen.append(bool(kwargs.get("structured")))
        return {"is_error": False, "result": "OK"}

    monkeypatch.setattr(claude_process, "run_turn", _fake_run_turn)
    model = _ClaudeCodeModel("claude-opus-4-8")

    asyncio.run(_drive(model))  # _drive passes tools=[]
    assert seen == [False]


def test_run_turn_returns_result_event(monkeypatch: pytest.MonkeyPatch) -> None:
    stdout = (
        '{"type": "system", "subtype": "init"}\n'
        '{"type": "result", "subtype": "success", "is_error": false, "result": "{}"}\n'
    )
    _patch_run(monkeypatch, _completed(stdout, 0))
    result = asyncio.run(claude_process.run_turn("claude-opus-4-8", "prompt"))
    assert result["type"] == "result"
    assert result["is_error"] is False


def test_run_turn_returns_error_result_even_on_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A rate-limited turn may exit non-zero while still emitting an error result
    # line; run_turn must surface that line so the model layer can tag the 429 as
    # retryable, rather than raising an unclassified generic error.
    stdout = '{"type": "result", "is_error": true, "api_error_status": 429, "result": "429"}\n'
    _patch_run(monkeypatch, _completed(stdout, 1, "rate limited"))
    result = asyncio.run(claude_process.run_turn("claude-opus-4-8", "prompt"))
    assert result["api_error_status"] == 429


def test_run_turn_nonzero_exit_with_no_result_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _completed("", 1, "boom on stderr"))
    with pytest.raises(claude_code.ClaudeCodeError, match="exited with code 1"):
        asyncio.run(claude_process.run_turn("claude-opus-4-8", "prompt"))


def test_run_turn_no_result_event_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _completed('{"type": "system"}\n', 0))
    with pytest.raises(claude_code.ClaudeCodeError, match="no result event"):
        asyncio.run(claude_process.run_turn("claude-opus-4-8", "prompt"))


def test_semaphore_reused_across_separate_event_loops(monkeypatch: pytest.MonkeyPatch) -> None:
    # Regression: `strix -n` runs warm-up and the scan in two separate
    # asyncio.run() loops. A single process-wide semaphore bound to the first
    # loop would fail in the second; the per-loop cache must isolate them.
    stdout = '{"type": "result", "is_error": false, "result": "{}"}\n'
    _patch_run(monkeypatch, _completed(stdout, 0))

    async def _one() -> dict[str, Any]:
        return await claude_process.run_turn("claude-opus-4-8", "prompt")

    first = asyncio.run(_one())
    second = asyncio.run(_one())  # separate loop; must not raise
    assert first["type"] == "result"
    assert second["type"] == "result"


def test_run_turn_timeout_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")

    def _boom(*_a: Any, **_k: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd="claude", timeout=1.0)

    monkeypatch.setattr(claude_process, "_spawn", lambda *_a, **_k: _FakeProcess())
    monkeypatch.setattr(claude_process, "_communicate", _boom)
    with pytest.raises(claude_code.ClaudeCodeError, match="timed out"):
        asyncio.run(claude_process.run_turn("claude-opus-4-8", "prompt"))


def test_cancelled_turn_kills_the_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    # asyncio.to_thread cannot be cancelled: the worker thread runs to completion
    # regardless. An abandoned turn (outer timeout, budget stop, wind-down) releases
    # its semaphore slot immediately, so without an explicit kill the `claude` child
    # outlives it -- still spending subscription quota, and letting real concurrency
    # exceed STRIX_CLAUDE_CODE_MAX_PROCS precisely when turns are being abandoned.
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")
    process = _FakeProcess(running=True)
    started = threading.Event()

    def _blocks_until_killed(*_a: Any, **_k: Any) -> subprocess.CompletedProcess[str]:
        started.set()
        # Mirrors the real transport: communicate() returns once the child dies.
        deadline = time.monotonic() + 5.0
        while not process.killed and time.monotonic() < deadline:
            time.sleep(0.01)
        return _completed("", 0)

    monkeypatch.setattr(claude_process, "_spawn", lambda *_a, **_k: process)
    monkeypatch.setattr(claude_process, "_communicate", _blocks_until_killed)

    async def _cancel_mid_turn() -> None:
        task = asyncio.create_task(claude_process.run_turn("claude-opus-4-8", "prompt"))
        assert await asyncio.to_thread(started.wait, 5.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(_cancel_mid_turn())
    assert process.killed is True


def test_missing_binary_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_code, "binary_path", lambda: None)
    with pytest.raises(claude_code.ClaudeCodeError, match="on PATH"):
        asyncio.run(claude_process.run_turn("claude-opus-4-8", "prompt"))


def test_run_turn_works_under_selector_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    # Regression: on Windows Strix forces a SelectorEventLoop, which cannot spawn
    # subprocesses via asyncio. The threaded blocking call must still work.
    stdout = '{"type": "result", "is_error": false, "result": "{}"}\n'
    _patch_run(monkeypatch, _completed(stdout, 0))

    async def _drive_once() -> dict[str, Any]:
        return await claude_process.run_turn("claude-opus-4-8", "prompt")

    loop = asyncio.SelectorEventLoop()
    try:
        result = loop.run_until_complete(_drive_once())
    finally:
        loop.close()
    assert result["type"] == "result"


def test_semaphore_bounds_concurrency(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_CLAUDE_CODE_MAX_PROCS", "2")
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

    monkeypatch.setattr(claude_process, "_spawn", lambda *_a, **_k: _FakeProcess())
    monkeypatch.setattr(claude_process, "_communicate", _slow)

    async def _run_all() -> None:
        await asyncio.gather(*[claude_process.run_turn("claude-opus-4-8", "p") for _ in range(8)])

    asyncio.run(_run_all())
    assert peak <= 2
