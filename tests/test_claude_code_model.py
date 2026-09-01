"""``_ClaudeCodeModel`` translation, routing, and subprocess transport."""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, ClassVar, cast

import pytest
from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from openai.types.responses import (
    ResponseCompletedEvent,
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from strix.config import claude_bridge, claude_code, claude_process, codex, loader
from strix.config.loader import load_settings
from strix.config.models import (
    StrixProvider,
    _ClaudeCodeModel,
    _NonStreamingModel,
    _request_timeout,
    _TurnGuardModel,
    uses_chat_completions_tool_schema,
)
from strix.report import dedupe
from strix.report import state as report_state


if TYPE_CHECKING:
    from collections.abc import Iterator

    from agents.tool import Tool


FIXTURES = Path(__file__).parent / "fixtures" / "claude_code"


def _message_text(message: dict[str, Any]) -> str:
    """The prose of a built turn, for assertions about what the model was told."""
    return "".join(
        block["text"] for block in message["message"]["content"] if block["type"] == "text"
    )


@pytest.fixture
def _reset_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in ("STRIX_LLM", "LLM_DISABLE_STREAMING", "STRIX_CLAUDE_CODE_MAX_PROCS"):
        monkeypatch.delenv(key, raising=False)
    loader._cached = None
    yield
    # load_settings() memoizes into loader._cached by direct assignment, which
    # monkeypatch does not track; reset it so a claude-code model doesn't leak
    # into an unrelated test's ReportState (which would then report $0 cost).
    loader._cached = None


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

    async def _fake_run_turn(slug: str, message: dict[str, Any], **_: Any) -> dict[str, Any]:
        assert slug == "claude-opus-4-8"
        assert "go" in _message_text(message)
        return event

    monkeypatch.setattr(claude_process, "run_turn", _fake_run_turn)
    model = _ClaudeCodeModel("claude-opus-4-8", reasoning_effort="high")

    events = asyncio.run(_drive(model))
    assert len(events) == 1
    assert isinstance(events[0], ResponseCompletedEvent)
    response = events[0].response
    message = response.output[0]
    assert isinstance(message, ResponseOutputMessage)
    block = message.content[0]
    assert isinstance(block, ResponseOutputText)
    assert block.text.startswith("Reconnaissance")
    # 1200 raw input + 29225 cache reads + 24303 cache writes, as _decode_usage folds them.
    assert response.usage is not None
    assert response.usage.input_tokens == 54_728


def _costs_recorded_for(monkeypatch: pytest.MonkeyPatch, fixture: str) -> list[float]:
    """Drive one turn off ``fixture`` and return what reached the cost ledger."""
    event = _result_event(fixture)
    recorded: list[float] = []

    class _Recorder:
        def record_observed_llm_cost(self, cost: float) -> None:
            recorded.append(cost)

    async def _fake_run_turn(
        _slug: str, _message: dict[str, Any], **_kwargs: Any
    ) -> dict[str, Any]:
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

    async def _fake_run_turn(_slug: str, _message: dict[str, Any], **_: Any) -> dict[str, Any]:
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
    calls = [i for i in response.output if isinstance(i, ResponseFunctionToolCall)]
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
    assert isinstance(model, _TurnGuardModel)
    assert isinstance(model._inner, _ClaudeCodeModel)


# --------------------------------------------------------------------------- #
# Subprocess transport
# --------------------------------------------------------------------------- #


# One built turn, reused by the transport tests: they exercise process handling,
# not encoding, and only need something run_turn can serialise.
_TURN: dict[str, Any] = {
    "type": "user",
    "message": {"role": "user", "content": [{"type": "text", "text": "prompt"}]},
}


def _completed(stdout: str, returncode: int, stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["claude"], returncode=returncode, stdout=stdout, stderr=stderr
    )


class _FakeProcess:
    """Stand-in for Popen: run_turn only needs poll()/kill() for its cleanup path.

    Defaults to already-exited, which is the state a real child is in once
    communicate() has returned, so the cleanup kill is a no-op on the happy path.
    """

    def __init__(self, *, running: bool = False, pid: int = 4321) -> None:
        self.killed = False
        self.pid = pid
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
    result = asyncio.run(claude_process.run_turn("claude-opus-4-8", _TURN))
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
    result = asyncio.run(claude_process.run_turn("claude-opus-4-8", _TURN))
    assert result["api_error_status"] == 429


def test_run_turn_nonzero_exit_with_no_result_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _completed("", 1, "boom on stderr"))
    with pytest.raises(claude_code.ClaudeCodeError, match="exited with code 1"):
        asyncio.run(claude_process.run_turn("claude-opus-4-8", _TURN))


def test_run_turn_no_result_event_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _completed('{"type": "system"}\n', 0))
    with pytest.raises(claude_code.ClaudeCodeError, match="no result event"):
        asyncio.run(claude_process.run_turn("claude-opus-4-8", _TURN))


def test_semaphore_reused_across_separate_event_loops(monkeypatch: pytest.MonkeyPatch) -> None:
    # Regression: `strix -n` runs warm-up and the scan in two separate
    # asyncio.run() loops. A single process-wide semaphore bound to the first
    # loop would fail in the second; the per-loop cache must isolate them.
    stdout = '{"type": "result", "is_error": false, "result": "{}"}\n'
    _patch_run(monkeypatch, _completed(stdout, 0))

    async def _one() -> dict[str, Any]:
        return await claude_process.run_turn("claude-opus-4-8", _TURN)

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
        asyncio.run(claude_process.run_turn("claude-opus-4-8", _TURN))


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
        task = asyncio.create_task(claude_process.run_turn("claude-opus-4-8", _TURN))
        assert await asyncio.to_thread(started.wait, 5.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(_cancel_mid_turn())
    assert process.killed is True


def test_missing_binary_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_code, "binary_path", lambda: None)
    with pytest.raises(claude_code.ClaudeCodeError, match="on PATH"):
        asyncio.run(claude_process.run_turn("claude-opus-4-8", _TURN))


def test_run_turn_works_under_selector_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    # Regression: on Windows Strix forces a SelectorEventLoop, which cannot spawn
    # subprocesses via asyncio. The threaded blocking call must still work.
    stdout = '{"type": "result", "is_error": false, "result": "{}"}\n'
    _patch_run(monkeypatch, _completed(stdout, 0))

    async def _drive_once() -> dict[str, Any]:
        return await claude_process.run_turn("claude-opus-4-8", _TURN)

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
        await asyncio.gather(*[claude_process.run_turn("claude-opus-4-8", _TURN) for _ in range(8)])

    asyncio.run(_run_all())
    assert peak <= 2


def test_turn_is_bounded_by_the_callers_request_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    # Every other route honours LLM_TIMEOUT. Without it a wedged turn burns the
    # transport's own generous default and is then retried, so one stuck turn
    # could hold a run for over an hour.
    event = _result_event("simple_text.jsonl")
    seen: dict[str, Any] = {}

    async def _fake_run_turn(_slug: str, _message: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs)
        return event

    monkeypatch.setattr(claude_process, "run_turn", _fake_run_turn)
    asyncio.run(
        _ClaudeCodeModel("claude-opus-4-8").get_response(
            "sys",
            [{"role": "user", "content": "go"}],
            ModelSettings(extra_args={"timeout": 42.0}),
            [],
            None,
            [],
            ModelTracing.DISABLED,
            previous_response_id=None,
            conversation_id=None,
            prompt=None,
        )
    )
    assert seen["timeout"] == 42.0


def test_turn_relays_parallel_tool_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    event = _result_event("simple_text.jsonl")
    prompts: list[str] = []

    async def _fake_run_turn(_slug: str, message: dict[str, Any], **_: Any) -> dict[str, Any]:
        prompts.append(_message_text(message))
        return event

    monkeypatch.setattr(claude_process, "run_turn", _fake_run_turn)

    class _Tool:
        name = "shell"
        description = "run a command"
        params_json_schema: ClassVar[dict[str, Any]] = {"type": "object", "properties": {}}

    async def _call(settings: ModelSettings) -> None:
        await _ClaudeCodeModel("claude-opus-4-8").get_response(
            "sys",
            [{"role": "user", "content": "go"}],
            settings,
            [cast("Tool", _Tool())],
            None,
            [],
            ModelTracing.DISABLED,
            previous_response_id=None,
            conversation_id=None,
            prompt=None,
        )

    asyncio.run(_call(ModelSettings(parallel_tool_calls=False)))
    asyncio.run(_call(ModelSettings(parallel_tool_calls=True)))
    assert "Request at most one tool" in prompts[0]
    assert "Request only tools you need" in prompts[1]


def test_turn_timeout_rejects_non_finite_values(monkeypatch: pytest.MonkeyPatch) -> None:
    # float("inf") passes a bare `> 0` test but reaches Popen.communicate() as an
    # OverflowError, which kills every turn with an error classified as nothing.
    monkeypatch.delenv("STRIX_CLAUDE_CODE_TIMEOUT", raising=False)
    assert claude_process._turn_timeout() == claude_process._DEFAULT_TURN_TIMEOUT_S
    assert claude_process._turn_timeout(42.0) == 42.0
    for bad in (float("inf"), float("nan"), 0.0, -5.0):
        assert claude_process._turn_timeout(bad) == claude_process._DEFAULT_TURN_TIMEOUT_S

    # The backend's own knob outranks the caller's request timeout; an unusable
    # value falls back to it rather than to the broken number.
    for raw, expected in (
        ("60", 60.0),
        ("inf", 120.0),
        ("nan", 120.0),
        ("1e999", 120.0),
        ("-1", 120.0),
        ("0", 120.0),
        ("banana", 120.0),
    ):
        monkeypatch.setenv("STRIX_CLAUDE_CODE_TIMEOUT", raw)
        assert claude_process._turn_timeout(120.0) == expected


def test_argv_asks_for_stream_json_input(monkeypatch: pytest.MonkeyPatch) -> None:
    # Images ride as content blocks, which only stream-json input can carry.
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")
    argv = claude_process._build_argv("claude-opus-4-8", [])
    assert argv[argv.index("--input-format") + 1] == "stream-json"
    assert argv[argv.index("--output-format") + 1] == "stream-json"


def test_stdin_carries_one_json_line() -> None:
    message = claude_bridge.build_message(None, "hello", [])
    encoded = claude_process._encode_message(message)
    assert encoded.endswith("\n")
    assert encoded.count("\n") == 1
    assert json.loads(encoded)["message"]["role"] == "user"


def test_result_line_survives_unicode_line_separators(monkeypatch: pytest.MonkeyPatch) -> None:
    # str.splitlines() also breaks on U+2028/U+2029/U+0085, which a model's own
    # prose puts inside the JSON result line, cutting it in two so nothing parses
    # and a turn that actually succeeded is reported as having no result event.
    text = "line one\u2028line two\u2029three\u0085four"
    event = {"type": "result", "is_error": False, "structured_output": {"text": text}}
    stdout = json.dumps(event, ensure_ascii=False) + "\n"
    assert len(stdout.splitlines()) > 1  # the bug this guards
    _patch_run(monkeypatch, _completed(stdout, 0))
    result = asyncio.run(claude_process.run_turn("claude-opus-4-8", _TURN))
    assert result["structured_output"]["text"] == text


def test_windows_kill_takes_the_whole_process_tree(monkeypatch: pytest.MonkeyPatch) -> None:
    # An npm install puts a claude.cmd shim on PATH, so the handle is cmd.exe and
    # killing it alone leaves the node grandchild holding the pipes.
    killed: list[list[str]] = []
    taskkill = "C:\\taskkill.exe"

    def _run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        killed.append(argv)
        return subprocess.CompletedProcess(args=argv, returncode=0)

    monkeypatch.setattr(claude_process, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(shutil, "which", lambda _name: taskkill)
    monkeypatch.setattr(subprocess, "run", _run)

    process = _FakeProcess(running=True, pid=4321)
    claude_process._kill_if_running(cast("subprocess.Popen[str]", process))
    assert killed == [[taskkill, "/F", "/T", "/PID", "4321"]]
    assert process.killed is True


def test_posix_kill_does_not_shell_out(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def _run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        return subprocess.CompletedProcess(args=argv, returncode=0)

    monkeypatch.setattr(claude_process, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(subprocess, "run", _run)
    process = _FakeProcess(running=True)
    claude_process._kill_if_running(cast("subprocess.Popen[str]", process))
    assert calls == []
    assert process.killed is True


def test_stdin_payload_is_one_line_whatever_the_prompt_contains() -> None:
    # The CLI reads stdin a line at a time. U+2028/U+2029/U+0085 passed through
    # as literals would split one message into four unparseable fragments, the
    # same hazard the transcript decoder guards on the way back.
    text = "one\u2028two\u2029three\u0085four \u00e9"
    encoded = claude_process._encode_message(claude_bridge.build_message(None, text, []))
    assert len(encoded.splitlines()) == 1
    assert encoded.endswith("\n")
    assert encoded.isascii()
    rendered = json.loads(encoded)["message"]["content"][0]["text"]
    assert text in rendered


def test_request_timeout_ignores_a_non_numeric_or_boolean_value() -> None:
    # bool is an int subclass, so a True would otherwise become a 1 second turn.
    for value in (True, False, "300", None, {"seconds": 300}):
        assert _request_timeout(ModelSettings(extra_args={"timeout": value})) is None
    assert _request_timeout(ModelSettings(extra_args={"timeout": 300})) == 300.0
    assert _request_timeout(ModelSettings()) is None


def test_deduplication_runs_on_this_backend_and_gets_its_json_back(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    # report/dedupe.py picks `(dedupe.model or "").strip() or settings.llm.model`, so with
    # STRIX_DEDUPE_MODEL unset -- the default -- deduplication runs on the main model, which
    # on a claude-code/ scan is this backend. It used to fail every check: the turn carried
    # the agent framing and the schema, so the model narrated a step and the caller's own
    # JSON was never found.
    monkeypatch.setenv("STRIX_LLM", "claude-code/claude-opus-4-8")
    monkeypatch.delenv("STRIX_DEDUPE_MODEL", raising=False)
    load_settings()

    answer = (
        '{"is_duplicate": true, "duplicate_id": "vuln-0001", '
        '"confidence": 0.93, "reason": "same endpoint"}'
    )
    seen: dict[str, Any] = {}

    async def _fake_run_turn(_slug: str, message: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        seen["prompt"] = _message_text(message)
        seen["structured"] = kwargs.get("structured")
        return {"type": "result", "is_error": False, "result": answer}

    monkeypatch.setattr(claude_process, "run_turn", _fake_run_turn)
    monkeypatch.setattr(dedupe, "get_global_report_state", lambda: None)

    result = asyncio.run(
        dedupe.check_duplicate(
            {"id": "vuln-0002", "title": "SQLi in /admin", "endpoint": "/admin"},
            [{"id": "vuln-0001", "title": "SQL injection in /admin", "endpoint": "/admin"}],
        )
    )

    assert "error" not in result
    assert result["is_duplicate"] is True
    assert result["duplicate_id"] == "vuln-0001"
    assert result["confidence"] == pytest.approx(0.93)
    # A tool-less turn must not be forced into the agent envelope, on the argv or in the prompt.
    assert seen["structured"] is False
    assert "Answer the request above directly" in seen["prompt"]
    assert "tool_calls" not in seen["prompt"]


def test_turns_run_on_their_own_thread_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    # A turn blocks a whole thread for its duration. asyncio's default executor is
    # sized min(32, cpu_count + 4), which on a 2-core host is six workers against a
    # default of eight concurrent turns, so sharing it would stall every other
    # asyncio.to_thread in Strix behind a model call.
    monkeypatch.setenv("STRIX_CLAUDE_CODE_MAX_PROCS", "3")
    names: list[str] = []

    def _record(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        names.append(threading.current_thread().name)
        return _completed('{"type":"result","is_error":false,"result":"ok"}', 0)

    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")
    monkeypatch.setattr(claude_process, "_spawn", lambda *_a, **_k: _FakeProcess())
    monkeypatch.setattr(claude_process, "_communicate", _record)

    async def _drive_many() -> None:
        loop = asyncio.get_running_loop()
        executor = claude_process._get_executor(loop)
        assert executor._max_workers == 3
        assert executor is not None
        await asyncio.gather(*[claude_process.run_turn("claude-opus-4-8", _TURN) for _ in range(4)])

    asyncio.run(_drive_many())
    assert names, "the turn never reached a worker thread"
    assert all(name.startswith("strix-claude-code") for name in names), names


def test_the_executor_is_resized_with_the_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _sizes() -> tuple[int, int]:
        loop = asyncio.get_running_loop()
        monkeypatch.setenv("STRIX_CLAUDE_CODE_MAX_PROCS", "2")
        first = claude_process._get_executor(loop)._max_workers
        monkeypatch.setenv("STRIX_CLAUDE_CODE_MAX_PROCS", "5")
        return first, claude_process._get_executor(loop)._max_workers

    assert asyncio.run(_sizes()) == (2, 5)
