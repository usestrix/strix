"""Tests for provider-agnostic conversation compaction."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest
from litellm.exceptions import BadRequestError, ContextWindowExceededError, RateLimitError
from openai.types.responses import ResponseOutputMessage, ResponseOutputText

from strix.config import ContextSettings
from strix.llm import compaction


if TYPE_CHECKING:
    from agents.memory.session_settings import SessionSettings


class FakeSession:
    """Minimal in-memory Session for exercising compaction."""

    session_id = "fake"
    session_settings: SessionSettings | None = None

    def __init__(self, items: list[Any]) -> None:
        self._items = list(items)

    async def get_items(self, limit: int | None = None) -> list[Any]:
        return list(self._items) if limit is None else list(self._items[-limit:])

    async def add_items(self, items: list[Any]) -> None:
        self._items.extend(items)

    async def clear_session(self) -> None:
        self._items = []

    async def pop_item(self) -> Any:
        return self._items.pop() if self._items else None


def _user(text: str) -> dict[str, Any]:
    return {"role": "user", "content": text}


def _assistant(text: str) -> dict[str, Any]:
    return {"role": "assistant", "content": text}


def _call(call_id: str, name: str = "exec_command") -> dict[str, Any]:
    return {"type": "function_call", "call_id": call_id, "name": name, "arguments": "{}"}


def _output(call_id: str, text: str = "done") -> dict[str, Any]:
    return {"type": "function_call_output", "call_id": call_id, "output": text}


def _turns(n: int) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for i in range(n):
        items += [
            _user(f"task {i}"),
            _call(f"c{i}"),
            _output(f"c{i}", f"result {i}"),
            _assistant(f"ok {i}"),
        ]
    return items


def _has_orphan_tool_output(items: list[Any]) -> bool:
    call_ids = {i["call_id"] for i in items if compaction._is_tool_call(i)}
    return any(i["call_id"] not in call_ids for i in items if compaction._is_tool_output(i))


def test_is_context_overflow_uses_litellm_typed_error() -> None:
    overflow = ContextWindowExceededError(
        message="context length exceeded", model="m", llm_provider="openai"
    )
    assert compaction.is_context_overflow(overflow)
    assert not compaction.is_context_overflow(
        RateLimitError(message="slow down", model="m", llm_provider="openai")
    )
    assert not compaction.is_context_overflow(RuntimeError("maximum context length is 8192"))


def test_is_context_overflow_matches_untyped_openrouter_400() -> None:
    # OpenRouter overflows arrive as a plain BadRequestError, so match the message.
    openrouter = BadRequestError(
        message=(
            "litellm.BadRequestError: This endpoint's maximum context length is 16385 "
            "tokens. However, you requested about 75064 tokens. Please reduce the length "
            "of the messages."
        ),
        model="openrouter/openai/gpt-3.5-turbo",
        llm_provider="openrouter",
    )
    assert compaction.is_context_overflow(openrouter)


def test_is_context_overflow_ignores_rate_limit_shaped_bad_request() -> None:
    # A 400 that is really throttling must never be treated as an overflow.
    throttled = BadRequestError(
        message="Rate limit exceeded, please slow down",
        model="openrouter/openai/gpt-4o",
        llm_provider="openrouter",
    )
    assert not compaction.is_context_overflow(throttled)
    unrelated = BadRequestError(
        message="Invalid value for 'temperature'", model="m", llm_provider="openrouter"
    )
    assert not compaction.is_context_overflow(unrelated)


def test_select_split_never_orphans_tool_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compaction, "count_tokens", lambda _m, t: len(t))
    items = _turns(10)
    split = compaction._select_split("m", items, keep_tokens=25)
    recent = items[split:]
    assert recent  # something is kept
    assert not _has_orphan_tool_output(recent)


def test_select_split_handles_parallel_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compaction, "count_tokens", lambda _m, _t: 1)
    # Two parallel calls then their two outputs.
    items = [
        _user("start"),
        _call("a"),
        _call("b"),
        _output("a"),
        _output("b"),
        _assistant("done"),
    ]
    # keep_tokens picks a boundary that would land between the calls/outputs.
    split = compaction._select_split("m", items, keep_tokens=2)
    assert not _has_orphan_tool_output(items[split:])


def _patch_budget(monkeypatch: pytest.MonkeyPatch, *, keep_tokens: int, window: int) -> None:
    monkeypatch.setattr(compaction, "count_tokens", lambda _m, t: len(t))
    monkeypatch.setattr(compaction, "context_window", lambda _m: window)
    monkeypatch.setattr(compaction, "output_limit", lambda _m: 0)
    context = ContextSettings()
    context.keep_tokens = keep_tokens
    context.compact_buffer_tokens = 0
    context.summary_max_tokens = 64
    context.auto_compact = True
    settings = SimpleNamespace(
        context=context,
        llm=SimpleNamespace(api_key=None, api_base=None, timeout=1, extra_headers=None),
    )
    monkeypatch.setattr(compaction, "load_settings", lambda: settings)


def _model_response(text: str) -> Any:
    chunk = ResponseOutputText(annotations=[], text=text, type="output_text")
    message = ResponseOutputMessage(
        id="msg", content=[chunk], role="assistant", status="completed", type="message"
    )
    return SimpleNamespace(output=[message])


def _patch_summary(
    monkeypatch: pytest.MonkeyPatch, text: str, captured: dict[str, Any] | None = None
) -> None:
    class FakeModel:
        async def get_response(self, **kwargs: Any) -> Any:
            if captured is not None:
                captured.update(kwargs)
            return _model_response(text)

    class FakeProvider:
        def get_model(self, model_name: str | None) -> Any:
            if captured is not None:
                captured["model"] = model_name
            return FakeModel()

    monkeypatch.setattr(compaction, "StrixProvider", FakeProvider)


@pytest.mark.asyncio
async def test_maybe_compact_noop_when_within_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_budget(monkeypatch, keep_tokens=50, window=1_000_000)
    session = FakeSession(_turns(10))
    before = await session.get_items()

    assert await compaction.maybe_compact(session, model="m") is False
    assert await session.get_items() == before


@pytest.mark.asyncio
async def test_maybe_compact_rewrites_and_keeps_pairs(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_budget(monkeypatch, keep_tokens=30, window=4_000)
    _patch_summary(monkeypatch, "SUMMARY BODY")
    session = FakeSession(_turns(12))

    assert await compaction.maybe_compact(session, model="m", force=True) is True

    items = await session.get_items()
    assert items[0]["role"] == "user"
    assert items[0]["content"].startswith(compaction._CHECKPOINT_TAG)
    assert "SUMMARY BODY" in items[0]["content"]
    assert len(items) < len(_turns(12))
    assert not _has_orphan_tool_output(items)


@pytest.mark.asyncio
async def test_maybe_compact_updates_previous_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    # Window large enough to leave real room for the summary instructions.
    _patch_budget(monkeypatch, keep_tokens=30, window=4_000)
    captured: dict[str, Any] = {}
    _patch_summary(monkeypatch, "NEW", captured)

    prior = compaction._checkpoint_item("OLD SUMMARY TEXT")
    session = FakeSession([prior, *_turns(12)])

    assert await compaction.maybe_compact(session, model="m", force=True) is True
    assert "OLD SUMMARY TEXT" in captured["input"]


@pytest.mark.asyncio
async def test_summarize_routes_through_provider_with_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_budget(monkeypatch, keep_tokens=30, window=4_000)
    monkeypatch.setattr(
        compaction,
        "load_settings",
        lambda: SimpleNamespace(
            llm=SimpleNamespace(
                api_key=None, api_base=None, timeout=1, extra_headers={"X-Feature-Key": "svc"}
            )
        ),
    )
    captured: dict[str, Any] = {}
    _patch_summary(monkeypatch, "S", captured)

    assert await compaction._summarize("litellm/openai/some-model", "p", 64) == "S"
    assert captured["model"] == "litellm/openai/some-model"
    settings = captured["model_settings"]
    assert settings.extra_headers == {"X-Feature-Key": "svc"}
    assert settings.max_tokens == 64


def test_fit_to_tokens_truncates_oversized_text(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compaction, "count_tokens", lambda _m, t: len(t))
    text = "x" * 10_000

    fitted = compaction._fit_to_tokens("m", text, 500)

    assert len(fitted) <= 500
    assert compaction._HEAD_TRUNCATED_MARKER in fitted
    # Small text is returned untouched.
    assert compaction._fit_to_tokens("m", "short", 500) == "short"


def test_summary_output_tokens_capped_at_model_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    context = ContextSettings()
    monkeypatch.setattr(compaction, "load_settings", lambda: SimpleNamespace(context=context))

    monkeypatch.setattr(compaction, "output_limit", lambda _m: 1_000)
    context.summary_max_tokens = 4_096
    # Configured allowance above the model cap is clamped down to the cap.
    assert compaction._summary_output_tokens("m") == 1_000
    # Below the cap, the configured value is used unchanged.
    context.summary_max_tokens = 500
    assert compaction._summary_output_tokens("m") == 500


@pytest.mark.asyncio
async def test_maybe_compact_bounds_summary_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    # A tiny window with a huge head must not send an oversized summary request.
    _patch_budget(monkeypatch, keep_tokens=30, window=4_000)
    captured: dict[str, Any] = {}
    _patch_summary(monkeypatch, "S", captured)
    big_turns = [{"role": "user", "content": "y" * 2_000} for _ in range(50)]
    session = FakeSession(big_turns)

    assert await compaction.maybe_compact(session, model="m") is True
    # count_tokens==len(chars); prompt must fit the model window.
    assert len(captured["input"]) <= 4_000


@pytest.mark.asyncio
async def test_summary_request_fits_when_room_is_below_old_floor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Head-input budget must shrink to the real room so the request fits.
    instructions = len(compaction._SUMMARY_INSTRUCTIONS)
    window = instructions + 64 + 256 + 300  # summary_max(64)+slack(256)+room(300)
    _patch_budget(monkeypatch, keep_tokens=30, window=window)
    captured: dict[str, Any] = {}
    _patch_summary(monkeypatch, "S", captured)
    session = FakeSession([{"role": "user", "content": "y" * 5_000} for _ in range(20)])

    assert await compaction.maybe_compact(session, model="m") is True
    assert len(captured["input"]) <= window


@pytest.mark.asyncio
async def test_maybe_compact_skips_when_summary_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_budget(monkeypatch, keep_tokens=30, window=4_000)

    class BoomModel:
        async def get_response(self, **_kwargs: Any) -> Any:
            raise RuntimeError("boom")

    class BoomProvider:
        def get_model(self, _model_name: str | None) -> Any:
            return BoomModel()

    monkeypatch.setattr(compaction, "StrixProvider", BoomProvider)
    session = FakeSession(_turns(12))
    before = await session.get_items()

    assert await compaction.maybe_compact(session, model="m", force=True) is False
    assert await session.get_items() == before


@pytest.mark.asyncio
async def test_maybe_compact_skips_when_no_room_to_summarise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No room for any head -> no (doomed) summary is attempted.
    _patch_budget(monkeypatch, keep_tokens=30, window=200)
    captured: dict[str, Any] = {}
    _patch_summary(monkeypatch, "S", captured)
    session = FakeSession(_turns(12))
    before = await session.get_items()

    assert await compaction.maybe_compact(session, model="m", force=True) is False
    assert not captured
    assert await session.get_items() == before
