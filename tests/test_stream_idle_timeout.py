"""Tests for the model-stream idle watchdog.

A turn that streams a few tokens and then goes silent is not covered by the
request timeout: the read timeout resets on every byte, keepalives included.
The watchdog bounds the gap between events so the turn fails and can be
retried instead of parking the agent forever.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any

import pytest
from agents.model_settings import ModelSettings
from agents.models.interface import Model, ModelTracing
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from openai import AsyncOpenAI

from strix.config import loader
from strix.config.loader import load_settings
from strix.config.models import (
    ModelStreamTimeoutError,
    StrixProvider,
    _TurnGuardModel,
    _with_idle_timeout,
)


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator


_STALL_SECONDS = 30.0


def _chunk(text: str) -> bytes:
    payload = {
        "id": "chatcmpl-1",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "gw-model",
        "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}],
    }
    return b"data: " + json.dumps(payload).encode() + b"\n\n"


class _StallingHandler(BaseHTTPRequestHandler):
    """Streams a couple of tokens, then stops producing anything."""

    stop = threading.Event()

    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.write(_chunk("Now"))
        self.wfile.write(_chunk(" spawning"))
        self.wfile.flush()
        self.stop.wait(_STALL_SECONDS)


class _FirstEventStallingHandler(BaseHTTPRequestHandler):
    """Sends stream headers, then waits before sending the first event."""

    stop = threading.Event()

    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.flush()
        self.stop.wait(_STALL_SECONDS)


@pytest.fixture
def stalling_gateway() -> Iterator[str]:
    _StallingHandler.stop.clear()
    server = HTTPServer(("127.0.0.1", 0), _StallingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        _StallingHandler.stop.set()
        server.shutdown()
        server.server_close()


@pytest.fixture
def first_event_stalling_gateway() -> Iterator[str]:
    _FirstEventStallingHandler.stop.clear()
    server = HTTPServer(("127.0.0.1", 0), _FirstEventStallingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        _FirstEventStallingHandler.stop.set()
        server.shutdown()
        server.server_close()


def _stream(
    base_url: str,
    *,
    idle_timeout: float,
    first_event_timeout: float = 0.0,
) -> AsyncIterator[Any]:
    client = AsyncOpenAI(api_key="tok", base_url=base_url, max_retries=0, timeout=_STALL_SECONDS)
    inner: Model = OpenAIChatCompletionsModel(model="gw-model", openai_client=client)
    guarded = _TurnGuardModel(
        inner,
        stream_idle_timeout=idle_timeout,
        stream_first_event_timeout=first_event_timeout,
    )
    return guarded.stream_response(
        None,
        "go",
        ModelSettings(),
        [],
        None,
        [],
        ModelTracing.DISABLED,
        previous_response_id=None,
        conversation_id=None,
        prompt=None,
    )


async def _drain(
    base_url: str,
    *,
    idle_timeout: float,
    first_event_timeout: float = 0.0,
) -> list[Any]:
    return [
        event
        async for event in _stream(
            base_url,
            idle_timeout=idle_timeout,
            first_event_timeout=first_event_timeout,
        )
    ]


@pytest.mark.asyncio
async def test_stalled_stream_hangs_without_the_watchdog(stalling_gateway: str) -> None:
    # Repro: tokens arrive, then nothing. Un-watched, the turn just sits there;
    # the request timeout is far away and would reset on any keepalive byte.
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(_drain(stalling_gateway, idle_timeout=0), timeout=2)


@pytest.mark.asyncio
async def test_stalled_stream_is_abandoned_by_the_watchdog(stalling_gateway: str) -> None:
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="produced no event"):
        await _drain(stalling_gateway, idle_timeout=1)

    assert time.monotonic() - started < _STALL_SECONDS


@pytest.mark.asyncio
async def test_first_event_timeout_abandons_silent_stream(
    first_event_stalling_gateway: str,
) -> None:
    started = time.monotonic()
    with pytest.raises(ModelStreamTimeoutError, match="no first event within 1s"):
        await _drain(
            first_event_stalling_gateway,
            idle_timeout=10,
            first_event_timeout=1,
        )

    assert time.monotonic() - started < _STALL_SECONDS


@pytest.mark.asyncio
async def test_first_event_timeout_does_not_replace_idle_timeout(
    stalling_gateway: str,
) -> None:
    with pytest.raises(ModelStreamTimeoutError, match="produced no event for 1s"):
        await _drain(
            stalling_gateway,
            idle_timeout=1,
            first_event_timeout=10,
        )


@pytest.mark.asyncio
async def test_events_keep_flowing_while_the_stream_is_alive() -> None:
    async def _live() -> AsyncIterator[Any]:
        for i in range(5):
            await asyncio.sleep(0.05)
            yield f"event-{i}"

    seen: list[Any] = [event async for event in _with_idle_timeout(_live(), 1.0)]

    assert seen == [f"event-{i}" for i in range(5)]


@pytest.fixture
def _reset_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in (
        "STRIX_LLM",
        "LLM_DISABLE_STREAMING",
        "LLM_STREAM_IDLE_TIMEOUT",
        "LLM_STREAM_FIRST_EVENT_TIMEOUT",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)
    yield


class _DummyModel(Model):
    async def get_response(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError

    def stream_response(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError


def test_idle_timeout_is_configurable(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    monkeypatch.setattr("strix.config.models.MultiProvider.get_model", lambda *_: _DummyModel())
    monkeypatch.setenv("LLM_STREAM_IDLE_TIMEOUT", "45")
    load_settings()

    model = StrixProvider().get_model("openai/gpt-4o-mini")
    assert isinstance(model, _TurnGuardModel)
    assert model._stream_idle_timeout == 45
    assert model._stream_first_event_timeout == 0


def test_first_event_timeout_is_configurable(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    monkeypatch.setattr("strix.config.models.MultiProvider.get_model", lambda *_: _DummyModel())
    monkeypatch.setenv("LLM_STREAM_IDLE_TIMEOUT", "45")
    monkeypatch.setenv("LLM_STREAM_FIRST_EVENT_TIMEOUT", "12")
    load_settings()

    model = StrixProvider().get_model("openai/gpt-4o-mini")
    assert isinstance(model, _TurnGuardModel)
    assert model._stream_first_event_timeout == 12


def test_idle_timeout_is_off_without_streaming(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    # LLM_DISABLE_STREAMING turns the whole request into one event, so an idle
    # gap would just be the request duration — the request timeout bounds that.
    monkeypatch.setattr("strix.config.models.MultiProvider.get_model", lambda *_: _DummyModel())
    monkeypatch.setenv("LLM_STREAM_IDLE_TIMEOUT", "45")
    monkeypatch.setenv("LLM_DISABLE_STREAMING", "true")
    load_settings()

    model = StrixProvider().get_model("openai/gpt-4o-mini")
    assert isinstance(model, _TurnGuardModel)
    assert model._stream_idle_timeout == 0
    assert model._stream_first_event_timeout == 0
