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
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents.model_settings import ModelSettings
from agents.models.interface import Model, ModelTracing
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from openai import AsyncOpenAI

from strix.config import loader
from strix.config.loader import load_settings
from strix.config.models import StrixProvider, _TurnGuardModel, _with_idle_timeout


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, AsyncIterator, Iterator


_STALL_SECONDS = 30.0


class _ClosableBlockingStream:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.closed = False

    def __aiter__(self) -> _ClosableBlockingStream:
        return self

    async def __anext__(self) -> Any:
        self.started.set()
        await asyncio.Event().wait()
        raise StopAsyncIteration

    async def aclose(self) -> None:
        self.closed = True


class _OneEventClosableStream(_ClosableBlockingStream):
    def __init__(self) -> None:
        super().__init__()
        self._sent = False

    async def __anext__(self) -> Any:
        if not self._sent:
            self._sent = True
            return "event"
        return await super().__anext__()


class _StreamModel(Model):
    def __init__(self, stream: _OneEventClosableStream) -> None:
        self.stream = stream

    async def get_response(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError

    def stream_response(self, *_args: Any, **_kwargs: Any) -> Any:
        return self.stream


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


def _stream(base_url: str, *, idle_timeout: float) -> AsyncIterator[Any]:
    client = AsyncOpenAI(api_key="tok", base_url=base_url, max_retries=0, timeout=_STALL_SECONDS)
    inner: Model = OpenAIChatCompletionsModel(model="gw-model", openai_client=client)
    guarded = _TurnGuardModel(inner, stream_idle_timeout=idle_timeout)
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


async def _drain(base_url: str, *, idle_timeout: float) -> list[Any]:
    return [event async for event in _stream(base_url, idle_timeout=idle_timeout)]


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
async def test_events_keep_flowing_while_the_stream_is_alive() -> None:
    async def _live() -> AsyncIterator[Any]:
        for i in range(5):
            await asyncio.sleep(0.05)
            yield f"event-{i}"

    seen: list[Any] = [event async for event in _with_idle_timeout(_live(), 1.0)]

    assert seen == [f"event-{i}" for i in range(5)]


@pytest.mark.asyncio
async def test_consumer_cancellation_closes_the_inner_stream() -> None:
    stream = _ClosableBlockingStream()
    task = asyncio.create_task(
        anext(_with_idle_timeout(stream, 60.0)),
    )
    await asyncio.wait_for(stream.started.wait(), timeout=1.0)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert stream.closed is True


@pytest.mark.asyncio
async def test_closing_guarded_model_stream_closes_provider_stream_immediately() -> None:
    provider_stream = _OneEventClosableStream()
    model = _TurnGuardModel(_StreamModel(provider_stream), stream_idle_timeout=60.0)
    guarded_stream = cast(
        "AsyncGenerator[Any]",
        model.stream_response(
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
        ),
    )

    assert await anext(guarded_stream) == "event"
    await guarded_stream.aclose()

    assert provider_stream.closed is True


@pytest.fixture
def _reset_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in ("STRIX_LLM", "LLM_DISABLE_STREAMING", "LLM_STREAM_IDLE_TIMEOUT"):
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
