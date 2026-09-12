"""Regression test for the ChatGPT Codex backend's streaming requirement.

The backend rejects non-streamed requests with ``{"detail": "Stream must be set
to true"}``. ``_CodexResponsesModel`` must therefore issue a streamed request
even from the non-streaming ``get_response`` path and aggregate the events into
a single response. A local server that mimics that behaviour proves the wrapper
works where the stock responses model would fail.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any

import pytest
from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from agents.models.openai_responses import OpenAIResponsesModel
from openai import AsyncOpenAI, BadRequestError
from openai.types.responses import ResponseOutputMessage, ResponseOutputText

from strix.config import codex
from strix.config.models import _CodexResponsesModel


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator


def _response_payload() -> dict[str, Any]:
    return {
        "id": "resp_1",
        "object": "response",
        "created_at": 0,
        "status": "completed",
        "model": "gpt-5.5",
        "output": [
            {
                "type": "message",
                "id": "m1",
                "status": "completed",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "OK", "annotations": []}],
            }
        ],
        "usage": {
            "input_tokens": 1,
            "output_tokens": 1,
            "total_tokens": 2,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens_details": {"reasoning_tokens": 0},
        },
        "parallel_tool_calls": False,
        "tool_choice": "auto",
        "tools": [],
        "metadata": {},
        "temperature": 1.0,
        "top_p": 1.0,
        "error": None,
        "incomplete_details": None,
        "instructions": None,
        "max_output_tokens": None,
    }


_CAPTURED: dict[str, Any] = {}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        _CAPTURED.clear()
        _CAPTURED.update(body)
        if not body.get("stream"):
            payload = json.dumps({"detail": "Stream must be set to true"}).encode()
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        event = {
            "type": "response.completed",
            "sequence_number": 0,
            "response": _response_payload(),
        }
        frame = f"event: response.completed\ndata: {json.dumps(event)}\n\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.write(frame)


@pytest.fixture
def backend_url() -> Iterator[str]:
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/backend-api/codex"
    finally:
        server.shutdown()
        server.server_close()


def _client(base_url: str) -> AsyncOpenAI:
    return AsyncOpenAI(api_key="tok", base_url=base_url)


def _call_kwargs() -> dict[str, Any]:
    return {
        "system_instructions": "s",
        "input": "hi",
        "model_settings": ModelSettings(
            store=False, response_include=["reasoning.encrypted_content"]
        ),
        "tools": [],
        "output_schema": None,
        "handoffs": [],
        "tracing": ModelTracing.DISABLED,
        "previous_response_id": None,
        "conversation_id": None,
        "prompt": None,
    }


@pytest.mark.asyncio
async def test_stock_model_fails_on_non_streamed_backend(backend_url: str) -> None:
    model = OpenAIResponsesModel(model="gpt-5.5", openai_client=_client(backend_url))
    with pytest.raises(BadRequestError, match="Stream must be set to true"):
        await model.get_response(**_call_kwargs())


@pytest.mark.asyncio
async def test_codex_model_streams_and_aggregates(backend_url: str) -> None:
    model = _CodexResponsesModel(model="gpt-5.5", openai_client=_client(backend_url))
    response = await model.get_response(**_call_kwargs())
    message = response.output[0]
    assert isinstance(message, ResponseOutputMessage)
    text = message.content[0]
    assert isinstance(text, ResponseOutputText)
    assert text.text == "OK"
    assert response.usage.total_tokens == 2


class _TrackingStream:
    """An async iterator that yields, then raises, and records if it was closed."""

    def __init__(self, events: list[Any], error: Exception | None) -> None:
        self._events = iter(events)
        self._error = error
        self.closed = False

    def __aiter__(self) -> _TrackingStream:
        return self

    async def __anext__(self) -> Any:
        try:
            return next(self._events)
        except StopIteration:
            if self._error is not None:
                raise self._error from None
            raise StopAsyncIteration from None

    async def aclose(self) -> None:
        self.closed = True


async def _drain(gen: AsyncIterator[Any]) -> list[Any]:
    return [event async for event in gen]


@pytest.mark.asyncio
async def test_guarded_converts_guardrail_error() -> None:
    # A mid-stream backend rejection becomes a typed, model-tagged error.
    model = _CodexResponsesModel(model="gpt-5.6-sol", openai_client=_client("http://x/backend-api"))
    guardrail = RuntimeError("This content was flagged for possible cybersecurity risk.")
    stream = _TrackingStream(["a", "b"], guardrail)
    with pytest.raises(codex.CodexContentGuardrailError) as exc_info:
        await _drain(model._guarded(stream))
    assert exc_info.value.model == "gpt-5.6-sol"
    assert stream.closed is True  # underlying stream is released


@pytest.mark.asyncio
async def test_guarded_passes_through_other_errors() -> None:
    # A non-guardrail error propagates unchanged (still not swallowed).
    model = _CodexResponsesModel(model="gpt-5.5", openai_client=_client("http://x/backend-api"))
    boom = RuntimeError("some unrelated failure")
    stream = _TrackingStream(["a"], boom)
    with pytest.raises(RuntimeError, match="some unrelated failure"):
        await _drain(model._guarded(stream))
    assert stream.closed is True


@pytest.mark.asyncio
async def test_guarded_yields_all_events_when_clean() -> None:
    model = _CodexResponsesModel(model="gpt-5.4", openai_client=_client("http://x/backend-api"))
    stream = _TrackingStream(["a", "b", "c"], None)
    assert await _drain(model._guarded(stream)) == ["a", "b", "c"]
    assert stream.closed is True


@pytest.mark.asyncio
async def test_codex_model_self_enforces_backend_requirements(backend_url: str) -> None:
    # The caller passes ordinary settings; the model must impose the backend's
    # requirements (stream, store=false, encrypted reasoning) and the configured
    # reasoning effort itself.
    model = _CodexResponsesModel(
        model="gpt-5.4", openai_client=_client(backend_url), reasoning_effort="high"
    )
    kwargs = _call_kwargs()
    kwargs["model_settings"] = ModelSettings()  # nothing special from the caller
    await model.get_response(**kwargs)

    assert _CAPTURED["stream"] is True
    assert _CAPTURED["store"] is False
    assert _CAPTURED["include"] == ["reasoning.encrypted_content"]
    assert _CAPTURED["reasoning"] == {"effort": "high"}
