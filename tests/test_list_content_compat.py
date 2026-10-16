"""Tests for list-shaped chat-completions content from OpenAI-compatible gateways.

Reasoning models behind some OpenAI-compatible endpoints return assistant
content as a list of content blocks (``thinking`` + ``text``) instead of a
plain string. The OpenAI client constructs its models without validating that
field, and the SDK then crashes on ``ResponseOutputText``/``ResponseTextDeltaEvent``
validation. ``chat_content_compat.install()`` flattens the text blocks before
the SDK consumes them; a local gateway that answers with list-shaped content
proves both the non-streaming and the streaming path work end to end.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any

import pytest
from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from openai import AsyncOpenAI
from openai.types.responses import (
    ResponseCompletedEvent,
    ResponseOutputMessage,
    ResponseOutputText,
    ResponseTextDeltaEvent,
)

from strix.llm.chat_content_compat import install as install_content_compat


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator

install_content_compat()


def _list_content_completion() -> dict[str, Any]:
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 0,
        "model": "gw-model",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": [
                        {"type": "thinking", "thinking": "considering the request"},
                        {"type": "text", "text": "OK"},
                    ],
                },
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
    }


def _list_content_chunks() -> list[dict[str, Any]]:
    def chunk(delta: dict[str, Any], finish_reason: str | None = None) -> dict[str, Any]:
        return {
            "id": "chatcmpl-2",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": "gw-model",
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
        }

    return [
        chunk({"role": "assistant"}),
        chunk({"content": [{"type": "thinking", "thinking": "hmm"}]}),
        chunk({"content": [{"type": "text", "text": "OK"}]}),
        chunk({}, "stop"),
    ]


class _Handler(BaseHTTPRequestHandler):
    """A gateway whose assistant content arrives as a list of content blocks."""

    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        if body.get("stream"):
            payload = "".join(f"data: {json.dumps(c)}\n\n" for c in _list_content_chunks())
            payload += "data"
            payload_bytes = payload.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
        else:
            payload_bytes = json.dumps(_list_content_completion()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload_bytes)))
        self.end_headers()
        self.wfile.write(payload_bytes)


@pytest.fixture
def gateway_url() -> Iterator[str]:
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        server.shutdown()
        server.server_close()


def _model(base_url: str) -> OpenAIChatCompletionsModel:
    client = AsyncOpenAI(api_key="tok", base_url=base_url)
    return OpenAIChatCompletionsModel(model="gw-model", openai_client=client)


def _call_kwargs() -> dict[str, Any]:
    return {
        "system_instructions": "s",
        "input": "hi",
        "model_settings": ModelSettings(),
        "tools": [],
        "output_schema": None,
        "handoffs": [],
        "tracing": ModelTracing.DISABLED,
        "previous_response_id": None,
        "conversation_id": None,
        "prompt": None,
    }


async def _drain(gen: AsyncIterator[Any]) -> list[Any]:
    return [event async for event in gen]


async def test_get_response_flattens_list_content(gateway_url: str) -> None:
    response = await _model(gateway_url).get_response(**_call_kwargs())

    message = response.output[0]
    assert isinstance(message, ResponseOutputMessage)
    text = message.content[0]
    assert isinstance(text, ResponseOutputText)
    assert text.text == "OK"

    assert response.usage is not None
    assert response.usage.total_tokens == 8


async def test_stream_response_flattens_list_content_deltas(gateway_url: str) -> None:
    events = await _drain(_model(gateway_url).stream_response(**_call_kwargs()))

    deltas = [e for e in events if isinstance(e, ResponseTextDeltaEvent)]
    assert [d.delta for d in deltas] == ["OK"]

    completed = events[-1]
    assert isinstance(completed, ResponseCompletedEvent)
    message = completed.response.output[0]
    assert isinstance(message, ResponseOutputMessage)
    text = message.content[0]
    assert isinstance(text, ResponseOutputText)
    assert text.text == "OK"
