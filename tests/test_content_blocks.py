"""Chat completions whose message content is a list of blocks (#1357).

Mistral serves its reasoning models with ``content`` as a list such as
``[{"type": "thinking", ...}, {"type": "text", "text": "OK"}]``, in full
responses and in every streamed delta. The stock SDK model fails validation on
both paths. A local server that answers the way Mistral does shows the stock
model failing and the block-tolerant model returning the text, with the
thinking kept as a reasoning item.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any

import litellm
import pytest
from agents.model_settings import ModelSettings
from agents.models import _openai_shared
from agents.models.interface import ModelTracing
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from openai import AsyncOpenAI
from openai.types.responses import (
    ResponseCompletedEvent,
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseReasoningItem,
)
from pydantic import ValidationError

from strix.config.models import (
    StrixProvider,
    _NonStreamingModel,
    _TurnGuardModel,
    configure_sdk_model_defaults,
)
from strix.config.settings import Settings
from strix.llm.content_blocks import (
    BlockTolerantChatCompletionsModel,
    split_content_blocks,
    tolerate_content_blocks,
)
from strix.llm.request_log import RequestLoggingModel


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator


def _thinking(text: str) -> dict[str, Any]:
    # Mistral nests the thinking text in a list of text chunks.
    return {"type": "thinking", "thinking": [{"type": "text", "text": text}]}


def _completion(message: dict[str, Any], finish_reason: str = "stop") -> dict[str, Any]:
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 0,
        "model": "magistral",
        "choices": [{"index": 0, "finish_reason": finish_reason, "message": message}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
    }


def _chunk(content: Any) -> dict[str, Any]:
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "magistral",
        "choices": [{"index": 0, "delta": {"role": "assistant", "content": content}}],
    }


_REPLY: dict[str, Any] = {}
_STREAM_DELTAS: list[Any] = []


class _Handler(BaseHTTPRequestHandler):
    """An endpoint that answers like Mistral's reasoning models."""

    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        if body.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for content in _STREAM_DELTAS:
                self.wfile.write(f"data: {json.dumps(_chunk(content))}\n\n".encode())
            self.wfile.write(b"data: [DONE]\n\n")
            return
        payload = json.dumps(_REPLY).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def endpoint() -> Iterator[str]:
    _REPLY.clear()
    _REPLY.update(
        _completion(
            {
                "role": "assistant",
                "content": [_thinking("user wants OK"), {"type": "text", "text": "OK"}],
            }
        )
    )
    _STREAM_DELTAS[:] = [
        [_thinking("user ")],
        [_thinking("wants OK")],
        [{"type": "text", "text": "O"}],
        [{"type": "text", "text": "K"}],
    ]
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        server.shutdown()
        server.server_close()


def _client(base_url: str) -> AsyncOpenAI:
    return AsyncOpenAI(api_key="tok", base_url=base_url)


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


def _text(item: Any) -> str:
    assert isinstance(item, ResponseOutputMessage)
    return "".join(part.text for part in item.content)


def _reasoning(item: Any) -> str:
    assert isinstance(item, ResponseReasoningItem)
    return "".join(part.text for part in item.summary)


@pytest.mark.parametrize(
    ("blocks", "expected"),
    [
        ([_thinking("plan"), {"type": "text", "text": "OK"}], ("OK", "plan")),
        (
            [{"type": "thinking", "thinking": "plan"}, {"type": "text", "text": "OK"}],
            ("OK", "plan"),
        ),
        ([{"type": "text", "text": "a"}, {"type": "text", "text": "b"}], ("ab", "")),
        (["plain", {"type": "text", "text": " text"}], ("plain text", "")),
        ([{"type": "image_url", "image_url": {}}, {"type": "text", "text": "OK"}], ("OK", "")),
        ([], ("", "")),
    ],
)
def test_split_content_blocks(blocks: list[Any], expected: tuple[str, str]) -> None:
    assert split_content_blocks(blocks) == expected


@pytest.mark.asyncio
async def test_stock_model_rejects_block_content(endpoint: str) -> None:
    # The failure #1357 reports, on both SDK paths.
    model = OpenAIChatCompletionsModel(model="magistral", openai_client=_client(endpoint))
    with pytest.raises(ValidationError, match="ResponseOutputText"):
        await model.get_response(**_call_kwargs())
    with pytest.raises(ValidationError, match="ResponseTextDeltaEvent"):
        await _drain(model.stream_response(**_call_kwargs()))


@pytest.mark.asyncio
async def test_block_content_get_response(endpoint: str) -> None:
    model = BlockTolerantChatCompletionsModel(model="magistral", openai_client=_client(endpoint))
    response = await model.get_response(**_call_kwargs())

    reasoning, message = response.output
    assert _reasoning(reasoning) == "user wants OK"
    assert _text(message) == "OK"


@pytest.mark.asyncio
async def test_block_content_stream_response(endpoint: str) -> None:
    model = BlockTolerantChatCompletionsModel(model="magistral", openai_client=_client(endpoint))
    events = await _drain(model.stream_response(**_call_kwargs()))

    completed = events[-1]
    assert isinstance(completed, ResponseCompletedEvent)
    reasoning, message = completed.response.output
    assert _reasoning(reasoning) == "user wants OK"
    assert _text(message) == "OK"


@pytest.mark.asyncio
async def test_thinking_only_content_keeps_the_tool_call(endpoint: str) -> None:
    # A turn that thinks and then calls a tool has no text block at all.
    _REPLY.clear()
    _REPLY.update(
        _completion(
            {
                "role": "assistant",
                "content": [_thinking("need the tool")],
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "do_thing", "arguments": '{"n": 1}'},
                    }
                ],
            },
            finish_reason="tool_calls",
        )
    )
    model = BlockTolerantChatCompletionsModel(model="magistral", openai_client=_client(endpoint))
    response = await model.get_response(**_call_kwargs())

    reasoning, tool_call = response.output
    assert _reasoning(reasoning) == "need the tool"
    assert isinstance(tool_call, ResponseFunctionToolCall)
    assert tool_call.name == "do_thing"


@pytest.mark.asyncio
async def test_string_content_is_untouched(endpoint: str) -> None:
    _REPLY.clear()
    _REPLY.update(_completion({"role": "assistant", "content": "plain reply"}))
    _STREAM_DELTAS[:] = ["plain ", "reply"]
    model = BlockTolerantChatCompletionsModel(model="magistral", openai_client=_client(endpoint))

    response = await model.get_response(**_call_kwargs())
    assert [_text(item) for item in response.output] == ["plain reply"]

    events = await _drain(model.stream_response(**_call_kwargs()))
    assert [_text(item) for item in events[-1].response.output] == ["plain reply"]


def test_tolerate_content_blocks_keeps_the_model_configuration() -> None:
    client = AsyncOpenAI(api_key="tok", base_url="https://gateway.example/v1")
    stock = OpenAIChatCompletionsModel(
        model="magistral",
        openai_client=client,
        strict_feature_validation=True,
        buffer_streamed_tool_calls=True,
    )
    wrapped = tolerate_content_blocks(stock)

    assert isinstance(wrapped, BlockTolerantChatCompletionsModel)
    assert wrapped.model == "magistral"
    assert wrapped._client is client
    assert wrapped._strict_feature_validation is True
    assert wrapped._buffer_streamed_tool_calls is True


def test_tolerate_content_blocks_leaves_subclasses_alone() -> None:
    class _Custom(OpenAIChatCompletionsModel):
        pass

    custom = _Custom(model="m", openai_client=AsyncOpenAI(api_key="tok"))
    assert tolerate_content_blocks(custom) is custom


def test_provider_serves_chat_completions_through_the_tolerant_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The #1357 setup: an openai/ model id on a custom base URL.
    # configure_sdk_model_defaults writes these process-wide; register them so
    # they are put back and later tests don't pick up the fake endpoint.
    monkeypatch.setattr(_openai_shared, "_use_responses_by_default", True)
    monkeypatch.setattr(_openai_shared, "_default_openai_client", None)
    monkeypatch.setattr(_openai_shared, "_default_openai_key", None)
    monkeypatch.setattr(litellm, "api_key", None)
    monkeypatch.setattr(litellm, "api_base", None)
    monkeypatch.setattr(litellm, "headers", litellm.headers)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "")
    monkeypatch.setenv("STRIX_LLM", "openai/zai-glm-latest")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_API_BASE", "https://api.mistral.example/v1")
    monkeypatch.setenv("STRIX_API_TYPE", "chat_completions")
    configure_sdk_model_defaults(Settings())

    model = StrixProvider().get_model("openai/zai-glm-latest")
    while isinstance(model, _NonStreamingModel | _TurnGuardModel | RequestLoggingModel):
        model = model._inner
    assert isinstance(model, BlockTolerantChatCompletionsModel)
