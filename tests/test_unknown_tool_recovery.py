"""Tests for surviving a hallucinated tool name.

Models regularly invent tool names that Strix does not register (``read_file``
is a common one, borrowed from other agent frameworks). The SDK's default is to
raise ``ModelBehaviorError``, which ends the whole run: nothing in Strix retries
it, so one bad token discards a scan. The runner therefore opts into
``tool_not_found_behavior="return_error_to_model"`` so the unknown call comes
back as a tool result and the agent corrects itself on the next turn.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any

import pytest
from agents import Agent, Runner, function_tool
from agents.exceptions import ModelBehaviorError
from agents.models.interface import Model, ModelProvider
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from agents.run import RunConfig
from openai import AsyncOpenAI

from strix.config.models import _NonStreamingModel


if TYPE_CHECKING:
    from collections.abc import Iterator


_TURNS: list[dict[str, Any]] = []


def _unknown_tool_call_completion() -> dict[str, Any]:
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 0,
        "model": "gw-model",
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "read_file",
                                "arguments": '{"path": "/etc/passwd"}',
                            },
                        }
                    ],
                },
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
    }


def _text_completion(text: str) -> dict[str, Any]:
    return {
        "id": "chatcmpl-2",
        "object": "chat.completion",
        "created": 0,
        "model": "gw-model",
        "choices": [
            {"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": text}}
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
    }


class _Handler(BaseHTTPRequestHandler):
    """Calls an unregistered tool on turn 1, then answers on turn 2."""

    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        _TURNS.append(json.loads(self.rfile.read(length) or b"{}"))
        completion = (
            _unknown_tool_call_completion() if len(_TURNS) == 1 else _text_completion("recovered")
        )
        payload = json.dumps(completion).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def gateway_url() -> Iterator[str]:
    _TURNS.clear()
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        server.shutdown()
        server.server_close()


def _agent() -> Agent[Any]:
    @function_tool
    def real_tool(n: int) -> str:
        return f"did {n}"

    return Agent(name="Strix", instructions="test", tools=[real_tool], model="gw-model")


def _run_config(base_url: str, **kwargs: Any) -> RunConfig:
    class _Provider(ModelProvider):
        def get_model(self, model_name: str | None) -> Model:  # noqa: ARG002
            client = AsyncOpenAI(api_key="tok", base_url=base_url)
            return _NonStreamingModel(OpenAIChatCompletionsModel("gw-model", openai_client=client))

    return RunConfig(model_provider=_Provider(), **kwargs)


@pytest.mark.asyncio
async def test_unknown_tool_call_is_returned_to_the_model(gateway_url: str) -> None:
    result = Runner.run_streamed(
        _agent(),
        input="go",
        run_config=_run_config(gateway_url, tool_not_found_behavior="return_error_to_model"),
    )
    async for _ in result.stream_events():
        pass

    assert result.final_output == "recovered"
    # The second turn carries the error back to the model as a tool result.
    tool_results = [
        item
        for item in _TURNS[1]["messages"]
        if item.get("role") == "tool" and item.get("tool_call_id") == "call_1"
    ]
    assert tool_results
    assert "read_file" in str(tool_results[0]["content"])


@pytest.mark.asyncio
async def test_unknown_tool_call_kills_the_run_without_the_setting(gateway_url: str) -> None:
    result = Runner.run_streamed(_agent(), input="go", run_config=_run_config(gateway_url))
    with pytest.raises(ModelBehaviorError, match="read_file"):
        async for _ in result.stream_events():
            pass
