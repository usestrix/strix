"""Tests for the per-response tool-call cap.

A degenerate generation can emit hundreds of tool calls in one assistant
response — a wait/poll loop the model writes out ahead of time. The run loop
honours every one of them, so the agent stops reacting for hours. The cap
keeps the first N calls of a response and drops the tail.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any

import pytest
from agents import Agent, Runner, function_tool
from agents.models.interface import Model, ModelProvider
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from agents.run import RunConfig
from openai import AsyncOpenAI

from strix.config import loader
from strix.config.loader import load_settings
from strix.config.models import StrixProvider, _NonStreamingModel, _TurnGuardModel


if TYPE_CHECKING:
    from collections.abc import Iterator


_RUNAWAY_CALLS = 200
_CAP = 32


def _runaway_completion() -> dict[str, Any]:
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
                            "id": f"call_{i}",
                            "type": "function",
                            "function": {"name": "wait_for_message", "arguments": "{}"},
                        }
                        for i in range(_RUNAWAY_CALLS)
                    ],
                },
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
    }


def _text_completion() -> dict[str, Any]:
    return {
        "id": "chatcmpl-2",
        "object": "chat.completion",
        "created": 0,
        "model": "gw-model",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": "done"},
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
    }


_TURNS: list[int] = []


class _RunawayHandler(BaseHTTPRequestHandler):
    """First turn queues a huge poll loop; the next turn ends the run."""

    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        _TURNS.append(1)
        payload = _runaway_completion() if len(_TURNS) == 1 else _text_completion()
        encoded = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


@pytest.fixture
def runaway_gateway() -> Iterator[str]:
    _TURNS.clear()
    server = HTTPServer(("127.0.0.1", 0), _RunawayHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        server.shutdown()
        server.server_close()


def _model(base_url: str) -> Model:
    client = AsyncOpenAI(api_key="tok", base_url=base_url, max_retries=0)
    return _NonStreamingModel(OpenAIChatCompletionsModel(model="gw-model", openai_client=client))


async def _run_agent(base_url: str, *, cap: int) -> list[int]:
    executed: list[int] = []

    @function_tool
    def wait_for_message() -> str:
        executed.append(1)
        return "nothing new"

    class _Provider(ModelProvider):
        def get_model(self, model_name: str | None) -> Model:  # noqa: ARG002
            return _TurnGuardModel(_model(base_url), max_tool_calls_per_turn=cap)

    agent = Agent(name="t", instructions="orchestrate", tools=[wait_for_message], model="gw-model")
    result = Runner.run_streamed(
        agent, input="go", run_config=RunConfig(model_provider=_Provider())
    )
    async for _ in result.stream_events():
        pass
    assert result.final_output == "done"
    return executed


@pytest.mark.asyncio
async def test_runaway_response_runs_every_queued_call_when_uncapped(runaway_gateway: str) -> None:
    # Repro: one response queues 200 calls and the run loop honours all of them.
    executed = await _run_agent(runaway_gateway, cap=0)

    assert len(executed) == _RUNAWAY_CALLS


@pytest.mark.asyncio
async def test_runaway_response_is_capped(runaway_gateway: str) -> None:
    executed = await _run_agent(runaway_gateway, cap=_CAP)

    assert len(executed) == _CAP


@pytest.mark.asyncio
async def test_response_below_the_cap_is_untouched(runaway_gateway: str) -> None:
    executed = await _run_agent(runaway_gateway, cap=_RUNAWAY_CALLS + 1)

    assert len(executed) == _RUNAWAY_CALLS


@pytest.fixture
def _reset_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in ("STRIX_LLM", "LLM_DISABLE_STREAMING", "LLM_MAX_TOOL_CALLS_PER_TURN"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)
    yield


class _DummyModel(Model):
    async def get_response(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError

    def stream_response(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError


def test_cap_is_configurable(monkeypatch: pytest.MonkeyPatch, _reset_settings: None) -> None:
    monkeypatch.setattr("strix.config.models.MultiProvider.get_model", lambda *_: _DummyModel())
    monkeypatch.setenv("LLM_MAX_TOOL_CALLS_PER_TURN", "7")
    load_settings()

    model = StrixProvider().get_model("openai/gpt-4o-mini")
    assert isinstance(model, _TurnGuardModel)
    assert model._max_tool_calls_per_turn == 7
