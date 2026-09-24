"""Tests for keeping replayed tool-call arguments valid JSON.

A model that emits a tool call with malformed ``arguments`` fails that one
call, but the raw string is recorded in the session. Strict OpenAI-compatible
servers validate every assistant tool call in the request, so each later turn
is rejected and the agent can never recover. A gateway that validates
arguments the way those servers do proves both the failure and the fix.
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
from openai import AsyncOpenAI, BadRequestError
from openai.types.responses import ResponseFunctionToolCall

from strix.config.models import _NonStreamingModel, _TurnGuardModel
from strix.config.tool_call_arguments import (
    MALFORMED_ARGUMENTS_KEY,
    describe_malformed_arguments,
    repair_arguments,
    repair_history_arguments,
    repair_input,
)


if TYPE_CHECKING:
    from collections.abc import Iterator


TRUNCATED = '{"n": 1'


def _tool_call_completion(arguments: str) -> dict[str, Any]:
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
                            "function": {"name": "do_thing", "arguments": arguments},
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


_REQUESTS: list[list[dict[str, Any]]] = []


def _assistant_arguments(messages: list[dict[str, Any]]) -> list[str]:
    return [
        str(call["function"]["arguments"])
        for message in messages
        for call in message.get("tool_calls") or []
    ]


def _tool_results(messages: list[dict[str, Any]]) -> list[str]:
    return [str(m.get("content")) for m in messages if m.get("role") == "tool"]


class _StrictHandler(BaseHTTPRequestHandler):
    """Gateway that rejects malformed assistant tool-call arguments, like vLLM/SGLang do."""

    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        messages = body.get("messages", [])
        _REQUESTS.append(messages)

        for arguments in _assistant_arguments(messages):
            try:
                json.loads(arguments)
            except ValueError:
                self._respond(
                    400,
                    {
                        "object": "error",
                        "message": "Assistant tool call function.arguments must be valid JSON.",
                        "type": "BadRequest",
                        "param": None,
                        "code": 400,
                    },
                )
                return

        if len(_REQUESTS) == 1:
            self._respond(200, _tool_call_completion(TRUNCATED))
        else:
            self._respond(200, _text_completion("all done"))

    def _respond(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


@pytest.fixture
def strict_gateway() -> Iterator[str]:
    _REQUESTS.clear()
    server = HTTPServer(("127.0.0.1", 0), _StrictHandler)
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


async def _run_agent(base_url: str, *, wrap: bool) -> Any:
    @function_tool
    def do_thing(n: int) -> str:
        return f"did {n}"

    class _Provider(ModelProvider):
        def get_model(self, model_name: str | None) -> Model:  # noqa: ARG002
            model = _model(base_url)
            return _TurnGuardModel(model) if wrap else model

    agent = Agent(name="t", instructions="use the tool", tools=[do_thing], model="gw-model")
    result = Runner.run_streamed(
        agent, input="please", run_config=RunConfig(model_provider=_Provider())
    )
    async for _ in result.stream_events():
        pass
    return result


@pytest.mark.asyncio
async def test_malformed_arguments_poison_every_later_turn_without_the_wrapper(
    strict_gateway: str,
) -> None:
    # Repro: the model truncates a tool call's arguments once. The tool fails
    # that call gracefully, but the next request replays the raw string and
    # the provider rejects the whole conversation from then on.
    with pytest.raises(BadRequestError, match="must be valid JSON"):
        await _run_agent(strict_gateway, wrap=False)

    assert _assistant_arguments(_REQUESTS[-1]) == [TRUNCATED]


@pytest.mark.asyncio
async def test_malformed_arguments_are_replayed_as_valid_json(strict_gateway: str) -> None:
    result = await _run_agent(strict_gateway, wrap=True)

    assert result.final_output == "all done"
    (arguments,) = _assistant_arguments(_REQUESTS[-1])
    assert json.loads(arguments) == {MALFORMED_ARGUMENTS_KEY: TRUNCATED}
    (tool_result,) = _tool_results(_REQUESTS[-1])
    assert "JSON" in tool_result


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ('{"cmd": "ls', json.dumps({MALFORMED_ARGUMENTS_KEY: '{"cmd": "ls'})),
        ("[1, 2]", json.dumps({MALFORMED_ARGUMENTS_KEY: "[1, 2]"})),
        ("", "{}"),
        ("  ", "{}"),
        (None, "{}"),
    ],
)
def test_repair_arguments_rewrites_anything_but_a_json_object(
    arguments: str | None, expected: str
) -> None:
    assert repair_arguments(arguments) == expected


@pytest.mark.parametrize("arguments", ["{}", '{"cmd": "ls -la"}', '{"nested": {"a": [1]}}'])
def test_repair_arguments_leaves_json_objects_alone(arguments: str) -> None:
    assert repair_arguments(arguments) is None


def test_history_repair_rewrites_only_malformed_calls() -> None:
    items = [
        {"role": "user", "content": "go"},
        {"type": "function_call", "call_id": "a", "name": "x", "arguments": '{"cmd": "ls'},
        {"type": "function_call_output", "call_id": "a", "output": "invalid JSON"},
        {"type": "function_call", "call_id": "b", "name": "y", "arguments": '{"ok": true}'},
        ResponseFunctionToolCall(call_id="c", name="z", arguments="", type="function_call"),
    ]

    rebuilt, changed = repair_history_arguments(items)

    assert changed
    assert rebuilt[0] is items[0]
    assert json.loads(rebuilt[1]["arguments"]) == {MALFORMED_ARGUMENTS_KEY: '{"cmd": "ls'}
    assert rebuilt[1]["call_id"] == "a"
    assert rebuilt[2] is items[2]
    assert rebuilt[3] is items[3]
    assert isinstance(rebuilt[4], ResponseFunctionToolCall)
    assert rebuilt[4].arguments == "{}"
    assert items[1]["arguments"] == '{"cmd": "ls'


def test_repair_input_returns_same_object_when_nothing_changes() -> None:
    items = [{"type": "function_call", "call_id": "a", "name": "x", "arguments": "{}"}]

    assert repair_input(items) is items
    assert repair_input("plain prompt") == "plain prompt"


@pytest.mark.parametrize("arguments", ['{"cmd": "ls -la', "[1, 2]", "null", "not json"])
def test_describe_malformed_arguments_tells_the_model_to_reissue(arguments: str) -> None:
    message = describe_malformed_arguments("exec_command", arguments)

    assert message is not None
    assert message.startswith("exec_command: the tool call was not executed")
    assert "Re-issue the call" in message


@pytest.mark.parametrize("arguments", ["", "   ", "{}", '{"cmd": "ls"}'])
def test_describe_malformed_arguments_accepts_objects_and_empty_input(arguments: str) -> None:
    assert describe_malformed_arguments("exec_command", arguments) is None
