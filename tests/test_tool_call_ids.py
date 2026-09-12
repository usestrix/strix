"""Tests for tool-call id uniqueness.

Providers that number tool calls per turn (``exec_command:0``, ``:1``, ...)
restart the counter on every turn, so the same id eventually appears twice in
one conversation. Strict providers then reject the whole request, and because
the history is replayed on every retry the agent can never recover. A gateway
that validates id uniqueness the way those providers do proves both the
failure and the fix.
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
from openai.types.responses import ResponseFunctionToolCall

from strix.config.models import _NonStreamingModel, _TurnGuardModel
from strix.config.tool_call_ids import TurnCallIdRewriter, dedupe_history_call_ids


if TYPE_CHECKING:
    from collections.abc import Iterator


def _tool_call_completion(call_id: str, n: int = 1) -> dict[str, Any]:
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
                            "id": call_id,
                            "type": "function",
                            "function": {"name": "do_thing", "arguments": json.dumps({"n": n})},
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


def _assistant_call_ids(messages: list[dict[str, Any]]) -> list[str]:
    return [str(call.get("id")) for message in messages for call in message.get("tool_calls") or []]


def _tool_results(messages: list[dict[str, Any]]) -> list[str]:
    return [str(m.get("content")) for m in messages if m.get("role") == "tool"]


class _StrictHandler(BaseHTTPRequestHandler):
    """Gateway that rejects a history reusing a tool-call id, like strict providers do."""

    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        messages = body.get("messages", [])
        _REQUESTS.append(messages)
        call_ids = _assistant_call_ids(messages)

        if len(call_ids) != len(set(call_ids)):
            self._respond(
                400,
                {
                    "error": {
                        "message": (
                            "tool messages need a resolvable tool name: carry `tool`/`name`, "
                            "or match a preceding assistant tool_call by order"
                        )
                    }
                },
            )
            return

        turn = len(_REQUESTS)
        if turn <= 2:
            # The provider restarts its per-turn counter, so both turns say ":0".
            self._respond(200, _tool_call_completion("exec_command:0", n=turn))
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
    # The gateway answers plain JSON, so the run loop's streamed turns are
    # served non-streamed; the ids on the wire are the same either way.
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
async def test_recycled_call_id_erases_a_turn_without_the_wrapper(strict_gateway: str) -> None:
    # Repro: two turns run a tool and both are labelled ``exec_command:0``, so
    # the colliding call and its result are dropped as duplicates. The agent
    # ends the run having silently lost a turn of its own work — and a provider
    # that does not drop them instead rejects the malformed history outright.
    result = await _run_agent(strict_gateway, wrap=False)

    assert result.final_output == "all done"
    assert _assistant_call_ids(_REQUESTS[-1]) == ["exec_command:0"]
    assert _tool_results(_REQUESTS[-1]) == ["did 2"]


@pytest.mark.asyncio
async def test_recycled_call_id_is_rewritten_so_no_turn_is_lost(strict_gateway: str) -> None:
    result = await _run_agent(strict_gateway, wrap=True)

    assert result.final_output == "all done"
    call_ids = _assistant_call_ids(_REQUESTS[-1])
    assert len(call_ids) == len(set(call_ids)) == 2
    assert call_ids[0] == "exec_command:0"
    assert call_ids[1].startswith("call_")
    assert _tool_results(_REQUESTS[-1]) == ["did 1", "did 2"]


def test_history_dedupe_keeps_outputs_paired_with_their_call() -> None:
    items = [
        {"type": "function_call", "call_id": "exec_command:0", "name": "a", "arguments": "{}"},
        {"type": "function_call_output", "call_id": "exec_command:0", "output": "first"},
        {"type": "function_call", "call_id": "exec_command:0", "name": "b", "arguments": "{}"},
        {"type": "function_call_output", "call_id": "exec_command:0", "output": "second"},
    ]

    rebuilt, changed = dedupe_history_call_ids(items)

    assert changed
    ids = [item["call_id"] for item in rebuilt]
    assert ids[0] == ids[1] == "exec_command:0"
    assert ids[2] == ids[3] != "exec_command:0"
    assert rebuilt[3]["output"] == "second"


def test_history_dedupe_pairs_parallel_calls_by_order() -> None:
    items = [
        {"type": "function_call", "call_id": "dup", "name": "a", "arguments": "{}"},
        {"type": "function_call", "call_id": "dup", "name": "b", "arguments": "{}"},
        {"type": "function_call_output", "call_id": "dup", "output": "for-a"},
        {"type": "function_call_output", "call_id": "dup", "output": "for-b"},
    ]

    rebuilt, changed = dedupe_history_call_ids(items)

    assert changed
    assert rebuilt[0]["call_id"] == rebuilt[2]["call_id"] == "dup"
    assert rebuilt[1]["call_id"] == rebuilt[3]["call_id"]
    assert rebuilt[1]["call_id"] != "dup"


def test_history_dedupe_leaves_unique_ids_alone() -> None:
    items = [
        {"type": "function_call", "call_id": "call_a", "name": "a", "arguments": "{}"},
        {"type": "function_call_output", "call_id": "call_a", "output": "x"},
        {"type": "function_call", "call_id": "call_b", "name": "b", "arguments": "{}"},
    ]

    rebuilt, changed = dedupe_history_call_ids(items)

    assert not changed
    assert rebuilt == items


def test_turn_rewriter_is_stable_across_repeated_sightings() -> None:
    history = [{"type": "function_call", "call_id": "exec_command:0", "name": "a"}]
    rewriter = TurnCallIdRewriter(history)
    call = ResponseFunctionToolCall(
        call_id="exec_command:0", name="a", arguments="{}", type="function_call"
    )

    first = rewriter.rewrite_item(call)
    second = rewriter.rewrite_item(first)

    assert first.call_id != "exec_command:0"
    assert second.call_id == first.call_id
