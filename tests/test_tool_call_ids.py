"""Tests for tool-call id presence and uniqueness.

Providers that number tool calls per turn (``exec_command:0``, ``:1``, ...)
restart the counter on every turn, so the same id eventually appears twice in
one conversation. Others hand back a tool call with no id at all, leaving the
paired tool message with a blank ``tool_call_id``. Strict providers reject the
whole request either way, and because the history is replayed on every retry
the agent can never recover. Gateways that validate ids the way those
providers do prove both failures and their fixes.
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


class _BlankIdHandler(BaseHTTPRequestHandler):
    """Gateway that hands out an id-less tool call and rejects blank ids, like GLM does."""

    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        messages = body.get("messages", [])
        _REQUESTS.append(messages)

        for index, message in enumerate(messages):
            if message.get("role") == "tool" and not message.get("tool_call_id"):
                self._respond(
                    400,
                    {
                        "error": {
                            "message": (
                                f"messages[{index}]: tool messages must include "
                                "a non-empty string tool_call_id"
                            ),
                            "code": 400,
                        }
                    },
                )
                return

        if len(_REQUESTS) == 1:
            self._respond(200, _tool_call_completion(""))
        else:
            self._respond(200, _text_completion("all done"))

    def _respond(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def _serve(handler: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    _REQUESTS.clear()
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def strict_gateway() -> Iterator[str]:
    yield from _serve(_StrictHandler)


@pytest.fixture
def blank_id_gateway() -> Iterator[str]:
    yield from _serve(_BlankIdHandler)


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


@pytest.mark.asyncio
async def test_blank_call_id_is_rejected_by_the_provider_without_the_wrapper(
    blank_id_gateway: str,
) -> None:
    # Repro: the model answers with a tool call carrying no id, so the paired
    # tool result goes back as a ``tool`` message with a blank ``tool_call_id``
    # and the provider rejects the whole replayed history with a 400.
    with pytest.raises(Exception, match="non-empty string tool_call_id"):
        await _run_agent(blank_id_gateway, wrap=False)


@pytest.mark.asyncio
async def test_blank_call_id_is_filled_in_so_the_history_stays_valid(
    blank_id_gateway: str,
) -> None:
    result = await _run_agent(blank_id_gateway, wrap=True)

    assert result.final_output == "all done"
    call_ids = _assistant_call_ids(_REQUESTS[-1])
    assert len(call_ids) == 1
    assert call_ids[0].startswith("call_")
    assert _tool_results(_REQUESTS[-1]) == ["did 1"]


def test_history_dedupe_fills_in_blank_ids_and_keeps_outputs_paired() -> None:
    items = [
        {"type": "function_call", "call_id": "", "name": "a", "arguments": "{}"},
        {"type": "function_call", "call_id": "", "name": "b", "arguments": "{}"},
        {"type": "function_call_output", "call_id": "", "output": "for-a"},
        {"type": "function_call_output", "call_id": "", "output": "for-b"},
    ]

    rebuilt, changed = dedupe_history_call_ids(items)

    assert changed
    ids = [item["call_id"] for item in rebuilt]
    assert all(call_id.startswith("call_") for call_id in ids)
    assert ids[0] == ids[2]
    assert ids[1] == ids[3]
    assert ids[0] != ids[1]


def test_history_dedupe_fills_in_a_missing_call_id_key() -> None:
    items = [
        {"type": "function_call", "name": "a", "arguments": "{}"},
        {"type": "function_call_output", "output": "x"},
    ]

    rebuilt, changed = dedupe_history_call_ids(items)

    assert changed
    assert rebuilt[0]["call_id"] == rebuilt[1]["call_id"]
    assert rebuilt[0]["call_id"].startswith("call_")


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


def test_turn_rewriter_fills_in_a_blank_id_stably() -> None:
    rewriter = TurnCallIdRewriter([])
    call = ResponseFunctionToolCall(
        id="fc_1", call_id="", name="a", arguments="{}", type="function_call"
    )

    first = rewriter.rewrite_item(call)
    second = rewriter.rewrite_item(call)

    assert first.call_id.startswith("call_")
    assert second.call_id == first.call_id
    assert rewriter.rewrite_item(first).call_id == first.call_id


def test_turn_rewriter_gives_parallel_blank_calls_distinct_ids() -> None:
    rewriter = TurnCallIdRewriter([])
    a = ResponseFunctionToolCall(
        id="fc_1", call_id="", name="a", arguments="{}", type="function_call"
    )
    b = ResponseFunctionToolCall(
        id="fc_2", call_id="", name="b", arguments="{}", type="function_call"
    )

    assert rewriter.rewrite_item(a).call_id != rewriter.rewrite_item(b).call_id
