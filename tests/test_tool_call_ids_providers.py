"""Tool-call id repair across provider routes, models, and streaming modes.

Every model Strix resolves goes through ``StrixProvider``, which picks the
OpenAI SDK for ``openai/...`` and LiteLLM for every other prefix, then wraps the
result in the turn guard that repairs tool-call ids. Each route parses a
provider's tool calls on its own code path, so a blank or missing id — or a
per-turn counter that repeats — has to be repaired no matter which route
carried it, streamed or not.

A local OpenAI-compatible gateway stands in for the provider. It hands out
tool calls with whatever ids the scenario calls for and rejects a history the
way strict providers do: any ``tool`` message with an empty ``tool_call_id``,
or two assistant tool calls sharing one id.
"""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any, ClassVar

import litellm
import pytest
from agents import Agent, ModelSettings, Runner, function_tool
from agents.run import RunConfig

from strix.config import loader
from strix.config import models as strix_models
from strix.config.models import StrixProvider


if TYPE_CHECKING:
    from collections.abc import Iterator


_MISSING = object()


@dataclass(frozen=True)
class _Scenario:
    """Tool-call ids the gateway hands out, one list per tool-calling turn."""

    turns: tuple[tuple[Any, ...], ...]

    @property
    def calls(self) -> int:
        return sum(len(turn) for turn in self.turns)

    @property
    def has_null_id(self) -> bool:
        return any(
            call_id is None or call_id is _MISSING for turn in self.turns for call_id in turn
        )


SCENARIOS = {
    "empty-id": _Scenario(turns=(("",),)),
    "null-id": _Scenario(turns=((None,),)),
    "missing-id": _Scenario(turns=((_MISSING,),)),
    "parallel-empty-ids": _Scenario(turns=(("", ""),)),
    "empty-id-every-turn": _Scenario(turns=(("",), ("",), ("",))),
    "recycled-counter": _Scenario(turns=(("exec_command:0",), ("exec_command:0",))),
    "parallel-recycled-counter": _Scenario(
        turns=(("exec_command:0", "exec_command:1"), ("exec_command:0", "exec_command:1"))
    ),
    "mixed-blank-and-recycled": _Scenario(
        turns=(("exec_command:0", ""), ("exec_command:0", None), (_MISSING,))
    ),
    "valid-ids": _Scenario(turns=(("call_a",), ("call_b", "call_c"))),
}

# One model per provider family Strix recommends or documents, each on the
# route ``StrixProvider`` gives it: the OpenAI SDK for ``openai/``, LiteLLM's
# OpenAI-compatible adapters for the rest, and a generic OpenAI-compatible
# endpoint through ``litellm/openai/``.
MODELS = [
    "openai/gpt-5.4",
    "openrouter/z-ai/glm-5.3",
    "openrouter/anthropic/claude-sonnet-4.6",
    "openrouter/google/gemini-3-pro-preview",
    "openrouter/qwen/qwen3-coder",
    "zai/glm-5.3",
    "zai/glm-5.3-flash",
    "deepseek/deepseek-chat",
    "moonshot/kimi-k2.5",
    "xai/grok-4",
    "mistral/mistral-large-latest",
    "together_ai/Qwen/Qwen3-235B-A22B",
    "fireworks_ai/accounts/fireworks/models/kimi-k2",
    "dashscope/qwen3-max",
    "deepinfra/Qwen/Qwen3-32B",
    "nebius/Qwen/Qwen3-32B",
    "hosted_vllm/Qwen/Qwen3-32B",
    "litellm/openai/gw-model",
]


class _Gateway(BaseHTTPRequestHandler):
    scenario: ClassVar[_Scenario]
    requests: ClassVar[list[dict[str, Any]]]
    lock: ClassVar[threading.Lock]

    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        messages = body.get("messages", [])
        with self.lock:
            self.requests.append(body)
            turn = len(self.requests) - 1

        error = _history_error(messages)
        if error:
            self._send_json(400, {"error": {"message": error, "code": 400}})
            return

        if turn < len(self.scenario.turns):
            ids = self.scenario.turns[turn]
            message = _tool_call_message(ids, first_n=turn * 10)
            finish = "tool_calls"
        else:
            message = {"role": "assistant", "content": "all done"}
            finish = "stop"

        if body.get("stream"):
            self._send_stream(message, finish)
        else:
            self._send_json(
                200,
                {
                    "id": f"chatcmpl-{turn}",
                    "object": "chat.completion",
                    "created": 0,
                    "model": body.get("model", "gw-model"),
                    "choices": [{"index": 0, "finish_reason": finish, "message": message}],
                    "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
                },
            )

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_stream(self, message: dict[str, Any], finish: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()

        def chunk(delta: dict[str, Any], finish_reason: str | None = None) -> None:
            payload = {
                "id": "chatcmpl-s",
                "object": "chat.completion.chunk",
                "created": 0,
                "model": "gw-model",
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
            }
            self.wfile.write(f"data: {json.dumps(payload)}\n\n".encode())

        chunk({"role": "assistant", "content": ""})
        if message.get("content"):
            chunk({"content": message["content"]})
        for index, call in enumerate(message.get("tool_calls") or []):
            head: dict[str, Any] = {
                "index": index,
                "type": "function",
                "function": {"name": call["function"]["name"], "arguments": ""},
            }
            if "id" in call:
                head["id"] = call["id"]
            chunk({"tool_calls": [head]})
            arguments = call["function"]["arguments"]
            middle = len(arguments) // 2
            for part in (arguments[:middle], arguments[middle:]):
                chunk({"tool_calls": [{"index": index, "function": {"arguments": part}}]})
        chunk({}, finish)
        usage = {
            "id": "chatcmpl-s",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": "gw-model",
            "choices": [],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
        }
        self.wfile.write(f"data: {json.dumps(usage)}\n\n".encode())
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


def _tool_call_message(ids: tuple[Any, ...], *, first_n: int) -> dict[str, Any]:
    calls = []
    for offset, call_id in enumerate(ids):
        call: dict[str, Any] = {
            "type": "function",
            "function": {"name": "do_thing", "arguments": json.dumps({"n": first_n + offset})},
        }
        if call_id is not _MISSING:
            call["id"] = call_id
        calls.append(call)
    return {"role": "assistant", "content": None, "tool_calls": calls}


def _history_error(messages: list[dict[str, Any]]) -> str | None:
    seen: set[str] = set()
    for index, message in enumerate(messages):
        if message.get("role") == "tool":
            call_id = message.get("tool_call_id")
            if not isinstance(call_id, str) or not call_id:
                return (
                    f"messages[{index}]: tool messages must include a non-empty string tool_call_id"
                )
        for call in message.get("tool_calls") or []:
            call_id = call.get("id")
            if not isinstance(call_id, str) or not call_id:
                return f"messages[{index}]: assistant tool_calls must include a non-empty id"
            if call_id in seen:
                return f"messages[{index}]: duplicate tool_call id {call_id!r}"
            seen.add(call_id)
    return None


def _serve(scenario: _Scenario) -> tuple[HTTPServer, type[_Gateway]]:
    handler = type(
        "_ScenarioGateway",
        (_Gateway,),
        {"scenario": scenario, "requests": [], "lock": threading.Lock()},
    )
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, handler


@pytest.fixture(autouse=True)
def _reset_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ("STRIX_LLM", "LLM_DISABLE_STREAMING", "LLM_MAX_TOOL_CALLS_PER_TURN"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)
    # As ``configure_sdk_model_defaults`` sets it, so routes like ``zai/`` that
    # reject ``parallel_tool_calls`` still get a request out.
    monkeypatch.setattr(litellm, "drop_params", True)


@contextmanager
def _gateway(scenario: _Scenario) -> Iterator[tuple[str, type[_Gateway]]]:
    server, handler = _serve(scenario)
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1", handler
    finally:
        server.shutdown()
        server.server_close()


async def _run(
    monkeypatch: pytest.MonkeyPatch, model: str, base_url: str, *, stream: bool, parallel: bool
) -> tuple[Any, list[int]]:
    monkeypatch.setenv("LLM_DISABLE_STREAMING", "false" if stream else "true")
    monkeypatch.setattr(loader, "_cached", None)
    # Binding the provider to the gateway sends every route there, the way a
    # custom endpoint would, while each prefix keeps its own adapter.
    provider = StrixProvider(api_key="tok", base_url=base_url)
    ran: list[int] = []

    @function_tool
    def do_thing(n: int) -> str:
        ran.append(n)
        return f"did {n}"

    agent = Agent(
        name="t",
        instructions="use the tool",
        tools=[do_thing],
        model=model,
        model_settings=ModelSettings(parallel_tool_calls=parallel),
    )
    result = Runner.run_streamed(
        agent, input="please", max_turns=10, run_config=RunConfig(model_provider=provider)
    )
    async for _ in result.stream_events():
        pass
    return result, ran


def _final_history(handler: type[_Gateway]) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = handler.requests[-1]["messages"]
    return messages


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [True, False], ids=["streamed", "non-streamed"])
@pytest.mark.parametrize("scenario_name", list(SCENARIOS))
@pytest.mark.parametrize("model", MODELS)
async def test_tool_call_ids_are_repaired_on_every_route(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    model: str,
    scenario_name: str,
    *,
    stream: bool,
) -> None:
    scenario = SCENARIOS[scenario_name]
    if model.startswith("openai/") and not stream and scenario.has_null_id:
        request.applymarker(
            pytest.mark.xfail(
                strict=True,
                reason=(
                    "the Agents SDK's Chat Completions converter rejects a null tool-call id "
                    "in a non-streamed response before the turn guard sees it"
                ),
            )
        )
    with _gateway(scenario) as (base_url, handler):
        result, ran = await _run(
            monkeypatch,
            model,
            base_url,
            stream=stream,
            parallel=any(len(t) > 1 for t in scenario.turns),
        )

    assert result.final_output == "all done"
    assert len(handler.requests) == len(scenario.turns) + 1
    assert all(bool(body.get("stream")) is stream for body in handler.requests)

    history = _final_history(handler)
    call_ids = [call["id"] for m in history for call in m.get("tool_calls") or []]
    assert len(call_ids) == scenario.calls
    assert all(isinstance(call_id, str) and call_id for call_id in call_ids)
    assert len(set(call_ids)) == len(call_ids)

    outputs = {m["tool_call_id"]: m["content"] for m in history if m.get("role") == "tool"}
    assert set(outputs) == set(call_ids)

    originals = {
        turn * 10 + offset: call_id
        for turn, ids in enumerate(scenario.turns)
        for offset, call_id in enumerate(ids)
    }
    assert sorted(ran) == sorted(originals)

    # Each output still answers the call that produced it.
    id_by_n = {
        json.loads(call["function"]["arguments"])["n"]: call["id"]
        for m in history
        for call in m.get("tool_calls") or []
    }
    assert {id_by_n[n]: f"did {n}" for n in originals} == outputs

    # A usable id is kept the first time it appears; only blanks and repeats change.
    seen: set[str] = set()
    for n, original in sorted(originals.items()):
        if isinstance(original, str) and original and original not in seen:
            assert id_by_n[n] == original
            seen.add(original)


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [True, False], ids=["streamed", "non-streamed"])
@pytest.mark.parametrize("model", MODELS)
async def test_blank_call_id_is_rejected_on_every_route_without_the_guard(
    monkeypatch: pytest.MonkeyPatch, model: str, *, stream: bool
) -> None:
    # Repro: with the turn guard removed, an empty id reaches the provider on
    # every route, so the matrix above is exercising the repair and not a
    # route that happens to fill ids in on its own.
    monkeypatch.setattr(strix_models, "_TurnGuardModel", lambda model, **_: model)
    with (
        _gateway(SCENARIOS["empty-id"]) as (base_url, _handler),
        pytest.raises(Exception, match="must include a non-empty"),
    ):
        await _run(monkeypatch, model, base_url, stream=stream, parallel=False)
