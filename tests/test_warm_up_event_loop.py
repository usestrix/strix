"""The headless warm-up must not leave pooled connections bound to its own loop.

``strix -n`` runs ``warm_up_llm`` under one ``asyncio.run`` and the scan under
another. The agents SDK hands every OpenAI client the same module-global httpx
client, so a keep-alive connection opened during warm-up belongs to a loop that
is already closed when the scan picks it back up, and the scan's first model
request dies with ``RuntimeError: Event loop is closed``.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any

import pytest
from agents.model_settings import ModelSettings
from agents.models import openai_provider as agents_openai_provider
from agents.models.interface import ModelTracing
from agents.models.openai_provider import OpenAIProvider, shared_http_client
from openai import AsyncOpenAI

from strix.config import codex, loader


if TYPE_CHECKING:
    from collections.abc import Iterator

    import httpx


cli_main: Any = importlib.import_module("strix.interface.main")


def _completion() -> dict[str, Any]:
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 0,
        "model": "gw-model",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "OK"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }


def _chunk(delta: dict[str, Any], finish_reason: str | None) -> bytes:
    payload = {
        "id": "chatcmpl-1",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "gw-model",
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
    }
    return b"data: " + json.dumps(payload).encode() + b"\n\n"


class _KeepAliveHandler(BaseHTTPRequestHandler):
    """An OpenAI-compatible gateway that keeps connections open between requests."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        request = json.loads(self.rfile.read(length) or b"{}")
        if not request.get("stream"):
            body = json.dumps(_completion()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for event in (
            _chunk({"role": "assistant", "content": "OK"}, None),
            _chunk({}, "stop"),
            b"data: [DONE]\n\n",
        ):
            self.wfile.write(b"%x\r\n%s\r\n" % (len(event), event))
        self.wfile.write(b"0\r\n\r\n")


async def _stream_turn(client: AsyncOpenAI) -> str:
    """One streamed scan turn. The SDK's model retry disables the OpenAI client's
    own retries, so a stale connection is not quietly replaced by a fresh one."""
    stream = await client.with_options(max_retries=0).chat.completions.create(
        model="gw-model",
        messages=[{"role": "user", "content": "go"}],
        stream=True,
    )
    text = ""
    async for chunk in stream:
        if chunk.choices and chunk.choices[0].delta.content:
            text += chunk.choices[0].delta.content
    await stream.close()
    return text


@pytest.fixture
def keep_alive_gateway() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _KeepAliveHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def _headless_settings(
    monkeypatch: pytest.MonkeyPatch, keep_alive_gateway: str, tmp_path: Any
) -> None:
    monkeypatch.setattr(loader, "_override", tmp_path / "no-config.json")
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-5.4")
    monkeypatch.setenv("LLM_API_KEY", "tok")
    monkeypatch.setenv("LLM_API_BASE", keep_alive_gateway)
    monkeypatch.delenv("STRIX_DEDUPE_MODEL", raising=False)
    # Start from a fresh SDK client and put the suite's one back afterwards.
    monkeypatch.setattr(agents_openai_provider, "_http_client", None)
    # Keep the warm-up from reconfiguring process-wide SDK and LiteLLM defaults.
    monkeypatch.setattr("strix.config.models.configure_sdk_model_defaults", lambda _s: None)


def test_scan_can_stream_on_the_shared_http_client_after_warm_up(
    monkeypatch: pytest.MonkeyPatch, keep_alive_gateway: str, _headless_settings: None
) -> None:
    warm_up_clients: list[httpx.AsyncClient] = []

    async def preflight(_model_name: str, *, settings: Any = None) -> None:  # noqa: ARG001
        # The real preflight's route: an SDK provider whose OpenAI client
        # rides the SDK's shared httpx client.
        warm_up_clients.append(shared_http_client())
        provider = OpenAIProvider(api_key="tok", base_url=keep_alive_gateway, use_responses=False)
        await provider.get_model("gw-model").get_response(
            system_instructions="You are a helpful assistant.",
            input="Reply with just 'OK'.",
            model_settings=ModelSettings(),
            tools=[],
            output_schema=None,
            handoffs=[],
            tracing=ModelTracing.DISABLED,
            previous_response_id=None,
            conversation_id=None,
            prompt=None,
        )

    monkeypatch.setattr(cli_main, "preflight_model_connection", preflight)

    # Loop #1: the headless warm-up, exactly as ``_bootstrap_scan`` runs it.
    asyncio.run(cli_main.warm_up_llm(show_model_warning=False))

    # Loop #2: the scan, on the same shared httpx client.
    scan_client = AsyncOpenAI(
        api_key="tok", base_url=keep_alive_gateway, http_client=shared_http_client()
    )
    assert asyncio.run(_stream_turn(scan_client)) == "OK"
    assert warm_up_clients, "the warm-up never reached the model"
    assert shared_http_client() is not warm_up_clients[0]
    assert warm_up_clients[0].is_closed


def test_scan_can_stream_on_the_subscription_client_after_warm_up(
    monkeypatch: pytest.MonkeyPatch, keep_alive_gateway: str, _headless_settings: None
) -> None:
    # ``chatgpt/<model>`` routes through Strix's own cached client instead of the
    # SDK's shared one, and that client keeps its own connection pool.
    monkeypatch.setenv("STRIX_LLM", "chatgpt/gpt-5.4")
    monkeypatch.setattr(codex, "CODEX_BASE_URL", keep_alive_gateway)
    monkeypatch.setattr(codex, "get_valid_token", lambda: ("access", "acct"))
    monkeypatch.setattr(codex, "_subscription_client", None)
    warm_up_clients: list[AsyncOpenAI] = []

    async def preflight(_model_name: str, *, settings: Any = None) -> None:  # noqa: ARG001
        client = codex.get_subscription_client()
        warm_up_clients.append(client)
        await client.chat.completions.create(
            model="gw-model", messages=[{"role": "user", "content": "Reply with just 'OK'."}]
        )

    monkeypatch.setattr(cli_main, "preflight_model_connection", preflight)

    asyncio.run(cli_main.warm_up_llm(show_model_warning=False))

    assert asyncio.run(_stream_turn(codex.get_subscription_client())) == "OK"
    assert warm_up_clients, "the warm-up never reached the model"
    assert codex.get_subscription_client() is not warm_up_clients[0]
    assert warm_up_clients[0].is_closed()
