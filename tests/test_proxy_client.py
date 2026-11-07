"""Tests for the shared Caido client lifecycle and proxy call serialization.

Covers the caching + serialization guarantees of ``caido_api.call_with_client``
(the sandbox-imported path) and ``proxy.tools._call`` (the host-side path). The
Caido GraphQL transport is not concurrency-safe, so both paths must run one
call at a time against the shared client.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock

import pytest
from agents.tool_context import ToolContext
from caido_sdk_client.errors import OperationUserError

from strix.runtime.caido_handle import CaidoBootstrapHandle
from strix.tools.proxy import caido_api, tools


if TYPE_CHECKING:
    from collections.abc import Iterator


class _FakeClient:
    def __init__(self, name: str) -> None:
        self.name = name
        self.closed = False
        self.graphql: Any = None

    async def aclose(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def _clear_cache() -> Iterator[None]:
    caido_api._CLIENT_CACHE.clear()
    yield
    caido_api._CLIENT_CACHE.clear()


async def test_call_with_client_reuses_cached_client(monkeypatch: pytest.MonkeyPatch) -> None:
    cached = _FakeClient("cached")
    caido_api._CLIENT_CACHE["default"] = cast("Any", cached)

    async def _new() -> Any:
        raise AssertionError("_new_client must not run when a client is cached")

    monkeypatch.setattr(caido_api, "_new_client", _new)

    seen: dict[str, Any] = {}

    async def fn(client: Any) -> str:
        seen["client"] = client
        return "ok"

    assert await caido_api.call_with_client(fn) == "ok"
    assert seen["client"] is cached


async def test_call_with_client_creates_and_caches_when_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = _FakeClient("fresh")

    async def _new() -> Any:
        return created

    monkeypatch.setattr(caido_api, "_new_client", _new)

    seen: dict[str, Any] = {}

    async def fn(client: Any) -> str:
        seen["client"] = client
        return "ok"

    assert await caido_api.call_with_client(fn) == "ok"
    assert seen["client"] is created
    assert caido_api._CLIENT_CACHE["default"] is created


async def test_failed_init_does_not_poison_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _new() -> Any:
        raise ConnectionRefusedError("caido not up yet")

    monkeypatch.setattr(caido_api, "_new_client", _new)

    async def fn(_client: Any) -> str:
        return "unreachable"

    with pytest.raises(ConnectionRefusedError):
        await caido_api.call_with_client(fn)
    assert "default" not in caido_api._CLIENT_CACHE


async def test_call_with_client_propagates_errors() -> None:
    cached = _FakeClient("cached")
    caido_api._CLIENT_CACHE["default"] = cast("Any", cached)

    async def fn(_client: Any) -> str:
        raise ValueError("Invalid HTTPQL filter")

    with pytest.raises(ValueError, match="Invalid HTTPQL"):
        await caido_api.call_with_client(fn)
    assert caido_api._CLIENT_CACHE["default"] is cached


async def test_call_with_client_serializes_concurrent_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caido_api._CLIENT_CACHE["default"] = cast("Any", _FakeClient("shared"))

    async def _new() -> Any:
        raise AssertionError("no new client expected")

    monkeypatch.setattr(caido_api, "_new_client", _new)

    state = {"active": 0, "max": 0}

    async def fn(_client: Any) -> str:
        state["active"] += 1
        state["max"] = max(state["max"], state["active"])
        await asyncio.sleep(0.01)
        state["active"] -= 1
        return "ok"

    await asyncio.gather(*(caido_api.call_with_client(fn) for _ in range(6)))
    assert state["max"] == 1


async def test_host_call_serializes_concurrent_calls() -> None:
    client = _FakeClient("host")
    state = {"active": 0, "max": 0}

    async def fn(_client: Any) -> str:
        state["active"] += 1
        state["max"] = max(state["max"], state["active"])
        await asyncio.sleep(0.01)
        state["active"] -= 1
        return "ok"

    await asyncio.gather(*(tools._call(cast("Any", client), fn) for _ in range(6)))
    assert state["max"] == 1


def _headers_named(raw: bytes, name: str) -> list[str]:
    head = raw.decode("utf-8").split("\r\n\r\n", 1)[0]
    return [
        line.split(":", 1)[1].strip()
        for line in head.split("\r\n")[1:]
        if line.split(":", 1)[0].strip().lower() == name.lower()
    ]


def test_build_raw_request_recomputes_content_length_for_modified_body() -> None:
    # The captured request declared Content-Length: 12 (original body); the
    # replayed body is longer. The emitted request must carry exactly one
    # Content-Length equal to the ACTUAL body length, or the target truncates
    # the modified payload (or the connection desyncs).
    body = '{"user":"a\' OR 1=1 -- injected long payload"}'
    _conn, raw = caido_api.build_raw_request(
        method="POST",
        url="https://example.com/login",
        headers={"content-length": "12", "Content-Type": "application/json"},
        body=body,
    )
    sent_body = raw.decode("utf-8").split("\r\n\r\n", 1)[1]
    assert sent_body == body
    assert _headers_named(raw, "Content-Length") == [str(len(body.encode("utf-8")))]


def test_build_raw_request_drops_transfer_encoding_for_modified_body() -> None:
    body = '{"user":"updated"}'
    _conn, raw = caido_api.build_raw_request(
        method="POST",
        url="https://example.com/login",
        headers={
            "tRaNsFeR-EnCoDiNg": "chunked",
            "Content-Length": "7",
            "Content-Type": "application/json",
        },
        body=body,
    )
    assert _headers_named(raw, "Transfer-Encoding") == []
    assert _headers_named(raw, "Content-Length") == [str(len(body.encode("utf-8")))]


def test_build_raw_request_drops_stale_content_length_for_empty_body() -> None:
    # A body cleared to empty must not keep the inherited (non-zero) length.
    _conn, raw = caido_api.build_raw_request(
        method="POST",
        url="https://example.com/x",
        headers={"Content-Length": "12"},
        body="",
    )
    assert _headers_named(raw, "Content-Length") == []


@pytest.mark.parametrize("entrypoint", ["sandbox", "host"])
@pytest.mark.parametrize(
    ("framing", "body", "modifications", "expected_body"),
    [
        pytest.param(b"\r\n", b"\r\n  value \t\r\n", None, b"\r\n  value \t\r\n", id="unmodified"),
        pytest.param(
            b"\r\n",
            b"\r\n  value \t\r\n",
            {"headers": {"X-Replay": "changed"}},
            b"\r\n  value \t\r\n",
            id="header-only",
        ),
        pytest.param(b"\r\n", b" \t\r\n", None, b" \t\r\n", id="whitespace-only"),
        pytest.param(b"\n", b"\n  value \t\n", None, b"\n  value \t\n", id="lf-framing"),
        pytest.param(
            b"\r\n",
            "\u2003caf\u00e9\u2003".encode(),
            None,
            "\u2003caf\u00e9\u2003".encode(),
            id="unicode",
        ),
        pytest.param(b"\r\n", b"value", None, b"value", id="plain"),
        pytest.param(b"\r\n", b"", None, b"", id="empty"),
        pytest.param(
            b"\r\n",
            b" old \r\n",
            {"body": " \treplacement\r\n"},
            b" \treplacement\r\n",
            id="explicit-replacement",
        ),
        pytest.param(b"\r\n", b" old \r\n", {"body": ""}, b"", id="explicit-empty"),
    ],
)
async def test_repeat_request_preserves_body(
    entrypoint: str,
    framing: bytes,
    body: bytes,
    modifications: dict[str, Any] | None,
    expected_body: bytes,
) -> None:
    raw = (
        framing.join(
            [
                b"POST /submit HTTP/1.1",
                b"Host: example.com",
                f"Content-Length: {len(body)}".encode(),
            ]
        )
        + framing * 2
        + body
    )
    original = SimpleNamespace(raw=raw, host="example.com", is_tls=True)
    get = AsyncMock(return_value=SimpleNamespace(request=original))
    create = AsyncMock(return_value=SimpleNamespace(id="replay-fixture"))
    send = AsyncMock(
        return_value=SimpleNamespace(
            status="DONE", error=None, entry=SimpleNamespace(response=None)
        )
    )
    client = SimpleNamespace(
        request=SimpleNamespace(get=get),
        replay=SimpleNamespace(sessions=SimpleNamespace(create=create), send=send),
    )

    # Mock only the remote Caido operations; both entrypoints use the real
    # request parser, modification handling, and replay serialization.
    if entrypoint == "sandbox":
        caido_api._CLIENT_CACHE["default"] = cast("Any", client)
        result = await caido_api.repeat_request("fixture", modifications=modifications)
    else:
        arguments = json.dumps({"request_id": "fixture", "modifications": modifications})
        ctx = ToolContext(
            context={"caido_client": client},
            tool_name="repeat_request",
            tool_call_id="call-replay",
            tool_arguments=arguments,
        )
        result = json.loads(await tools.repeat_request.on_invoke_tool(ctx, arguments))

    assert result["status"] == "DONE"
    get.assert_awaited_once()
    create.assert_awaited_once_with()
    send.assert_awaited_once()
    assert send.await_args is not None
    assert send.await_args.args[0] == "replay-fixture"
    sent_raw = send.await_args.args[1].raw
    assert sent_raw.split(b"\r\n\r\n", 1)[1] == expected_body
    expected_lengths = [str(len(expected_body))] if expected_body else []
    assert _headers_named(sent_raw, "Content-Length") == expected_lengths
    if modifications and "headers" in modifications:
        assert _headers_named(sent_raw, "X-Replay") == ["changed"]


class _Ctx:
    def __init__(self, context: Any) -> None:
        self.context = context


async def test_ctx_client_returns_client_when_present() -> None:
    client = _FakeClient("host")
    got = await tools._ctx_client(cast("Any", _Ctx({"caido_client": client})))
    assert got is client


async def test_ctx_client_returns_none_without_client() -> None:
    assert await tools._ctx_client(cast("Any", _Ctx({}))) is None
    assert await tools._ctx_client(cast("Any", _Ctx(None))) is None


async def test_ctx_client_resolves_bootstrap_handle() -> None:
    client = _FakeClient("host")

    async def _bootstrap() -> Any:
        return client

    handle = CaidoBootstrapHandle(asyncio.ensure_future(_bootstrap()))
    got = await tools._ctx_client(cast("Any", _Ctx({"caido_client": handle})))
    assert got is client


async def test_ctx_client_degrades_when_bootstrap_failed() -> None:
    async def _bootstrap() -> Any:
        raise RuntimeError("caido never came up")

    handle = CaidoBootstrapHandle(asyncio.ensure_future(_bootstrap()))
    assert await tools._ctx_client(cast("Any", _Ctx({"caido_client": handle}))) is None


class _FakeGraphQL:
    def __init__(self, answers: dict[str, list[Any]]) -> None:
        self.answers = answers
        self.queries: list[tuple[str, dict[str, Any]]] = []

    async def query(self, document: str, variables: dict[str, Any]) -> dict[str, Any]:
        self.queries.append((document, dict(variables)))
        answer = self.answers[variables["id"]].pop(0)
        if isinstance(answer, Exception):
            raise answer
        return {"request": answer}


async def test_existing_request_ids_select_only_the_id() -> None:
    client = _FakeClient("host")
    graphql = _FakeGraphQL({"1042": [{"id": "1042"}], "1088": [None]})
    client.graphql = graphql

    existing = await tools.existing_request_ids(
        cast("Any", _Ctx({"caido_client": client})),
        ["1042", "1088"],
    )

    assert existing == {"1042"}
    assert [variables["id"] for _, variables in graphql.queries] == ["1042", "1088"]
    for document, _ in graphql.queries:
        assert "raw" not in document
        assert "{ id }" in document


async def test_existing_request_ids_retry_once_before_giving_up() -> None:
    client = _FakeClient("host")
    graphql = _FakeGraphQL(
        {
            "1042": [TimeoutError("deadline exceeded"), {"id": "1042"}],
            "1088": [TimeoutError("deadline exceeded"), TimeoutError("deadline exceeded")],
        }
    )
    client.graphql = graphql

    with pytest.raises(TimeoutError):
        await tools.existing_request_ids(
            cast("Any", _Ctx({"caido_client": client})),
            ["1042", "1088"],
        )

    assert [variables["id"] for _, variables in graphql.queries] == [
        "1042",
        "1042",
        "1088",
        "1088",
    ]


def test_err_logs_caido_errors_as_warnings(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING", logger="strix.tools.proxy.tools"):
        tools._err("list_requests", OperationUserError(""))

    [record] = caplog.records
    assert record.levelname == "WARNING"
