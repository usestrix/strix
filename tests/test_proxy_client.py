"""Tests for the shared Caido client lifecycle and proxy call serialization.

Covers the caching + serialization guarantees of ``caido_api.call_with_client``
(the sandbox-imported path) and ``proxy.tools._call`` (the host-side path). The
Caido GraphQL transport is not concurrency-safe, so both paths must run one
call at a time against the shared client.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest

from strix.tools.proxy import caido_api, tools


if TYPE_CHECKING:
    from collections.abc import Iterator


class _FakeClient:
    def __init__(self, name: str) -> None:
        self.name = name
        self.closed = False

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


class _Ctx:
    def __init__(self, context: Any) -> None:
        self.context = context


def test_ctx_client_returns_client_when_present() -> None:
    client = _FakeClient("host")
    got = tools._ctx_client(cast("Any", _Ctx({"caido_client": client})))
    assert got is client


def test_ctx_client_returns_none_without_client() -> None:
    assert tools._ctx_client(cast("Any", _Ctx({}))) is None
    assert tools._ctx_client(cast("Any", _Ctx(None))) is None
