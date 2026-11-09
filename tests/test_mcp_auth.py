"""HTTP bearer refresh regressions without network access."""

from __future__ import annotations

import asyncio
from typing import Any, cast
from unittest.mock import AsyncMock

import httpx
import pytest
from mcp.types import CallToolResult, TextContent, Tool

from strix.tools.mcp import BearerAuth, McpConnectionConfig, McpConnectionRequest, McpRegistry
from strix.tools.mcp import client as mcp_client
from strix.tools.mcp import session as mcp_session
from strix.tools.mcp.auth import RefreshingBearerAuth


def _config() -> McpConnectionConfig:
    return McpConnectionConfig(
        name="refresh",
        url="https://example.test/mcp",
        auth=BearerAuth(token="old"),  # noqa: S106  # nosec B106
    )


def _client(auth: RefreshingBearerAuth | None, handler: Any) -> httpx.AsyncClient:
    built = mcp_client._build_server(_config(), auth)
    params = cast("Any", built.server).params
    assert params["headers"] == ({} if auth else {"Authorization": "Bearer old"})
    client = cast("httpx.AsyncClient", params["httpx_client_factory"](headers=params["headers"]))
    client._transport = httpx.MockTransport(handler)
    return client


@pytest.mark.asyncio
async def test_refresh_retries_once_and_persists_across_server_builds() -> None:
    refresh = AsyncMock(return_value="new")
    session = mcp_session.SupervisedMcpSession(_config(), refresh_token=refresh)
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["Authorization"])
        return httpx.Response(200 if seen[-1] == "Bearer new" else 401)

    for _ in range(2):
        async with _client(session._bearer_auth, handler) as client:
            response = await client.post("https://example.test/mcp", content=b"payload")
            assert response.status_code == 200
    assert seen == ["Bearer old", "Bearer new", "Bearer new"]
    refresh.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("replacement", ["new", None, "old", "raises"])
async def test_concurrent_unauthorized_requests_share_refresh(replacement: str | None) -> None:
    refresh = AsyncMock(return_value=replacement)
    if replacement == "raises":
        refresh.side_effect = ValueError("refresh unavailable")
    auth = RefreshingBearerAuth("old", refresh)
    both_sent = asyncio.Event()
    old_requests = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal old_requests
        if request.headers["Authorization"] == "Bearer old":
            old_requests += 1
            if old_requests == 5:
                both_sent.set()
            await both_sent.wait()
            return httpx.Response(401)
        return httpx.Response(200)

    async with _client(auth, handler) as client:
        responses = await asyncio.wait_for(
            asyncio.gather(*(client.get("https://example.test/mcp") for _ in range(5))),
            timeout=2,
        )
    assert [response.status_code for response in responses] == [
        200 if replacement == "new" else 401
    ] * 5
    assert old_requests == 5
    refresh.assert_awaited_once()


@pytest.mark.parametrize("replacement", [None, "", "old", "new", "raises", "disabled"])
@pytest.mark.asyncio
async def test_unrecovered_401_still_retires_connection(
    replacement: str | None, caplog: pytest.LogCaptureFixture
) -> None:
    refresh = AsyncMock(return_value=replacement)
    if replacement == "raises":
        refresh.side_effect = ValueError("private-token-value")
    auth = None if replacement == "disabled" else RefreshingBearerAuth("old", refresh)
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["Authorization"])
        return httpx.Response(401)

    async with _client(auth, handler) as client:
        server = AsyncMock()

        async def call_tool(*_args: Any, **_kwargs: Any) -> None:
            response = await client.get("https://example.test/mcp")
            response.raise_for_status()

        server.call_tool = call_tool
        session = mcp_session.SupervisedMcpSession.adopt(server, name="refresh")
        result = await session.dispatch("read", {}, label="refresh_read")
        assert result["success"] is False
        assert session.is_dead
        await session.aclose()
    assert seen == (["Bearer old", "Bearer new"] if replacement == "new" else ["Bearer old"])
    assert refresh.await_count == (0 if replacement == "disabled" else 1)
    assert "private-token-value" not in caplog.text
    if replacement == "raises":
        assert "ValueError" in caplog.text


@pytest.mark.asyncio
async def test_non_401_does_not_refresh() -> None:
    refresh = AsyncMock(return_value="new")
    auth = RefreshingBearerAuth("old", refresh)
    async with _client(auth, lambda _: httpx.Response(403)) as client:
        assert (await client.get("https://example.test/mcp")).status_code == 403
    refresh.assert_not_awaited()


@pytest.mark.asyncio
async def test_registry_passes_refresher_to_session(monkeypatch: pytest.MonkeyPatch) -> None:
    refresh = AsyncMock(return_value="new")
    registry = McpRegistry()
    entry = registry.register(McpConnectionRequest(_config(), refresh_token=refresh))
    server = AsyncMock()
    captured: list[RefreshingBearerAuth] = []

    def build(_config: McpConnectionConfig, auth: RefreshingBearerAuth) -> Any:
        captured.append(auth)
        return mcp_client.BuiltMcpServer(server, None)

    monkeypatch.setattr(mcp_client, "_build_server", build)
    session = await entry.ensure_connected()
    assert entry.refresh_token is refresh
    assert captured == [session._bearer_auth]
    await session._open()
    assert captured == [session._bearer_auth, session._bearer_auth]
    await session.aclose()


@pytest.mark.asyncio
async def test_refreshed_token_can_refresh_again_after_expiry() -> None:
    refresh = AsyncMock(side_effect=["new", "newer"])
    auth = RefreshingBearerAuth("old", refresh)
    valid = "new"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200 if request.headers["Authorization"] == f"Bearer {valid}" else 401)

    async with _client(auth, handler) as client:
        assert (await client.get("https://example.test/mcp")).status_code == 200
        valid = "newer"
        assert (await client.get("https://example.test/mcp")).status_code == 200
    assert refresh.await_count == 2


@pytest.mark.parametrize("with_refresher", [True, False])
@pytest.mark.asyncio
async def test_eager_attachment_preserves_bearer_refresh(
    monkeypatch: pytest.MonkeyPatch, with_refresher: bool
) -> None:
    refresh = AsyncMock(return_value="new")
    original_build = mcp_client._build_server
    valid = "old"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200 if request.headers["Authorization"] == f"Bearer {valid}" else 401)

    def build(config: McpConnectionConfig, auth: RefreshingBearerAuth | None = None) -> Any:
        built = original_build(config, auth)
        params = cast("Any", built.server).params
        client = params["httpx_client_factory"](headers=params["headers"])
        client._transport = httpx.MockTransport(handler)
        server = AsyncMock()
        server.use_structured_content = False
        server.list_tools.return_value = [Tool(name="read", inputSchema={"type": "object"})]
        server.cleanup.side_effect = client.aclose

        async def call_tool(*_args: Any, **_kwargs: Any) -> CallToolResult:
            response = await client.post("https://example.test/mcp")
            response.raise_for_status()
            return CallToolResult(content=[TextContent(type="text", text="ok")])

        server.call_tool = call_tool
        return mcp_client.BuiltMcpServer(server, built.recorder)

    monkeypatch.setattr(mcp_client, "_build_server", build)
    registry = McpRegistry()
    try:
        connections = await mcp_client.attach_mcp_requests(
            [McpConnectionRequest(_config(), refresh_token=refresh if with_refresher else None)],
            registry,
        )
        assert len(connections) == 1
        entry = registry.get("refresh")
        assert entry is not None
        assert entry.refresh_token is (refresh if with_refresher else None)
        session = await entry.ensure_connected()
        assert await session.dispatch("read", {}, label="refresh_read") == {
            "type": "text",
            "text": "ok",
        }
        valid = "new"
        result = await session.dispatch("read", {}, label="refresh_read")
        if with_refresher:
            assert result == {"type": "text", "text": "ok"}
            assert not session.is_dead
            refresh.assert_awaited_once()
        else:
            assert result["success"] is False
            assert session.is_dead
    finally:
        await registry.close()
