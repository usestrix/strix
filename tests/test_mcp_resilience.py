"""Fast regression tests for MCP failure handling and lifecycle resilience."""

from __future__ import annotations

import asyncio
import importlib
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from agents.exceptions import UserError
from mcp.shared.exceptions import McpError
from mcp.types import ErrorData

from strix.tools.mcp import BearerAuth, McpConnectionConfig
from strix.tools.mcp import client as mcp_client
from strix.tools.mcp import session as mcp_session
from strix.tools.mcp.failures import FailureInfo, HttpStatusRecorder, classify


_test_mcp_client = importlib.import_module("tests.test_mcp_client")
FakeMCPServer: Any = _test_mcp_client.FakeMCPServer
_mcp_tool: Any = _test_mcp_client._mcp_tool


def _http_error(status: int, *, retry_after: str | None = None) -> httpx.HTTPStatusError:
    request = httpx.Request(
        "POST",
        "https://provider.example/tools?token=secret-query",
        headers={"Authorization": "Bearer secret-header"},
        content=b"secret-body",
    )
    response = httpx.Response(
        status,
        request=request,
        headers={"Retry-After": retry_after} if retry_after else None,
    )
    return httpx.HTTPStatusError("provider failure", request=request, response=response)


@pytest.mark.parametrize(
    ("exc", "kind"),
    [
        (_http_error(401), "auth"),
        (_http_error(429), "rate_limit"),
        (_http_error(503), "server"),
        (_http_error(404), "protocol"),
        (httpx.ReadTimeout("timed out"), "timeout"),
        (httpx.ConnectError("disconnected"), "transport"),
        (McpError(ErrorData(code=-1, message="bad response")), "protocol"),
        (UserError("Failed to call tool: HTTP error 403"), "auth"),
    ],
)
def test_classifies_failures(exc: BaseException, kind: str) -> None:
    assert classify(exc).kind == kind


def test_classifies_nested_exception_groups_by_specificity() -> None:
    error = ExceptionGroup(
        "outer",
        [ExceptionGroup("inner", [httpx.ConnectError("down"), _http_error(401)])],
    )
    info = classify(error)
    assert info.kind == "auth"
    assert info.status == 401
    assert info.retryable is False


def test_retry_after_parses_seconds_and_http_date() -> None:
    seconds = HttpStatusRecorder()
    seconds(_http_error(429, retry_after="12").response)
    assert seconds.take() is not None
    assert seconds.take() is None

    date = (datetime.now(UTC) + timedelta(seconds=20)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    recorder = HttpStatusRecorder()
    recorder(_http_error(429, retry_after=date).response)
    info = recorder.take()
    assert info is not None
    retry_after = info.retry_after
    assert retry_after is not None
    assert 0 <= retry_after <= 20


def test_recorder_only_keeps_non_sensitive_request_metadata() -> None:
    recorder = HttpStatusRecorder()
    response = _http_error(500, retry_after="3").response
    recorder(response)
    info = recorder.take()
    assert info == FailureInfo(
        "server",
        500,
        "Internal Server Error",
        3,
        "POST",
        "/tools",
    )
    assert "secret" not in repr(info)
    assert recorder.take() is None


def _config(name: str, **kwargs: Any) -> McpConnectionConfig:
    return McpConnectionConfig(
        name=name,
        url="https://provider.example/mcp",
        auth=BearerAuth(token="secret-token"),  # noqa: S106  # nosec B106
        **kwargs,
    )


async def _no_sleep(_delay: float) -> None:
    return None


def _zero_delay(_attempt: int, _retry_after: float | None) -> float:
    return 0


def _sequence_server(name: str, error: BaseException | None = None) -> Any:
    server = FakeMCPServer(name, [_mcp_tool("read")])
    original_call_tool = server.call_tool

    async def call_tool(tool_name: str, arguments: dict[str, Any] | None, meta: Any = None) -> Any:
        if error is not None:
            raise error
        return await original_call_tool(tool_name, arguments, meta)

    server.call_tool = call_tool
    return server


@pytest.mark.asyncio
async def test_rate_limit_retries_and_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mcp_session, "_retry_delay", _zero_delay)
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    builds = iter(
        [
            _sequence_server("rate", _http_error(429, retry_after="0")),
            _sequence_server("rate"),
        ]
    )
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: next(builds))
    session = mcp_session.SupervisedMcpSession(_config("rate"))
    assert await session.start()
    result = await session.dispatch("read", {}, label="rate_read")
    assert result == {"type": "text", "text": "routed:read"}
    assert session.is_dead is False
    await session.aclose()


@pytest.mark.asyncio
async def test_server_exhaustion_quarantines_then_revives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mcp_session, "_retry_delay", _zero_delay)
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    clock = [100.0]
    monkeypatch.setattr("strix.tools.mcp.session.time.monotonic", lambda: clock[0])
    builds = iter(
        [
            _sequence_server("quarantine", _http_error(500)),
            _sequence_server("quarantine", _http_error(500)),
            _sequence_server("quarantine", _http_error(500)),
            _sequence_server("quarantine"),
        ]
    )
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: next(builds))
    session = mcp_session.SupervisedMcpSession(_config("quarantine"))
    assert await session.start()
    result = await session.dispatch("read", {}, label="quarantine_read")
    assert result["success"] is False
    assert session.is_dead is False
    assert session.is_unavailable is True
    clock[0] += 31
    result = await session.dispatch("read", {}, label="quarantine_read")
    assert result == {"type": "text", "text": "routed:read"}
    await session.aclose()


@pytest.mark.asyncio
async def test_auth_failure_dies_without_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    builds = [_sequence_server("auth", _http_error(401))]
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: builds.pop())
    session = mcp_session.SupervisedMcpSession(_config("auth"))
    assert await session.start()
    result = await session.dispatch("read", {}, label="auth_read")
    assert result["success"] is False
    assert session.is_dead is True
    assert builds == []
    await session.aclose()


@pytest.mark.asyncio
async def test_cancelled_call_uses_recorded_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = HttpStatusRecorder()
    first = _sequence_server("cancelled", asyncio.CancelledError())
    first._strix_http_status_recorder = recorder
    second = _sequence_server("cancelled")
    builds = iter([first, second])
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: next(builds))
    monkeypatch.setattr(mcp_session, "_retry_delay", _zero_delay)
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)

    session = mcp_session.SupervisedMcpSession(_config("cancelled"))
    assert await session.start()
    recorder(_http_error(503).response)
    result = await session.dispatch("read", {}, label="cancelled_read")
    assert result == {"type": "text", "text": "routed:read"}
    await session.aclose()


@pytest.mark.asyncio
async def test_build_server_passes_explicit_http_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class Server:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(mcp_client, "MCPServerStreamableHttp", Server)
    config = _config(
        "values",
        http_timeout_seconds=11,
        sse_read_timeout_seconds=22,
        session_timeout_seconds=33,
    )
    mcp_client._build_server(config)
    assert captured["params"]["timeout"] == 11
    assert captured["params"]["sse_read_timeout"] == 22
    assert captured["client_session_timeout_seconds"] == 33
    factory = captured["params"]["httpx_client_factory"]
    client = factory(headers={}, timeout=httpx.Timeout(1), auth=None)
    assert client.event_hooks["response"]
    await client.aclose()


@pytest.mark.asyncio
async def test_same_name_sessions_share_concurrency_cap() -> None:
    active = 0
    peak = 0

    def slow_server() -> Any:
        server = FakeMCPServer("cap", [_mcp_tool("read")])
        original_call_tool = server.call_tool

        async def call_tool(
            tool_name: str, arguments: dict[str, Any] | None, meta: Any = None
        ) -> Any:
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            return await original_call_tool(tool_name, arguments, meta)

        server.call_tool = call_tool
        return server

    first = slow_server()
    second = slow_server()
    config = _config("cap", max_concurrent_calls=1)
    left = mcp_session.SupervisedMcpSession.adopt(first, name="cap", config=config)
    right = mcp_session.SupervisedMcpSession.adopt(second, name="cap", config=config)
    await asyncio.gather(
        left.dispatch("read", {}, label="cap_read"),
        right.dispatch("read", {}, label="cap_read"),
    )
    assert peak == 1
    await left.aclose()
    await right.aclose()


@pytest.mark.asyncio
async def test_resilience_logs_do_not_include_request_secrets(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(mcp_session, "_retry_delay", _zero_delay)
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    server = _sequence_server("redaction", _http_error(401))
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: server)
    session = mcp_session.SupervisedMcpSession(_config("redaction"))
    assert await session.start()
    with caplog.at_level("WARNING"):
        await session.dispatch("read", {}, label="redaction_read")
    assert "secret-token" not in caplog.text
    assert "secret-query" not in caplog.text
    assert "secret-header" not in caplog.text
    assert "secret-body" not in caplog.text
    await session.aclose()
