"""Fast regression tests for MCP failure handling and lifecycle resilience."""

from __future__ import annotations

import asyncio
import importlib
from datetime import UTC, datetime, timedelta
from typing import Any, cast

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


def _built_server(server: Any) -> Any:
    return mcp_client.BuiltMcpServer(server, None)


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
        (_http_error(403), "permission"),
        (_http_error(429), "rate_limit"),
        (_http_error(503), "server"),
        (_http_error(404), "protocol"),
        (httpx.ReadTimeout("timed out"), "timeout"),
        (httpx.ConnectError("disconnected"), "transport"),
        (McpError(ErrorData(code=-1, message="bad response")), "protocol"),
        (UserError("Failed to call tool: HTTP error 403"), "permission"),
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


def test_classifies_permission_before_rate_limit() -> None:
    error = ExceptionGroup("outer", [_http_error(429), _http_error(403)])
    info = classify(error)
    assert info.kind == "permission"
    assert info.status == 403
    assert info.retryable is False


@pytest.mark.parametrize("control_flow", [SystemExit, KeyboardInterrupt])
@pytest.mark.asyncio
async def test_control_flow_exceptions_propagate(
    control_flow: type[BaseException],
) -> None:
    server = _sequence_server("control-flow", control_flow("stop"))
    session = mcp_session.SupervisedMcpSession.adopt(server, name="control-flow")

    with pytest.raises(control_flow):
        await session.dispatch("read", {}, label="control_flow")

    await session.aclose()


@pytest.mark.asyncio
async def test_retry_after_parses_seconds_and_http_date() -> None:
    seconds = HttpStatusRecorder()
    await seconds(_http_error(429, retry_after="12").response)
    assert seconds.take() is not None
    assert seconds.take() is None

    date = (datetime.now(UTC) + timedelta(seconds=20)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    recorder = HttpStatusRecorder()
    await recorder(_http_error(429, retry_after=date).response)
    info = recorder.take()
    assert info is not None
    retry_after = info.retry_after
    assert retry_after is not None
    assert 0 <= retry_after <= 20


@pytest.mark.asyncio
async def test_recorder_only_keeps_non_sensitive_request_metadata() -> None:
    recorder = HttpStatusRecorder()
    response = _http_error(500, retry_after="3").response
    await recorder(response)
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


def _list_tools_error_server(name: str, error: BaseException) -> Any:
    server = FakeMCPServer(name, [_mcp_tool("read")])

    async def list_tools(*_args: Any, **_kwargs: Any) -> Any:
        raise error

    server.list_tools = list_tools
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
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: _built_server(next(builds)))
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
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: _built_server(next(builds)))
    session = mcp_session.SupervisedMcpSession(_config("quarantine"))
    assert await session.start()
    result = await session.dispatch("read", {}, label="quarantine_read")
    assert result["success"] is False
    assert session.is_dead is False
    assert session.is_unavailable is True
    assert session.server is None
    clock[0] += 31
    result = await session.dispatch("read", {}, label="quarantine_read")
    assert result == {"type": "text", "text": "routed:read"}
    await session.aclose()


@pytest.mark.asyncio
async def test_success_resets_quarantine_strikes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A quarantine strike must be cleared by a successful revival, so transient
    # failure bursts separated by successes do not accumulate toward permanent
    # retirement. Without the reset, three such bursts would mark the connection
    # dead even though it recovered between each one.
    monkeypatch.setattr(mcp_session, "_retry_delay", _zero_delay)
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    clock = [100.0]
    monkeypatch.setattr("strix.tools.mcp.session.time.monotonic", lambda: clock[0])
    builds = iter(
        [
            _sequence_server("strikes", _http_error(500)),
            _sequence_server("strikes", _http_error(500)),
            _sequence_server("strikes", _http_error(500)),
            _sequence_server("strikes"),
        ]
    )
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: _built_server(next(builds)))
    session = mcp_session.SupervisedMcpSession(_config("strikes"))
    assert await session.start()

    # First burst exhausts three attempts and quarantines: one strike.
    result = await session.dispatch("read", {}, label="strikes_read")
    assert result["success"] is False
    assert session._quarantine_count == 1

    # The revive succeeds, which must clear the strike back to zero.
    clock[0] += 31
    result = await session.dispatch("read", {}, label="strikes_read")
    assert result == {"type": "text", "text": "routed:read"}
    assert session._quarantine_count == 0
    assert session.is_dead is False
    await session.aclose()


@pytest.mark.asyncio
async def test_auth_failure_dies_without_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    builds = [_sequence_server("auth", _http_error(401))]
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: _built_server(builds.pop()))
    session = mcp_session.SupervisedMcpSession(_config("auth"))
    assert await session.start()
    result = await session.dispatch("read", {}, label="auth_read")
    assert result["success"] is False
    assert session.is_dead is True
    assert builds == []
    await session.aclose()


@pytest.mark.parametrize(
    ("status", "name"),
    [(403, "permission-call"), (400, "protocol-call")],
)
@pytest.mark.asyncio
async def test_call_http_rejection_preserves_session(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    name: str,
) -> None:
    first = _sequence_server(name, _http_error(status))
    second = _sequence_server(name)
    builds = iter([first, second])
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: _built_server(next(builds)))

    session = mcp_session.SupervisedMcpSession(_config(name))
    assert await session.start()
    result = await session.dispatch("read", {}, label=f"{name}_read")
    assert result["success"] is False
    assert "not the connection" in result["content"]
    assert session.is_dead is False
    assert session.is_unavailable is False
    assert session._quarantine_count == 0

    result = await session.dispatch("read", {}, label=f"{name}_read")
    assert result == {"type": "text", "text": "routed:read"}
    assert session.is_dead is False
    await session.aclose()


@pytest.mark.asyncio
async def test_call_jsonrpc_error_preserves_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A JSON-RPC error is a well-formed reply to this request, so the session stays
    # up: no reconnect, no retry, no quarantine. The streamable-HTTP client also
    # synthesizes one (status-less "Session terminated") for an HTTP 404, which some
    # providers return for a missing resource.
    error = McpError(ErrorData(code=32600, message="Session terminated"))
    builds = 0

    def build(_config: Any) -> Any:
        nonlocal builds
        builds += 1
        return _built_server(_sequence_server("rpc-error", error))

    monkeypatch.setattr(mcp_client, "_build_server", build)
    monkeypatch.setattr(mcp_session, "_retry_delay", _zero_delay)

    session = mcp_session.SupervisedMcpSession(_config("rpc-error"))
    assert await session.start()
    result = await session.dispatch("read", {}, label="rpc_error_read")
    assert result["success"] is False
    assert "not the connection" in result["content"]
    assert "still available" in result["content"]
    assert session.is_dead is False
    assert session.is_unavailable is False
    assert session._quarantine_count == 0
    assert builds == 1
    await session.aclose()


@pytest.mark.asyncio
async def test_list_tools_during_quarantine_reports_temporary_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mcp_session, "_retry_delay", _zero_delay)
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    clock = [100.0]
    monkeypatch.setattr("strix.tools.mcp.session.time.monotonic", lambda: clock[0])
    builds = iter([_sequence_server("cooldown", _http_error(500)) for _ in range(3)])
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: _built_server(next(builds)))
    session = mcp_session.SupervisedMcpSession(_config("cooldown"))
    assert await session.start()
    await session.dispatch("read", {}, label="cooldown_read")
    assert session.is_unavailable is True

    with pytest.raises(mcp_session.McpConnectionUnavailableError) as excinfo:
        await session.list_tools()
    message = str(excinfo.value)
    assert "temporarily unavailable" in message
    assert "retrying in about 30 seconds" in message
    assert "rest of this run" not in message
    await session.aclose()


@pytest.mark.asyncio
async def test_call_http_403_during_list_tools_dies() -> None:
    server = _list_tools_error_server("connect-403", _http_error(403))
    session = mcp_session.SupervisedMcpSession.adopt(
        server,
        name="connect-403",
        config=_config("connect-403"),
    )

    with pytest.raises(mcp_session.McpConnectionUnavailableError):
        await session.list_tools()
    assert session.is_dead is True
    await session.aclose()


@pytest.mark.asyncio
async def test_cancelled_call_uses_recorded_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = HttpStatusRecorder()
    first = _sequence_server("cancelled", asyncio.CancelledError())
    second = _sequence_server("cancelled")
    builds = iter(
        [
            mcp_client.BuiltMcpServer(first, recorder),
            mcp_client.BuiltMcpServer(second, None),
        ]
    )
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: next(builds))
    monkeypatch.setattr(mcp_session, "_retry_delay", _zero_delay)
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)

    session = mcp_session.SupervisedMcpSession(_config("cancelled"))
    assert await session.start()
    await recorder(_http_error(503).response)
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
async def test_http_factory_awaits_response_recorder() -> None:
    built = mcp_client._build_server(_config("hook"))
    assert built.recorder is not None
    factory = cast("Any", built.server).params["httpx_client_factory"]
    client = factory(headers={}, timeout=httpx.Timeout(1), auth=None)

    def response(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "7"}, request=request)

    client._transport = httpx.MockTransport(response)
    result = await client.get("https://provider.example/mcp?token=secret-query")
    assert result.status_code == 429
    info = built.recorder.take()
    assert info is not None
    assert info.kind == "rate_limit"
    assert info.status == 429
    assert info.retry_after == 7
    assert info.request_method == "GET"
    assert info.request_path == "/mcp"
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


def test_same_name_semaphore_works_across_event_loops() -> None:
    async def run_once() -> None:
        server = FakeMCPServer("loop-cap", [_mcp_tool("read")])
        session = mcp_session.SupervisedMcpSession.adopt(
            server,
            name="loop-cap",
            config=_config("loop-cap", max_concurrent_calls=1),
        )
        assert await session.dispatch("read", {}, label="loop_cap_read") == {
            "type": "text",
            "text": "routed:read",
        }
        await session.aclose()

    asyncio.run(run_once())
    asyncio.run(run_once())


@pytest.mark.asyncio
async def test_resilience_logs_do_not_include_request_secrets(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(mcp_session, "_retry_delay", _zero_delay)
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    server = _sequence_server("redaction", _http_error(401))
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: _built_server(server))
    session = mcp_session.SupervisedMcpSession(_config("redaction"))
    assert await session.start()
    with caplog.at_level("WARNING"):
        await session.dispatch("read", {}, label="redaction_read")
    assert "secret-token" not in caplog.text
    assert "secret-query" not in caplog.text
    assert "secret-header" not in caplog.text
    assert "secret-body" not in caplog.text
    await session.aclose()
