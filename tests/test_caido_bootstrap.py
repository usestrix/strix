"""A bootstrap that dies mid-setup must not leave its transport behind.

The bootstrap now runs concurrently with the scan start, so teardown can
cancel it at any await — including inside ``Client.connect()``, where the
client exists but no caller will ever see it to close it.
"""

from __future__ import annotations

import asyncio
import io
import sys
import types
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from agents.sandbox.errors import ExecTransportError, WorkspaceStopError

from strix.runtime.caido_bootstrap import _login_as_guest, bootstrap_caido
from strix.tools.proxy import caido_api


class _FakeExecResult:
    def __init__(
        self,
        stdout: str,
        stderr: Any = b"",
        exit_code: int = 0,
    ) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code

    def ok(self) -> bool:
        return self.exit_code == 0


class _FakeSession:
    async def exec(self, *_args: Any, **_kwargs: Any) -> _FakeExecResult:
        return _FakeExecResult('{"data":{"loginAsGuest":{"token":{"accessToken":"t"}}}}')


class _FakeClient:
    def __init__(self, connect_error: BaseException) -> None:
        self.connect_error = connect_error
        self.closed = False

    async def connect(self) -> None:
        raise self.connect_error

    async def aclose(self) -> None:
        self.closed = True


async def _bootstrap_expecting(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> _FakeClient:
    """Run a bootstrap whose ``connect()`` fails with ``error``."""
    client = _FakeClient(error)
    # The SDK is imported inside bootstrap_caido (it is slow to import), so the
    # fakes are injected as the modules it imports.
    sdk = types.ModuleType("caido_sdk_client")
    sdk.Client = lambda *_a, **_k: client  # type: ignore[attr-defined]
    sdk.TokenAuthOptions = lambda token: token  # type: ignore[attr-defined]
    sdk_types = types.ModuleType("caido_sdk_client.types")
    sdk_types.CreateProjectOptions = lambda **_k: None  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "caido_sdk_client", sdk)
    monkeypatch.setitem(sys.modules, "caido_sdk_client.types", sdk_types)

    with pytest.raises(type(error)):
        await bootstrap_caido(
            _FakeSession(),  # type: ignore[arg-type]
            host_url="http://host",
            container_url="http://container",
        )
    return client


async def test_cancellation_during_connect_closes_the_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = await _bootstrap_expecting(monkeypatch, asyncio.CancelledError())
    assert client.closed


async def test_failed_connect_closes_the_client(monkeypatch: pytest.MonkeyPatch) -> None:
    client = await _bootstrap_expecting(monkeypatch, RuntimeError("no listener"))
    assert client.closed


class _MultiResultSession:
    def __init__(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self.call_count = 0

    async def exec(self, *_args: Any, **_kwargs: Any) -> _FakeExecResult:
        self.call_count += 1
        resp = self._responses.pop(0) if self._responses else "{}"
        return _FakeExecResult(resp)


async def _instant_sleep(_s: float) -> None:
    pass


async def test_login_as_guest_retries_when_data_is_null(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(asyncio, "sleep", _instant_sleep)
    session = _MultiResultSession([
        '{"data": null, "errors": [{"message": "Could not acquire a connection to the database"}]}',
        '{"data":{"loginAsGuest":{"token":{"accessToken":"retry_ok_token"}}}}',
    ])
    token = await _login_as_guest(
        session,  # type: ignore[arg-type]
        container_url="http://container",
        attempts=3,
    )
    assert token == "retry_ok_token"  # noqa: S105
    assert session.call_count == 2


async def test_login_as_guest_retries_when_login_as_guest_is_null(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(asyncio, "sleep", _instant_sleep)
    session = _MultiResultSession([
        '{"data": {"loginAsGuest": null}}',
        '{"data":{"loginAsGuest":{"token":{"accessToken":"retry_ok_token"}}}}',
    ])
    token = await _login_as_guest(
        session,  # type: ignore[arg-type]
        container_url="http://container",
        attempts=3,
    )
    assert token == "retry_ok_token"  # noqa: S105
    assert session.call_count == 2


async def test_login_as_guest_retries_when_token_is_null(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(asyncio, "sleep", _instant_sleep)
    session = _MultiResultSession([
        '{"data": {"loginAsGuest": {"token": null}}}',
        '{"data":{"loginAsGuest":{"token":{"accessToken":"retry_ok_token"}}}}',
    ])
    token = await _login_as_guest(
        session,  # type: ignore[arg-type]
        container_url="http://container",
        attempts=3,
    )
    assert token == "retry_ok_token"  # noqa: S105
    assert session.call_count == 2


async def test_login_as_guest_retries_when_data_is_non_dict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(asyncio, "sleep", _instant_sleep)
    session = _MultiResultSession([
        '{"data": "unexpected_string"}',
        '{"data": [1, 2, 3]}',
        '{"data":{"loginAsGuest":{"token":{"accessToken":"retry_ok_token"}}}}',
    ])
    token = await _login_as_guest(
        session,  # type: ignore[arg-type]
        container_url="http://container",
        attempts=4,
    )
    assert token == "retry_ok_token"  # noqa: S105
    assert session.call_count == 3


async def test_login_as_guest_fails_when_all_attempts_return_null_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(asyncio, "sleep", _instant_sleep)
    session = _MultiResultSession([
        '{"data": null, "errors": [{"message": "busy"}]}',
        '{"data": null, "errors": [{"message": "busy"}]}',
    ])
    with pytest.raises(RuntimeError, match="loginAsGuest failed after 2 attempts"):
        await _login_as_guest(
            session,  # type: ignore[arg-type]
            container_url="http://container",
            attempts=2,
        )
    assert session.call_count == 2


def test_caido_api_login_as_guest_null_data(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"data": null, "errors": [{"message": "busy"}]}'
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = None

    monkeypatch.setattr(urllib.request, "urlopen", lambda *_a, **_k: mock_resp)

    with pytest.raises(RuntimeError, match="loginAsGuest returned no token"):
        caido_api._login_as_guest()


def test_caido_api_login_as_guest_malformed_data(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"data": "invalid_string_instead_of_dict"}'
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = None

    monkeypatch.setattr(urllib.request, "urlopen", lambda *_a, **_k: mock_resp)

    with pytest.raises(RuntimeError, match="loginAsGuest returned no token"):
        caido_api._login_as_guest()


def test_caido_api_login_as_guest_success(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_resp = MagicMock()
    mock_resp.read.return_value = (
        b'{"data": {"loginAsGuest": {"token": {"accessToken": "host_token_123"}}}}'
    )
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = None

    monkeypatch.setattr(urllib.request, "urlopen", lambda *_a, **_k: mock_resp)

    assert caido_api._login_as_guest() == "host_token_123"


async def test_login_as_guest_retries_when_session_exec_raises_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(asyncio, "sleep", _instant_sleep)

    class _ExceptionThenSuccessSession:
        def __init__(self) -> None:
            self.call_count = 0

        async def exec(self, *_args: Any, **_kwargs: Any) -> _FakeExecResult:
            self.call_count += 1
            if self.call_count == 1:
                raise TimeoutError("container exec timed out")
            return _FakeExecResult(
                '{"data":{"loginAsGuest":{"token":{"accessToken":"retry_after_exec_err"}}}}'
            )

    session = _ExceptionThenSuccessSession()
    token = await _login_as_guest(
        session,  # type: ignore[arg-type]
        container_url="http://container",
        attempts=3,
    )
    assert token == "retry_after_exec_err"  # noqa: S105
    assert session.call_count == 2


async def test_login_as_guest_handles_none_stderr_on_curl_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(asyncio, "sleep", _instant_sleep)

    class _NoneStderrThenSuccessSession:
        def __init__(self) -> None:
            self.call_count = 0

        async def exec(self, *_args: Any, **_kwargs: Any) -> _FakeExecResult:
            self.call_count += 1
            if self.call_count == 1:
                return _FakeExecResult("", stderr=None, exit_code=7)
            return _FakeExecResult(
                '{"data":{"loginAsGuest":{"token":{"accessToken":"retry_after_none_stderr"}}}}'
            )

    session = _NoneStderrThenSuccessSession()
    token = await _login_as_guest(
        session,  # type: ignore[arg-type]
        container_url="http://container",
        attempts=3,
    )
    assert token == "retry_after_none_stderr"  # noqa: S105
    assert session.call_count == 2


async def test_login_as_guest_rejects_whitespace_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(asyncio, "sleep", _instant_sleep)
    session = _MultiResultSession([
        '{"data":{"loginAsGuest":{"token":{"accessToken":"   "}}}}',
        '{"data":{"loginAsGuest":{"token":{"accessToken":"valid_token"}}}}',
    ])
    token = await _login_as_guest(
        session,  # type: ignore[arg-type]
        container_url="http://container",
        attempts=3,
    )
    assert token == "valid_token"  # noqa: S105
    assert session.call_count == 2


def test_caido_api_login_as_guest_http_500_with_graphql_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    err_body = b'{"errors": [{"message": "database locked"}]}'
    http_err = urllib.error.HTTPError(
        url="http://127.0.0.1:8080/graphql",
        code=500,
        msg="Internal Server Error",
        hdrs={},  # type: ignore[arg-type]
        fp=io.BytesIO(err_body),
    )

    monkeypatch.setattr(urllib.request, "urlopen", MagicMock(side_effect=http_err))

    with pytest.raises(RuntimeError, match=r"HTTP 500.*database locked"):
        caido_api._login_as_guest()


def test_caido_api_login_as_guest_http_401_non_json_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http_err = urllib.error.HTTPError(
        url="http://127.0.0.1:8080/graphql",
        code=401,
        msg="Unauthorized",
        hdrs={},  # type: ignore[arg-type]
        fp=io.BytesIO(b"Unauthorized access"),
    )

    monkeypatch.setattr(urllib.request, "urlopen", MagicMock(side_effect=http_err))

    with pytest.raises(RuntimeError, match=r"HTTP 401.*Unauthorized access"):
        caido_api._login_as_guest()


def test_caido_api_login_as_guest_url_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url_err = urllib.error.URLError("Connection refused")
    monkeypatch.setattr(urllib.request, "urlopen", MagicMock(side_effect=url_err))

    with pytest.raises(RuntimeError, match="Failed to connect to Caido"):
        caido_api._login_as_guest()


async def test_login_as_guest_fails_promptly_on_permanent_transport_error() -> None:
    class _PermanentTransportSession:
        def __init__(self) -> None:
            self.call_count = 0

        async def exec(self, *_args: Any, **_kwargs: Any) -> _FakeExecResult:
            self.call_count += 1
            raise ExecTransportError(command=["curl"], message="Container gone", retryable=False)

    session = _PermanentTransportSession()
    with pytest.raises(
        RuntimeError, match=r"loginAsGuest failed permanently.*session.exec failed"
    ):
        await _login_as_guest(
            session,  # type: ignore[arg-type]
            container_url="http://container",
            attempts=10,
        )
    assert session.call_count == 1


async def test_login_as_guest_fails_promptly_on_workspace_stop_error() -> None:
    class _StoppedSession:
        def __init__(self) -> None:
            self.call_count = 0

        async def exec(self, *_args: Any, **_kwargs: Any) -> _FakeExecResult:
            self.call_count += 1
            raise WorkspaceStopError(path=Path("/workspace"))

    session = _StoppedSession()
    with pytest.raises(
        RuntimeError, match=r"loginAsGuest failed permanently.*session.exec failed"
    ):
        await _login_as_guest(
            session,  # type: ignore[arg-type]
            container_url="http://container",
            attempts=10,
        )
    assert session.call_count == 1


async def test_login_as_guest_fails_promptly_when_curl_not_found() -> None:
    class _CurlNotFoundSession:
        def __init__(self) -> None:
            self.call_count = 0

        async def exec(self, *_args: Any, **_kwargs: Any) -> _FakeExecResult:
            self.call_count += 1
            return _FakeExecResult("", stderr=b"/bin/sh: curl: not found", exit_code=127)

    session = _CurlNotFoundSession()
    with pytest.raises(RuntimeError, match="loginAsGuest failed permanently: curl exit 127"):
        await _login_as_guest(
            session,  # type: ignore[arg-type]
            container_url="http://container",
            attempts=10,
        )
    assert session.call_count == 1


async def test_login_as_guest_fails_promptly_when_curl_permission_denied() -> None:
    class _CurlPermissionDeniedSession:
        def __init__(self) -> None:
            self.call_count = 0

        async def exec(self, *_args: Any, **_kwargs: Any) -> _FakeExecResult:
            self.call_count += 1
            return _FakeExecResult("", stderr=b"/bin/sh: curl: Permission denied", exit_code=126)

    session = _CurlPermissionDeniedSession()
    with pytest.raises(RuntimeError, match="loginAsGuest failed permanently: curl exit 126"):
        await _login_as_guest(
            session,  # type: ignore[arg-type]
            container_url="http://container",
            attempts=10,
        )
    assert session.call_count == 1


