"""Docker endpoint resolution and the panel printed when the daemon is unreachable."""

from __future__ import annotations

import importlib
from types import SimpleNamespace
from typing import Any, cast

import pytest
from docker.errors import DockerException
from requests.exceptions import ConnectionError as RequestsConnectionError
from urllib3.exceptions import ProtocolError

from strix.runtime import backends, docker_connection
from strix.runtime.docker_connection import (
    DockerConnectionError,
    DockerEndpoint,
    resolve_docker_endpoint,
)


cli_utils: Any = importlib.import_module("strix.interface.utils")


def _sdk_error(inner: BaseException) -> DockerException:
    """Build the exception exactly as docker-py raises it for a dead daemon."""
    protocol = ProtocolError("Connection aborted.", inner)
    requests_exc = RequestsConnectionError(protocol)
    requests_exc.__cause__ = protocol
    sdk_exc = DockerException(f"Error while fetching server API version: {requests_exc}")
    sdk_exc.__cause__ = requests_exc
    return sdk_exc


def test_docker_host_wins_over_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(docker_connection, "get_current_context_name", lambda: "desktop-linux")
    endpoint = resolve_docker_endpoint({"DOCKER_HOST": "tcp://10.0.0.5:2375"})
    assert endpoint == DockerEndpoint("tcp://10.0.0.5:2375", "DOCKER_HOST")


def test_current_context_is_used_like_the_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(docker_connection, "get_current_context_name", lambda: "desktop-linux")
    monkeypatch.setattr(
        "strix.runtime.docker_connection.ContextAPI.get_context",
        lambda _name: SimpleNamespace(
            Host="unix:///Users/me/.docker/run/docker.sock", TLSConfig=None
        ),
    )
    endpoint = resolve_docker_endpoint({})
    assert endpoint.host == "unix:///Users/me/.docker/run/docker.sock"
    assert endpoint.source == "docker context 'desktop-linux'"


def test_default_context_uses_the_sdk_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(docker_connection, "get_current_context_name", lambda: "default")
    assert resolve_docker_endpoint({}) == DockerEndpoint(None, "default socket")


def test_missing_or_broken_current_context_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(docker_connection, "get_current_context_name", lambda: "gone")
    monkeypatch.setattr(
        "strix.runtime.docker_connection.ContextAPI.get_context", lambda _name: None
    )
    with pytest.raises(
        DockerConnectionError, match="docker context 'gone' is selected but does not exist"
    ):
        resolve_docker_endpoint({})

    def boom(_name: str) -> None:
        raise DockerException("bad meta.json")

    monkeypatch.setattr("strix.runtime.docker_connection.ContextAPI.get_context", boom)
    with pytest.raises(DockerConnectionError, match="bad meta") as info:
        resolve_docker_endpoint({})
    assert info.value.endpoint.label == "docker context 'gone'"


def test_docker_host_goes_through_from_env_so_tls_settings_apply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        docker_connection,
        "resolve_docker_endpoint",
        lambda _environ=None: DockerEndpoint("tcp://10.0.0.5:2376", "DOCKER_HOST"),
    )
    client = object()
    monkeypatch.setattr("strix.runtime.docker_connection.docker.from_env", lambda: client)

    def unexpected(**_kwargs: Any) -> None:
        raise AssertionError("DOCKER_HOST must not bypass from_env")

    monkeypatch.setattr("strix.runtime.docker_connection.docker.DockerClient", unexpected)
    assert docker_connection.connect_docker() is client


def test_context_endpoint_keeps_its_tls_config(monkeypatch: pytest.MonkeyPatch) -> None:
    tls = object()
    monkeypatch.setattr(
        docker_connection,
        "resolve_docker_endpoint",
        lambda _environ=None: DockerEndpoint("tcp://remote:2376", "docker context 'remote'", tls),
    )
    seen: dict[str, Any] = {}

    def client(**kwargs: Any) -> str:
        seen.update(kwargs)
        return "client"

    monkeypatch.setattr("strix.runtime.docker_connection.docker.DockerClient", client)
    assert docker_connection.connect_docker() == "client"
    assert seen == {"base_url": "tcp://remote:2376", "tls": tls}


@pytest.mark.parametrize(
    "inner",
    [
        FileNotFoundError(2, "No such file or directory"),
        PermissionError(13, "Permission denied"),
        ConnectionRefusedError(111, "Connection refused"),
    ],
)
def test_connect_docker_surfaces_the_root_cause(
    monkeypatch: pytest.MonkeyPatch, inner: OSError
) -> None:
    monkeypatch.setattr(
        docker_connection,
        "resolve_docker_endpoint",
        lambda _environ=None: DockerEndpoint("unix:///nope.sock", "docker context 'dead'"),
    )

    def dead_client(**_kwargs: Any) -> None:
        raise _sdk_error(inner)

    monkeypatch.setattr("strix.runtime.docker_connection.docker.DockerClient", dead_client)

    with pytest.raises(DockerConnectionError) as info:
        docker_connection.connect_docker()

    assert info.value.cause is inner
    assert info.value.detail.startswith(type(inner).__name__)
    assert info.value.endpoint.host == "unix:///nope.sock"


def test_check_docker_connection_prints_endpoint_and_error_then_exits(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    reported: list[tuple[str, type | None]] = []
    monkeypatch.setattr(
        cli_utils, "report_error", lambda name, exc=None: reported.append((name, type(exc)))
    )
    error = DockerConnectionError(
        DockerEndpoint(None, "default socket"), _sdk_error(PermissionError(13, "Permission denied"))
    )

    def failing_connect() -> None:
        raise error

    monkeypatch.setattr(docker_connection, "connect_docker", failing_connect)

    with pytest.raises(SystemExit) as exit_info:
        cli_utils.check_docker_connection()

    out = capsys.readouterr().out
    assert exit_info.value.code == 1
    assert reported == [("docker_unavailable", PermissionError)]
    assert "DOCKER NOT AVAILABLE" in out
    assert "Cannot connect to Docker at default socket." in out
    assert "PermissionError: [Errno 13] Permission denied" in out
    assert "docker info" in out


def test_check_docker_connection_returns_the_client(monkeypatch: pytest.MonkeyPatch) -> None:
    client = object()
    monkeypatch.setattr(docker_connection, "connect_docker", lambda: client)
    assert cli_utils.check_docker_connection() is client


@pytest.mark.asyncio
async def test_sandbox_backend_uses_the_same_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    resolved = object()
    monkeypatch.setattr(docker_connection, "connect_docker", lambda: resolved)
    captured: dict[str, Any] = {}

    class FakeSession:
        async def start(self) -> None:
            captured["started"] = True

    class FakeClient:
        def __init__(self, docker_client: Any) -> None:
            captured["docker_client"] = docker_client

        async def create(self, *, options: Any, **_kwargs: Any) -> FakeSession:
            captured["image"] = options.image
            return FakeSession()

    monkeypatch.setattr("strix.runtime.docker_client.StrixDockerSandboxClient", FakeClient)

    client, session = await backends._docker_backend(
        image="img:1", manifest=cast("Any", SimpleNamespace()), exposed_ports=(8080,)
    )

    assert captured["docker_client"] is resolved
    assert captured == {"docker_client": resolved, "image": "img:1", "started": True}
    assert isinstance(client, FakeClient)
    assert isinstance(session, FakeSession)
