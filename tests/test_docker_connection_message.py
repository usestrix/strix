from __future__ import annotations

import io

import pytest
from docker.errors import DockerException
from rich.console import Console

from strix.interface import utils
from strix.runtime import docker_connection
from strix.runtime.docker_connection import DockerConnectionError, DockerEndpoint


DOCKER_PERMISSION_ERROR = "permission denied while trying to connect to the Docker daemon socket"
DOCKER_SOCKET_HINT = "Docker socket"
DOCKER_GROUP_HINT = "docker group"


def test_docker_connection_permission_error_mentions_socket_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = io.StringIO()

    def fake_console() -> Console:
        return Console(file=output, color_system=None, force_terminal=False)

    def fail_connect() -> None:
        endpoint = DockerEndpoint(None, "default socket")
        raise DockerConnectionError(endpoint, DockerException(DOCKER_PERMISSION_ERROR))

    monkeypatch.setattr(utils, "Console", fake_console)
    monkeypatch.setattr(docker_connection, "connect_docker", fail_connect)

    with pytest.raises(SystemExit):
        utils.check_docker_connection()

    rendered = output.getvalue()
    assert DOCKER_SOCKET_HINT in rendered
    assert DOCKER_GROUP_HINT in rendered


def test_docker_connection_permission_error_on_remote_host_skips_socket_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = io.StringIO()

    def fake_console() -> Console:
        return Console(file=output, color_system=None, force_terminal=False)

    def fail_connect() -> None:
        endpoint = DockerEndpoint("tcp://10.0.0.5:2376", "DOCKER_HOST")
        raise DockerConnectionError(endpoint, DockerException(DOCKER_PERMISSION_ERROR))

    monkeypatch.setattr(utils, "Console", fake_console)
    monkeypatch.setattr(docker_connection, "connect_docker", fail_connect)

    with pytest.raises(SystemExit):
        utils.check_docker_connection()

    rendered = output.getvalue()
    assert DOCKER_SOCKET_HINT not in rendered
    assert DOCKER_GROUP_HINT not in rendered
