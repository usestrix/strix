from __future__ import annotations

import io

import pytest
from docker.errors import DockerException
from rich.console import Console

from strix.interface import utils


DOCKER_PERMISSION_ERROR = "permission denied while trying to connect to the Docker daemon socket"
DOCKER_SOCKET_HINT = "Docker socket"
DOCKER_GROUP_HINT = "docker group"


def test_docker_connection_permission_error_mentions_socket_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = io.StringIO()

    def fake_console() -> Console:
        return Console(file=output, color_system=None, force_terminal=False)

    def fail_from_env() -> None:
        raise DockerException(DOCKER_PERMISSION_ERROR)

    monkeypatch.setattr(utils, "Console", fake_console)
    monkeypatch.setattr(utils.docker, "from_env", fail_from_env)

    with pytest.raises(RuntimeError, match="Docker not available"):
        utils.check_docker_connection()

    rendered = output.getvalue()
    assert DOCKER_SOCKET_HINT in rendered
    assert DOCKER_GROUP_HINT in rendered
