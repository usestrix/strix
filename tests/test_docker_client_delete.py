"""StrixDockerSandboxClient.delete() best-effort teardown.

delete() kills the sandbox container before delegating to the SDK's delete().
The kill is meant to be best-effort, but the ``contextlib.suppress`` around it
must cover the case where the docker daemon socket is already gone: then
``containers.get()`` -> ``inspect_container`` raises requests'
``ConnectionError``, which is a *sibling* of ``docker.errors.APIError`` under
``requests.RequestException`` (not a subclass), so an APIError-only suppress
would let it escape and surface a traceback on every teardown.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from agents.sandbox.sandboxes.docker import DockerSandboxClient
from docker import errors as docker_errors
from requests.exceptions import ConnectionError as RequestsConnectionError

from strix.runtime.docker_client import StrixDockerSandboxClient


def _client_with_kill_error(exc: Exception) -> StrixDockerSandboxClient:
    """A StrixDockerSandboxClient whose containers.get(...).kill() raises ``exc``."""
    client = StrixDockerSandboxClient.__new__(StrixDockerSandboxClient)
    docker_client = MagicMock()
    docker_client.containers.get.side_effect = exc
    client.docker_client = docker_client
    return client


def _session() -> object:
    # delete() reads session._inner.state.container_id
    return SimpleNamespace(_inner=SimpleNamespace(state=SimpleNamespace(container_id="abc123")))


@pytest.mark.parametrize(
    "exc",
    [
        RequestsConnectionError("Connection aborted", FileNotFoundError(2, "No such file")),
        docker_errors.NotFound("gone"),
        docker_errors.APIError("unhappy"),
    ],
)
@pytest.mark.asyncio
async def test_delete_swallows_best_effort_kill_errors(exc):
    """A torn-down socket (ConnectionError) or a gone/unhappy container
    (NotFound/APIError) during the kill must not propagate; delete() still
    delegates to the SDK's delete()."""
    client = _client_with_kill_error(exc)
    session = _session()

    with patch.object(
        DockerSandboxClient, "delete", new=AsyncMock(return_value=session)
    ) as super_delete:
        result = await client.delete(session)

    assert result is session
    super_delete.assert_awaited_once()  # teardown proceeded despite the kill error


@pytest.mark.asyncio
async def test_delete_does_not_swallow_unrelated_errors():
    """A programming error (e.g. ValueError) is not part of best-effort kill and
    must still propagate."""
    client = _client_with_kill_error(ValueError("boom"))
    with pytest.raises(ValueError):
        await client.delete(_session())


@pytest.mark.asyncio
async def test_delete_noop_without_container_id():
    """No container_id -> no kill attempt, just delegate."""
    client = StrixDockerSandboxClient.__new__(StrixDockerSandboxClient)
    client.docker_client = MagicMock()
    session = SimpleNamespace(_inner=SimpleNamespace(state=SimpleNamespace(container_id=None)))

    with patch.object(
        DockerSandboxClient, "delete", new=AsyncMock(return_value=session)
    ) as super_delete:
        await client.delete(session)

    client.docker_client.containers.get.assert_not_called()
    super_delete.assert_awaited_once()
