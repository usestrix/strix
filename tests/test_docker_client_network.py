"""Sandbox network override and explicit hostname mappings.

Host networking cannot use the SDK's published-port resolver: Docker reports
no container IP, and published ports are omitted. ``STRIX_DOCKER_EXTRA_HOSTS``
adds target names the sandbox does not inherit from the host hosts file.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from agents.sandbox.errors import ExposedPortUnavailableError
from agents.sandbox.manifest import Environment, Manifest
from agents.sandbox.sandboxes.docker import DockerSandboxClientOptions, DockerSandboxSession
from agents.sandbox.types import ExposedPortEndpoint
from docker import errors as docker_errors

from strix.runtime.docker_client import StrixDockerSandboxClient, StrixDockerSandboxSession


_IMAGE = "strix-sandbox:test"
_CAIDO_PORT = 48080
_GATEWAY = {"host.docker.internal": "host-gateway"}
_CAIDO_LOOPBACK_LABEL = "strix.sandbox.caido-loopback"


def _clear_network_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_DOCKER_SANDBOX_NETWORK", raising=False)
    monkeypatch.delenv("STRIX_DOCKER_EXTRA_HOSTS", raising=False)


def _client(
    *, caido_loopback: bool = False
) -> tuple[StrixDockerSandboxClient, MagicMock, MagicMock]:
    docker = MagicMock()
    container = MagicMock()
    container.id = "container-1"
    container.short_id = "container-1"
    docker.containers.create.return_value = container
    if caido_loopback:
        image = MagicMock()
        image.attrs = {"Config": {"Labels": {_CAIDO_LOOPBACK_LABEL: "true"}}}
        docker.images.get.return_value = image
    return StrixDockerSandboxClient(docker), docker, container


def _created_kwargs(docker: MagicMock) -> dict[str, Any]:
    kwargs: dict[str, Any] = docker.containers.create.call_args.kwargs
    return kwargs


async def _create_session(
    monkeypatch: pytest.MonkeyPatch,
    network: str | None,
    *,
    manifest: Manifest | None = None,
) -> tuple[Any, MagicMock, MagicMock]:
    _clear_network_env(monkeypatch)
    if network is not None:
        monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", network)
    client, docker, container = _client(caido_loopback=network == "host")
    session = await client.create(
        options=DockerSandboxClientOptions(_IMAGE, (_CAIDO_PORT,)),
        manifest=manifest,
    )
    return session, docker, container


@pytest.mark.asyncio
async def test_default_network_publishes_localhost_and_keeps_entrypoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_network_env(monkeypatch)
    client, docker, _container = _client()

    await client._create_container(_IMAGE, exposed_ports=(_CAIDO_PORT,))

    kwargs = _created_kwargs(docker)
    docker.images.get.assert_called_with(_IMAGE)
    docker.images.pull.assert_not_called()
    assert kwargs["ports"] == {f"{_CAIDO_PORT}/tcp": ("127.0.0.1", None)}
    assert kwargs["command"] == ["tail", "-f", "/dev/null"]
    assert "entrypoint" not in kwargs
    assert kwargs["cap_add"] == ["NET_ADMIN", "NET_RAW"]
    assert kwargs["extra_hosts"] == _GATEWAY
    assert "network" not in kwargs
    assert kwargs["environment"] is None


@pytest.mark.asyncio
async def test_host_network_resolves_loopback_without_container_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = Manifest(environment=Environment(value={"SCAN_TARGET": "app.htb"}))
    session, docker, container = await _create_session(monkeypatch, "host", manifest=manifest)

    kwargs = _created_kwargs(docker)
    assert "ports" not in kwargs
    assert kwargs["network"] == "host"
    assert kwargs["environment"] == {
        "SCAN_TARGET": "app.htb",
        "STRIX_CAIDO_LISTEN_ADDRESS": "127.0.0.1",
    }
    assert kwargs["extra_hosts"] == _GATEWAY
    assert type(session._inner) is StrixDockerSandboxSession

    container.attrs = {
        "NetworkSettings": {
            "Networks": {"host": {"IPAddress": "", "GlobalIPv6Address": ""}},
        }
    }
    endpoint = await session.resolve_exposed_port(_CAIDO_PORT)
    assert endpoint == ExposedPortEndpoint(host="127.0.0.1", port=_CAIDO_PORT, tls=False)
    container.reload.assert_called()

    container.reload.side_effect = docker_errors.APIError("reload failed")
    with pytest.raises(ExposedPortUnavailableError) as exc_info:
        await session.resolve_exposed_port(_CAIDO_PORT)
    assert exc_info.value.context["detail"] == "container_reload_failed"


@pytest.mark.asyncio
async def test_host_network_rejects_image_without_caido_loopback_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_network_env(monkeypatch)
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", "host")
    client, docker, _container = _client()
    docker.images.get.return_value.attrs = {"Config": {"Labels": None}}
    with pytest.raises(ValueError, match="caido-loopback"):
        await client._create_container(_IMAGE, exposed_ports=(_CAIDO_PORT,))
    docker.containers.create.assert_not_called()


@pytest.mark.asyncio
async def test_named_network_resolves_ipv4_and_ipv6(monkeypatch: pytest.MonkeyPatch) -> None:
    session, docker, container = await _create_session(monkeypatch, "lab")

    kwargs = _created_kwargs(docker)
    assert kwargs["network"] == "lab"
    assert "ports" not in kwargs
    assert kwargs["environment"] == {}
    assert type(session._inner) is StrixDockerSandboxSession
    assert session._inner.sandbox_network == "lab"

    container.attrs = {
        "NetworkSettings": {"Networks": {"lab": {"IPAddress": "172.18.0.8"}}},
    }
    assert await session.resolve_exposed_port(_CAIDO_PORT) == ExposedPortEndpoint(
        host="172.18.0.8", port=_CAIDO_PORT, tls=False
    )

    container.attrs = {
        "NetworkSettings": {
            "Networks": {"lab": {"IPAddress": "", "GlobalIPv6Address": "fd00::8"}},
        }
    }
    assert await session.resolve_exposed_port(_CAIDO_PORT) == ExposedPortEndpoint(
        host="[fd00::8]", port=_CAIDO_PORT, tls=False
    )


@pytest.mark.asyncio
async def test_named_network_missing_address_and_reload_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, _docker, container = await _create_session(monkeypatch, "lab")
    container.attrs = {"NetworkSettings": {"Networks": {"lab": {"IPAddress": ""}}}}

    with pytest.raises(ExposedPortUnavailableError) as missing:
        await session.resolve_exposed_port(_CAIDO_PORT)
    assert missing.value.context["detail"] == "container_not_on_network"

    container.reload.side_effect = docker_errors.APIError("reload failed")
    with pytest.raises(ExposedPortUnavailableError) as failed:
        await session.resolve_exposed_port(_CAIDO_PORT)
    assert failed.value.context["detail"] == "container_reload_failed"


@pytest.mark.parametrize("network", [None, "", "   "])
@pytest.mark.asyncio
async def test_unset_network_keeps_sdk_published_port_resolver(
    monkeypatch: pytest.MonkeyPatch,
    network: str | None,
) -> None:
    session, docker, container = await _create_session(monkeypatch, network)

    kwargs = _created_kwargs(docker)
    assert "network" not in kwargs
    assert kwargs["ports"] == {f"{_CAIDO_PORT}/tcp": ("127.0.0.1", None)}
    assert type(session._inner) is DockerSandboxSession
    container.attrs = {
        "NetworkSettings": {
            "Ports": {f"{_CAIDO_PORT}/tcp": [{"HostIp": "127.0.0.1", "HostPort": "35123"}]},
            "Networks": {},
        }
    }
    endpoint = await session.resolve_exposed_port(_CAIDO_PORT)
    assert endpoint == ExposedPortEndpoint(host="127.0.0.1", port=35123, tls=False)


@pytest.mark.parametrize("network", [None, "host"])
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('{"app.htb":"10.10.11.42"}', {"app.htb": "10.10.11.42"}),
        (
            '{"app.htb":"10.10.11.42","db.htb":"10.10.11.7","v6.htb":"fd00::10"}',
            {"app.htb": "10.10.11.42", "db.htb": "10.10.11.7", "v6.htb": "fd00::10"},
        ),
    ],
)
@pytest.mark.asyncio
async def test_extra_hosts_merge_with_gateway(
    monkeypatch: pytest.MonkeyPatch,
    network: str | None,
    raw: str,
    expected: dict[str, str],
) -> None:
    _clear_network_env(monkeypatch)
    if network is not None:
        monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", network)
    monkeypatch.setenv("STRIX_DOCKER_EXTRA_HOSTS", raw)
    client, docker, _container = _client(caido_loopback=network == "host")

    await client._create_container(_IMAGE, exposed_ports=(_CAIDO_PORT,))

    assert _created_kwargs(docker)["extra_hosts"] == {**_GATEWAY, **expected}


@pytest.mark.parametrize("raw", [None, "", "   "])
@pytest.mark.asyncio
async def test_blank_extra_hosts_keep_gateway_mapping(
    monkeypatch: pytest.MonkeyPatch,
    raw: str | None,
) -> None:
    _clear_network_env(monkeypatch)
    if raw is not None:
        monkeypatch.setenv("STRIX_DOCKER_EXTRA_HOSTS", raw)
    client, docker, _container = _client()

    await client._create_container(_IMAGE, exposed_ports=(_CAIDO_PORT,))

    assert _created_kwargs(docker)["extra_hosts"] == _GATEWAY


@pytest.mark.parametrize(
    ("raw", "exc_type", "match"),
    [
        ("{", ValueError, r"STRIX_DOCKER_EXTRA_HOSTS must be a JSON object"),
        ('["app.htb"]', TypeError, r"got array"),
        (
            '{"app.htb": 1}',
            TypeError,
            r"value for 'app\.htb' must be an IPv4 or IPv6 address string",
        ),
        (
            '{"app.htb": "not-an-ip"}',
            ValueError,
            r"value for 'app\.htb' is not a literal IPv4 or IPv6 address",
        ),
        ('{"": "10.0.0.1"}', ValueError, r"empty hostname"),
        ('{"   ": "10.0.0.1"}', ValueError, r"empty hostname"),
        (
            '{"host.docker.internal": "10.0.0.1"}',
            ValueError,
            r"cannot replace the reserved host\.docker\.internal mapping",
        ),
        (
            '{"HOST.Docker.Internal": "10.0.0.1"}',
            ValueError,
            r"cannot replace the reserved host\.docker\.internal mapping",
        ),
    ],
)
@pytest.mark.asyncio
async def test_extra_hosts_rejected_before_container_create(
    monkeypatch: pytest.MonkeyPatch,
    raw: str,
    exc_type: type[Exception],
    match: str,
) -> None:
    _clear_network_env(monkeypatch)
    monkeypatch.setenv("STRIX_DOCKER_EXTRA_HOSTS", raw)
    client, docker, _container = _client()

    with pytest.raises(exc_type, match=match):
        await client._create_container(_IMAGE, exposed_ports=(_CAIDO_PORT,))

    docker.containers.create.assert_not_called()
