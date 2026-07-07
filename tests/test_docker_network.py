"""Tests for Docker network selection."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from strix.runtime import session_manager
from strix.runtime.docker_client import StrixDockerSandboxClient


class FakeSession:
    def __init__(self) -> None:
        self.resolve_calls: list[int] = []

    async def resolve_exposed_port(self, port: int) -> SimpleNamespace:
        self.resolve_calls.append(port)
        return SimpleNamespace(host="127.0.0.1", port=12345)


class FakeContainers:
    def __init__(self) -> None:
        self.create_kwargs: dict[str, Any] | None = None

    def create(self, **kwargs: Any) -> SimpleNamespace:
        self.create_kwargs = kwargs
        return SimpleNamespace(short_id="abc123", removed=False, remove=lambda **_kwargs: None)


class FakeNetwork:
    def __init__(self, name: str) -> None:
        self.name = name
        self.connected: list[Any] = []

    def connect(self, container: Any) -> None:
        self.connected.append(container)


class FakeNetworks:
    def __init__(self) -> None:
        self.requested: list[str] = []
        self.networks: dict[str, FakeNetwork] = {}

    def get(self, name: str) -> FakeNetwork:
        self.requested.append(name)
        network = self.networks.get(name)
        if network is None:
            network = FakeNetwork(name)
            self.networks[name] = network
        return network


class FakeDockerClient:
    def __init__(self) -> None:
        self.containers = FakeContainers()
        self.networks = FakeNetworks()
        self.images = SimpleNamespace(pull=lambda *_args, **_kwargs: None)


def _docker_sandbox_client(
    docker_network: str | None,
) -> tuple[StrixDockerSandboxClient, FakeDockerClient]:
    docker_client = FakeDockerClient()
    sandbox_client = object.__new__(StrixDockerSandboxClient)
    sandbox_client.docker_client = docker_client
    sandbox_client.strix_bind_mounts = []
    sandbox_client.strix_docker_network = docker_network
    sandbox_client.image_exists = lambda _image: True  # type: ignore[method-assign]
    return sandbox_client, docker_client


@pytest.mark.asyncio
async def test_create_or_reuse_passes_docker_network_to_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    session = FakeSession()

    async def fake_backend(
        *,
        image: str,
        manifest: Any,
        exposed_ports: tuple[int, ...],
        bind_mounts: list[dict[str, Any]] | None = None,
        docker_network: str | None = None,
    ) -> tuple[object, FakeSession]:
        del image, manifest, exposed_ports, bind_mounts
        captured["docker_network"] = docker_network
        return object(), session

    async def fake_bootstrap_caido(
        sandbox_session: FakeSession,
        *,
        host_url: str,
        container_url: str,
    ) -> object:
        del sandbox_session, host_url, container_url
        return object()

    monkeypatch.setattr(session_manager, "_SESSION_CACHE", {})
    monkeypatch.setattr(
        session_manager,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(backend="docker")),
    )
    monkeypatch.setattr(session_manager, "get_backend", lambda _name: fake_backend)
    monkeypatch.setattr(session_manager, "bootstrap_caido", fake_bootstrap_caido)

    await session_manager.create_or_reuse(
        "scan-with-docker-network",
        image="strix-test:latest",
        local_sources=[],
        docker_network="my-network",
    )

    assert captured["docker_network"] == "my-network"


@pytest.mark.asyncio
async def test_create_or_reuse_uses_local_caido_url_for_host_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    session = FakeSession()

    async def fake_backend(
        *,
        image: str,
        manifest: Any,
        exposed_ports: tuple[int, ...],
        bind_mounts: list[dict[str, Any]] | None = None,
        docker_network: str | None = None,
    ) -> tuple[object, FakeSession]:
        del image, manifest, exposed_ports, bind_mounts, docker_network
        return object(), session

    async def fake_bootstrap_caido(
        sandbox_session: FakeSession,
        *,
        host_url: str,
        container_url: str,
    ) -> object:
        del sandbox_session, container_url
        captured["host_url"] = host_url
        return object()

    monkeypatch.setattr(session_manager, "_SESSION_CACHE", {})
    monkeypatch.setattr(
        session_manager,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(backend="docker")),
    )
    monkeypatch.setattr(session_manager, "get_backend", lambda _name: fake_backend)
    monkeypatch.setattr(session_manager, "bootstrap_caido", fake_bootstrap_caido)

    await session_manager.create_or_reuse(
        "scan-with-host-network",
        image="strix-test:latest",
        local_sources=[],
        docker_network="host",
    )

    assert session.resolve_calls == []
    assert captured["host_url"] == "http://127.0.0.1:48080"


@pytest.mark.asyncio
async def test_docker_client_passes_docker_network_to_container_create() -> None:
    sandbox_client, docker_client = _docker_sandbox_client("my-network")

    await sandbox_client._create_container("strix-test:latest", exposed_ports=(48080,))

    assert docker_client.containers.create_kwargs is not None
    assert "network" not in docker_client.containers.create_kwargs
    assert "network_mode" not in docker_client.containers.create_kwargs
    assert docker_client.containers.create_kwargs["ports"] == {
        "48080/tcp": ("127.0.0.1", None),
    }
    assert docker_client.networks.requested == ["my-network"]
    assert len(docker_client.networks.networks["my-network"].connected) == 1


@pytest.mark.asyncio
async def test_docker_client_drops_port_bindings_for_host_network() -> None:
    sandbox_client, docker_client = _docker_sandbox_client("host")

    await sandbox_client._create_container("strix-test:latest", exposed_ports=(48080,))

    assert docker_client.containers.create_kwargs is not None
    assert docker_client.containers.create_kwargs["network_mode"] == "host"
    assert "network" not in docker_client.containers.create_kwargs
    assert "ports" not in docker_client.containers.create_kwargs
    assert docker_client.networks.requested == []


@pytest.mark.asyncio
async def test_docker_client_keeps_default_bridge_port_bindings() -> None:
    sandbox_client, docker_client = _docker_sandbox_client("bridge")

    await sandbox_client._create_container("strix-test:latest", exposed_ports=(48080,))

    assert docker_client.containers.create_kwargs is not None
    assert "network" not in docker_client.containers.create_kwargs
    assert "network_mode" not in docker_client.containers.create_kwargs
    assert docker_client.containers.create_kwargs["ports"] == {
        "48080/tcp": ("127.0.0.1", None),
    }
    assert docker_client.networks.requested == []
