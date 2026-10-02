"""Fix requests enforce network policy at container creation and session reuse."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from strix.fix import runtime as fix_runtime
from strix.runtime import session_manager
from strix.runtime.docker_client import StrixDockerSandboxClient


if TYPE_CHECKING:
    from agents.sandbox.manifest import Manifest


@pytest.mark.parametrize("network_allowed", [False, True])
@pytest.mark.parametrize("operator_network", ["", "operator-network"])
async def test_fix_network_policy_reaches_docker(
    monkeypatch: pytest.MonkeyPatch, network_allowed: bool, operator_network: str
) -> None:
    docker = MagicMock()
    session = SimpleNamespace(
        start=AsyncMock(),
        resolve_exposed_port=AsyncMock(
            return_value=SimpleNamespace(tls=False, host="localhost", port=48080)
        ),
    )
    settings = SimpleNamespace(runtime=SimpleNamespace(backend="docker", image="test-image"))
    monkeypatch.setattr(fix_runtime, "load_settings", lambda: settings)
    monkeypatch.setattr(session_manager, "load_settings", lambda: settings)
    monkeypatch.setattr(session_manager, "_SESSION_CACHE", {})
    bootstrap = AsyncMock()
    monkeypatch.setattr(session_manager, "bootstrap_caido", bootstrap)
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", operator_network)
    monkeypatch.setattr("docker.from_env", lambda: docker)
    monkeypatch.setattr(StrixDockerSandboxClient, "image_exists", lambda *_args: True)

    async def create(self: StrixDockerSandboxClient, *, options: Any, manifest: Manifest) -> Any:
        await self._create_container(
            options.image, manifest=manifest, exposed_ports=options.exposed_ports
        )
        return session

    monkeypatch.setattr(StrixDockerSandboxClient, "create", create)
    result = await fix_runtime._create_command_sandbox("fix", network_allowed=network_allowed)
    assert result is session
    session.start.assert_awaited_once()
    kwargs = docker.containers.create.call_args.kwargs
    if not network_allowed:
        assert kwargs["network_mode"] == "none"
        assert "network" not in kwargs
        assert "ports" not in kwargs
        session.resolve_exposed_port.assert_not_awaited()
        bootstrap.assert_not_awaited()
    else:
        assert "network_mode" not in kwargs
        if operator_network:
            assert kwargs["network"] == operator_network
            assert "ports" not in kwargs
        else:
            assert "network" not in kwargs
            assert kwargs["ports"] == {"48080/tcp": ("127.0.0.1", None)}
        await session_manager._SESSION_CACHE["fix"]["caido_client"].aclose()

    assert (
        await fix_runtime._create_command_sandbox("fix", network_allowed=network_allowed) is session
    )
    with pytest.raises(ValueError, match="different network policy"):
        await fix_runtime._create_command_sandbox("fix", network_allowed=not network_allowed)
    docker.containers.create.assert_called_once()


async def test_fix_sandbox_defaults_to_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    create = AsyncMock(return_value={"session": object()})
    monkeypatch.setattr(session_manager, "create_or_reuse", create)
    await fix_runtime._create_command_sandbox("fix")
    assert create.call_args.kwargs["network_allowed"] is False


async def test_network_isolation_rejects_unsupported_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = SimpleNamespace(runtime=SimpleNamespace(backend="custom", image="test-image"))
    backend = AsyncMock()
    monkeypatch.setattr(session_manager, "_SESSION_CACHE", {})
    monkeypatch.setattr(session_manager, "load_settings", lambda: settings)
    monkeypatch.setattr(session_manager, "get_backend", lambda _name: backend)
    with pytest.raises(ValueError, match="only supported by the Docker backend"):
        await session_manager.create_or_reuse(
            "fix", image="test-image", local_sources=[], network_allowed=False
        )
    backend.assert_not_awaited()
