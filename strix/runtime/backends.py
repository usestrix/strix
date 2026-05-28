"""Sandbox backend registry — selected via STRIX_RUNTIME_BACKEND (default: docker)."""

from __future__ import annotations

import logging
import os
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from strix.config import load_settings


if TYPE_CHECKING:
    from agents.sandbox.manifest import Manifest


logger = logging.getLogger(__name__)


SandboxBackend = Callable[..., Awaitable[tuple[Any, Any]]]


def get_host_gateway(backend_name: str) -> str:
    """Return the host-gateway hostname for *backend_name*.

    Docker uses ``host.docker.internal``; Podman uses
    ``host.containers.internal`` (resolved automatically by Podman's
    built-in DNS, no ``--add-host`` needed).
    """
    if backend_name == "podman":
        return "host.containers.internal"
    return "host.docker.internal"


def create_docker_client(backend_name: str) -> Any:
    """Create a ``docker.DockerClient`` pointed at the right daemon.

    Resolution order:
    1. ``STRIX_RUNTIME_SOCKET`` env var / config (explicit)
    2. ``DOCKER_HOST`` env var (standard docker-py mechanism)
    3. Per-backend auto-detection (e.g. Podman socket probing)
    4. ``docker.from_env()`` default
    """
    import docker

    settings = load_settings()
    socket_path = settings.runtime.socket_path
    if socket_path:
        logger.debug("Using explicit runtime socket: %s", socket_path)
        return docker.DockerClient(base_url=socket_path)

    if os.environ.get("DOCKER_HOST"):
        return docker.from_env()

    if backend_name == "podman":
        for candidate in _podman_socket_candidates():
            path = candidate.replace("unix://", "")
            if os.path.exists(path):
                logger.debug("Auto-detected podman socket: %s", candidate)
                return docker.DockerClient(base_url=candidate)

    return docker.from_env()


def _podman_socket_candidates() -> list[str]:
    """Return Podman socket URI candidates (rootless first, then rootful)."""
    candidates: list[str] = []
    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR")
    if xdg_runtime:
        candidates.append(f"unix://{xdg_runtime}/podman/podman.sock")
    else:
        try:
            candidates.append(f"unix:///run/user/{os.getuid()}/podman/podman.sock")
        except (AttributeError, OSError):
            pass
    candidates.append("unix:///run/podman/podman.sock")
    return candidates


# -- backend factories --------------------------------------------------


async def _create_sandbox(
    *,
    image: str,
    manifest: Manifest,
    exposed_ports: tuple[int, ...],
    docker_client: Any,
    host_gateway_hostname: str,
) -> tuple[Any, Any]:
    from agents.sandbox.sandboxes.docker import DockerSandboxClientOptions

    from strix.runtime.docker_client import StrixDockerSandboxClient

    client = StrixDockerSandboxClient(
        docker_client, host_gateway_hostname=host_gateway_hostname
    )
    options = DockerSandboxClientOptions(image=image, exposed_ports=exposed_ports)
    session = await client.create(options=options, manifest=manifest)
    await session.start()
    return client, session


async def _docker_backend(
    *,
    image: str,
    manifest: Manifest,
    exposed_ports: tuple[int, ...],
) -> tuple[Any, Any]:
    """Bring up a session backed by the local Docker daemon."""
    docker_client = create_docker_client("docker")
    return await _create_sandbox(
        image=image,
        manifest=manifest,
        exposed_ports=exposed_ports,
        docker_client=docker_client,
        host_gateway_hostname=get_host_gateway("docker"),
    )


async def _podman_backend(
    *,
    image: str,
    manifest: Manifest,
    exposed_ports: tuple[int, ...],
) -> tuple[Any, Any]:
    """Bring up a session backed by a local Podman daemon.

    Uses the Docker-compatible API socket — the same ``docker-py``
    library drives it, just pointed at the Podman socket.
    """
    docker_client = create_docker_client("podman")
    return await _create_sandbox(
        image=image,
        manifest=manifest,
        exposed_ports=exposed_ports,
        docker_client=docker_client,
        host_gateway_hostname=get_host_gateway("podman"),
    )


# -- registry -----------------------------------------------------------


_BACKENDS: dict[str, SandboxBackend] = {
    "docker": _docker_backend,
    "podman": _podman_backend,
}


def get_backend(name: str) -> SandboxBackend:
    """Return the backend factory for ``name`` or raise.

    Args:
        name: Backend identifier (e.g. ``"docker"``). Match is exact;
            no fallback. Unknown values raise so config typos surface
            immediately instead of silently picking a default.
    """
    backend = _BACKENDS.get(name)
    if backend is None:
        supported = ", ".join(sorted(_BACKENDS))
        raise ValueError(
            f"Unknown STRIX_RUNTIME_BACKEND: {name!r} (supported: {supported})",
        )
    logger.debug("Selected sandbox backend: %s", name)
    return backend


def register_backend(name: str, backend: SandboxBackend) -> None:
    """Register a custom backend under ``name``.

    Intended for downstream users who ship their own runtime — register
    before any ``session_manager.create_or_reuse`` call. Re-registering
    an existing name overwrites the prior entry.
    """
    _BACKENDS[name] = backend
    logger.info("Registered sandbox backend: %s", name)


def supported_backends() -> list[str]:
    return sorted(_BACKENDS)
