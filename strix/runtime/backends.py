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

    Resolution order (each step falls through on failure):
    1. ``STRIX_RUNTIME_SOCKET`` env var / config (explicit)
    2. ``DOCKER_HOST`` env var (standard docker-py mechanism)
    3. Per-backend auto-detection (e.g. Podman socket probing)
    4. ``docker.from_env()`` default
    """
    import docker

    settings = load_settings()
    socket_path = settings.runtime.socket_path

    if socket_path:
        try:
            logger.debug("Trying STRIX_RUNTIME_SOCKET: %s", socket_path)
            return docker.DockerClient(base_url=socket_path)
        except Exception as exc:
            logger.debug("STRIX_RUNTIME_SOCKET failed: %s", exc)

    if os.environ.get("DOCKER_HOST"):
        try:
            return docker.from_env()
        except Exception as exc:
            logger.debug("DOCKER_HOST connection failed: %s", exc)

    if backend_name == "podman":
        for candidate in _podman_socket_candidates():
            path = candidate.replace("unix://", "")
            if os.path.exists(path):
                try:
                    logger.debug("Trying podman socket: %s", candidate)
                    return docker.DockerClient(base_url=candidate)
                except Exception as exc:
                    logger.debug("Podman socket %s failed: %s", candidate, exc)

    return docker.from_env()


def _podman_socket_candidates() -> list[str]:
    """Return Podman socket URI candidates ordered by likelihood.

    Covers Linux rootless, Linux rootful, and macOS ``podman machine``
    (both applehv and libkrun).
    """
    candidates: list[str] = []

    # -- macOS podman machine (applehv / libkrun) --
    for entry in _macos_podman_machine_sockets():
        candidates.append(entry)

    # -- Linux rootless --
    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR")
    if xdg_runtime:
        candidates.append(f"unix://{xdg_runtime}/podman/podman.sock")
    else:
        try:
            candidates.append(f"unix:///run/user/{os.getuid()}/podman/podman.sock")
        except (AttributeError, OSError):
            pass

    # -- Linux rootful --
    candidates.append("unix:///run/podman/podman.sock")

    # -- macOS podman machine temp-dir fallback --
    tmpdir = os.environ.get("TMPDIR")
    if tmpdir:
        candidates.append(f"unix://{tmpdir}podman/podman-machine-default-api.sock")

    return candidates


def _macos_podman_machine_sockets() -> list[str]:
    """Query ``podman machine inspect`` for the exact socket path (macOS)."""
    import subprocess

    try:
        proc = subprocess.run(
            ["podman", "machine", "inspect"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []

    if proc.returncode != 0:
        return []

    try:
        import json

        machines = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []

    sockets: list[str] = []
    for m in machines:
        conn = m.get("ConnectionInfo", {})
        sock = conn.get("PodmanSocket", {})
        path = sock.get("Path")
        if path:
            sockets.append(f"unix://{path}")
    return sockets


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
