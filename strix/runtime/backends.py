"""Sandbox backend registry — selected via STRIX_RUNTIME_BACKEND (default: docker)."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from agents.sandbox.manifest import Manifest


logger = logging.getLogger(__name__)


SandboxBackend = Callable[..., Awaitable[tuple[Any, Any]]]


async def _docker_backend(
    *,
    image: str,
    manifest: Manifest,
    exposed_ports: tuple[int, ...],
    bind_mounts: list[dict[str, Any]] | None = None,
) -> tuple[Any, Any]:
    """Bring up a session backed by the local Docker daemon.

    Uses :class:`StrixDockerSandboxClient` to inject NET_ADMIN /
    NET_RAW caps + ``host.docker.internal`` host-gateway. Imports
    ``docker`` lazily so deployments that target a non-Docker
    backend don't need the docker-py library installed.

    ``session.start()`` is what materializes the manifest entries
    (LocalDir copies and manifest-declared volume/FUSE mounts) into the
    running container — the SDK's ``client.create()`` only builds the inner
    session object without applying the manifest. ``async with session:``
    would call it too, but Strix manages session lifetime explicitly via
    ``client.delete()`` so we trigger ``start()`` ourselves.

    ``bind_mounts`` are host directories (e.g. large repos passed via
    ``--mount``) bind-mounted read-only; unlike manifest entries they are
    applied by Docker at container-create time, not by ``start()``.
    """
    import docker
    from agents.sandbox.sandboxes.docker import DockerSandboxClientOptions

    from strix.runtime.docker_client import StrixDockerSandboxClient

    client = StrixDockerSandboxClient(docker.from_env())
    client.strix_bind_mounts = bind_mounts or []
    options = DockerSandboxClientOptions(image=image, exposed_ports=exposed_ports)
    session = await client.create(options=options, manifest=manifest)
    await session.start()
    return client, session


_BACKENDS: dict[str, SandboxBackend] = {
    "docker": _docker_backend,
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
