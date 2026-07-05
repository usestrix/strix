"""Sandbox backend registry — selected via STRIX_RUNTIME_BACKEND (default: docker)."""

from __future__ import annotations

import logging
import os
import sys
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

    # Handle Issue #671 Edge Cases: Concurrency limits for Windows Docker Desktop
    concurrency_limits = None
    try:
        from agents.sandbox.artifacts import SandboxConcurrencyLimits
        
        # Default to 1 (serial) on Windows to prevent race conditions. 
        # Leave as None (SDK default) for Linux/WSL2 where execution is fast enough.
        default_limit = 1 if sys.platform == "win32" else None
        
        # Check for env var override (e.g., STRIX_DOCKER_CONCURRENCY=4)
        limit_val = os.environ.get("STRIX_DOCKER_CONCURRENCY", default_limit)
        
        if limit_val is not None:
            limit = int(limit_val)
            concurrency_limits = SandboxConcurrencyLimits(
                manifest_entries=limit,
                local_dir_files=limit
            )
            logger.debug(f"Applied SandboxConcurrencyLimits: {limit}")
            
    except ImportError:
        logger.warning("Could not import SandboxConcurrencyLimits from SDK. Proceeding with defaults.")
    except ValueError:
        logger.warning("STRIX_DOCKER_CONCURRENCY must be a valid integer. Proceeding with defaults.")

    client = StrixDockerSandboxClient(docker.from_env())
    client.strix_bind_mounts = bind_mounts or []
    options = DockerSandboxClientOptions(image=image, exposed_ports=exposed_ports)
    
    # Pass concurrency_limits if successfully configured
    create_kwargs = {"options": options, "manifest": manifest}
    if concurrency_limits is not None:
        create_kwargs["concurrency_limits"] = concurrency_limits
        
    session = await client.create(**create_kwargs)
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