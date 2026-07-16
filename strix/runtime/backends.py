"""Sandbox backend registry — selected via STRIX_RUNTIME_BACKEND (default: docker)."""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from agents.sandbox.manifest import Manifest


logger = logging.getLogger(__name__)


SandboxBackend = Callable[..., Awaitable[tuple[Any, Any]]]

_DEFAULT_START_ATTEMPTS = 3
_START_BACKOFF_SECONDS = 2.0
_TRANSIENT_TIMEOUT_NAMES = {
    "ConnectTimeout",
    "PoolTimeout",
    "ReadTimeout",
    "TimeoutError",
    "TimeoutException",
    "WriteTimeout",
}
_TRANSIENT_CONNECTION_NAMES = {
    "ConnectError",
    "ConnectionError",
    "ConnectionResetError",
    "ReadError",
    "WriteError",
}


def _start_attempts() -> int:
    raw = os.environ.get("STRIX_SANDBOX_START_ATTEMPTS")
    if raw is None:
        return _DEFAULT_START_ATTEMPTS
    try:
        attempts = int(raw)
    except ValueError:
        logger.warning(
            "Invalid STRIX_SANDBOX_START_ATTEMPTS=%r; using %d",
            raw,
            _DEFAULT_START_ATTEMPTS,
        )
        return _DEFAULT_START_ATTEMPTS
    if attempts < 1:
        logger.warning(
            "STRIX_SANDBOX_START_ATTEMPTS must be positive; using %d",
            _DEFAULT_START_ATTEMPTS,
        )
        return _DEFAULT_START_ATTEMPTS
    return attempts


def _exception_chain(error: BaseException) -> list[BaseException]:
    chain: list[BaseException] = []
    pending: list[BaseException | None] = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        chain.append(current)
        pending.extend(
            (
                current.__cause__,
                current.__context__,
                getattr(current, "cause", None),
            )
        )
    return chain


def _is_transient_start_error(error: BaseException) -> bool:
    for cause in _exception_chain(error):
        name = type(cause).__name__
        module = type(cause).__module__
        if isinstance(cause, TimeoutError | ConnectionError | ConnectionResetError):
            return True
        if name in _TRANSIENT_TIMEOUT_NAMES:
            return True
        if name in _TRANSIENT_CONNECTION_NAMES and (
            module.startswith(("httpcore", "httpx", "agents"))
            or name in {"ConnectionError", "ConnectionResetError"}
        ):
            return True
    return False


async def start_session_with_retry(
    client: Any,
    create_session: Callable[[], Awaitable[Any]],
    *,
    attempts: int | None = None,
) -> Any:
    """Start a sandbox session, retrying transient transport failures.

    Backend implementations should use this helper when they own both session
    creation and ``session.start()`` so failed starts can be torn down before a
    retry. The caller owns the manifest and any temporary source directories
    until this helper returns.
    """
    max_attempts = attempts if attempts is not None else _start_attempts()
    for attempt in range(1, max_attempts + 1):
        session: Any | None = None
        try:
            session = await create_session()
            assert session is not None
            await session.start()
        except Exception as exc:
            if session is not None:
                try:
                    await client.delete(session)
                except Exception as teardown_error:
                    logger.warning(
                        "Failed to tear down sandbox after start failure; aborting retry",
                        exc_info=True,
                    )
                    raise exc from teardown_error
            transient = _is_transient_start_error(exc)
            if not transient or attempt == max_attempts:
                raise
            delay = _START_BACKOFF_SECONDS * (2 ** (attempt - 1))
            logger.warning(
                "Transient sandbox start failure; retrying attempt %d/%d in %.1fs",
                attempt + 1,
                max_attempts,
                delay,
            )
            await asyncio.sleep(delay)
        else:
            return session
    raise AssertionError("sandbox start retry loop completed without returning or raising")


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
    session = await start_session_with_retry(
        client,
        lambda: client.create(options=options, manifest=manifest),
    )
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
    an existing name overwrites the prior entry. Backends that own both
    session creation and ``session.start()`` should use
    :func:`start_session_with_retry`.
    """
    _BACKENDS[name] = backend
    logger.info("Registered sandbox backend: %s", name)


def supported_backends() -> list[str]:
    return sorted(_BACKENDS)
