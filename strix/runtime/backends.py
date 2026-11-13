"""Sandbox backend registry — selected via STRIX_RUNTIME_BACKEND (default: docker)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from agents.sandbox.manifest import Manifest


logger = logging.getLogger(__name__)


# Final line printed by containers/docker-entrypoint.sh once Caido, the proxy
# profile files and the NSS trust store are all set up (see #1704). The
# host must not hand the session to the agent before this line appears:
# the agent's first exec_command runs through ``sh -lc`` — a login shell
# that sources /etc/profile (hence /etc/profile.d/proxy.sh) — so an early
# exec can read partially-written profile files.
_ENTRYPOINT_READY_MARKER = "✅ Container ready"

# Worst case for the stock entrypoint is ~35 s (30 s Caido poll + sleep 2 +
# profile/NSS writes); CI measured ~12 s. 60 s leaves headroom while bounding
# the penalty for a custom image whose entrypoint never prints the marker
# (the wait then fails open with a warning — see below).
_ENTRYPOINT_READY_TIMEOUT_ENV = "STRIX_SANDBOX_ENTRYPOINT_READY_TIMEOUT_S"
_ENTRYPOINT_READY_POLL_ENV = "STRIX_SANDBOX_ENTRYPOINT_READY_POLL_S"
_DEFAULT_ENTRYPOINT_READY_TIMEOUT_S = 60.0
_DEFAULT_ENTRYPOINT_READY_POLL_S = 0.5


def _entrypoint_ready_timeout_s() -> float:
    try:
        return float(
            os.environ.get(_ENTRYPOINT_READY_TIMEOUT_ENV, "") or _DEFAULT_ENTRYPOINT_READY_TIMEOUT_S
        )
    except ValueError:
        return _DEFAULT_ENTRYPOINT_READY_TIMEOUT_S


def _entrypoint_ready_poll_s() -> float:
    try:
        return float(
            os.environ.get(_ENTRYPOINT_READY_POLL_ENV, "") or _DEFAULT_ENTRYPOINT_READY_POLL_S
        )
    except ValueError:
        return _DEFAULT_ENTRYPOINT_READY_POLL_S


async def _bounded_docker_call(
    func: Callable[..., Any], deadline: float, *args: Any, **kwargs: Any
) -> Any:
    """Run a synchronous docker-py call in a worker thread, bounded by the
    time left before ``deadline`` (a timed-out call keeps running in its
    thread, but the caller moves on)."""
    loop = asyncio.get_running_loop()
    remaining = deadline - loop.time()
    if remaining <= 0:
        raise TimeoutError("entrypoint readiness deadline exceeded")
    return await asyncio.wait_for(asyncio.to_thread(func, *args, **kwargs), timeout=remaining)


def _log_entrypoint_not_ready(timeout_s: float, container_id: str) -> None:
    logger.warning(
        "Sandbox entrypoint did not report ready within %.0f s "
        "(container %s); proceeding — first commands may race "
        "entrypoint bootstrap (see #1704)",
        timeout_s,
        container_id,
    )


async def _wait_for_entrypoint_ready(client: Any, session: Any) -> None:
    """Block until the sandbox entrypoint reports itself ready (see #1704).

    Polls the container logs for ``_ENTRYPOINT_READY_MARKER``. Logs are
    read host-side, so the wait itself needs no ``exec`` into the container
    and cannot race the bootstrap it is waiting for. docker-py is
    synchronous, so every Docker call (lookup, log read, ``reload``) runs
    in a worker thread, and each one is bounded by the time left before
    the deadline — a slow daemon cannot stall the TUI or hold startup
    past the timeout.

    The wait fails open: if the marker never appears within the timeout
    (e.g. a custom image whose entrypoint does not print it) the session
    is returned anyway with a warning, so a non-stock image cannot hang
    scans. A container that *exits* before printing the marker is a hard
    error instead — the session would be unusable, and the log tail is
    attached to the exception. Set
    ``STRIX_SANDBOX_ENTRYPOINT_READY_TIMEOUT_S<=0`` to disable the wait.
    """
    inner = getattr(session, "_inner", None)
    container_id = getattr(getattr(inner, "state", None), "container_id", None)
    if not container_id:
        logger.debug("Entrypoint readiness wait skipped: no container id on session")
        return
    timeout_s = _entrypoint_ready_timeout_s()
    if timeout_s <= 0:
        logger.debug("Entrypoint readiness wait disabled (timeout=%s)", timeout_s)
        return
    loop = asyncio.get_running_loop()
    # The deadline bounds the whole wait — lookup, Docker requests and
    # sleeps — so startup never exceeds the configured timeout.
    deadline = loop.time() + timeout_s
    poll_s = _entrypoint_ready_poll_s()

    try:
        container = await _bounded_docker_call(
            client.docker_client.containers.get, deadline, container_id
        )
    except Exception:  # noqa: BLE001
        logger.warning(
            "Could not fetch sandbox container %s to wait for entrypoint readiness; "
            "proceeding without the wait",
            container_id,
            exc_info=True,
        )
        return
    while True:
        if loop.time() >= deadline:
            _log_entrypoint_not_ready(timeout_s, container_id)
            break
        try:
            raw_logs = await _bounded_docker_call(container.logs, deadline, tail=200)
        except TimeoutError:
            _log_entrypoint_not_ready(timeout_s, container_id)
            break
        except Exception:  # noqa: BLE001
            logger.warning(
                "Could not read logs of sandbox container %s while waiting for "
                "entrypoint readiness; proceeding without the wait",
                container_id,
                exc_info=True,
            )
            break
        if isinstance(raw_logs, (bytes, bytearray)):
            text = bytes(raw_logs).decode("utf-8", errors="replace")
        else:
            text = str(raw_logs)
        if _ENTRYPOINT_READY_MARKER in text:
            logger.info("Sandbox entrypoint ready (container %s)", container_id)
            break
        with contextlib.suppress(Exception):
            await _bounded_docker_call(container.reload, deadline)
        if getattr(container, "status", None) in ("exited", "dead"):
            raise RuntimeError(
                "Sandbox container "
                f"{container_id} exited before its entrypoint reported ready; "
                f"last logs:\n{text[-2000:]}"
            )
        remaining = deadline - loop.time()
        if remaining <= 0:
            _log_entrypoint_not_ready(timeout_s, container_id)
            break
        await asyncio.sleep(min(poll_s, remaining))


async def _discard_started_session(client: Any, session: Any) -> None:
    """Best-effort teardown of a session whose readiness wait failed.

    Mirrors ``session_manager.cleanup``: ``client.delete`` kills and
    removes the container, then the Docker client is closed. This runs
    inside the backend because a failed wait raises before the caller
    ever receives the client/session to cache — without it, a quit
    mid-wait or an early-exit error would strand a running (or stopped)
    sandbox no later ``cleanup(scan_id)`` could find (see #1704 review).
    The delete is shielded so a second cancellation cannot interrupt it.
    """
    try:
        await asyncio.shield(client.delete(session))
    except Exception:  # noqa: BLE001
        logger.warning(
            "Failed to delete sandbox session after the entrypoint "
            "readiness wait failed; container may need manual reaping",
            exc_info=True,
        )
    docker_client = getattr(client, "docker_client", None)
    close = getattr(docker_client, "close", None)
    if callable(close):
        with contextlib.suppress(Exception):
            close()


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
    NET_RAW caps + ``host.docker.internal`` host-gateway, on the same
    endpoint the startup check resolved (``DOCKER_HOST``, docker context,
    default socket). Imports ``docker`` lazily so deployments that target
    a non-Docker backend don't need the docker-py library installed.

    ``session.start()`` is what materializes the manifest into the running
    container — the SDK's ``client.create()`` only builds the inner session
    object without applying it. ``async with session:`` would call it too, but
    Strix manages session lifetime explicitly via ``client.delete()`` so we
    trigger ``start()`` ourselves.
    """
    from agents.sandbox.sandboxes.docker import DockerSandboxClientOptions

    from strix.runtime.docker_client import StrixDockerSandboxClient
    from strix.runtime.docker_connection import connect_docker

    client = StrixDockerSandboxClient(connect_docker())
    client.strix_bind_mounts = bind_mounts or []
    options = DockerSandboxClientOptions(image=image, exposed_ports=exposed_ports)
    session = await client.create(options=options, manifest=manifest)
    await session.start()
    # session.start() only means the container is running and the SDK
    # workspace is prepared — the image's entrypoint (Caido bootstrap,
    # proxy profile writes, NSS trust store) is still running inside it.
    # Wait for its final readiness line before the session is handed to
    # the agent; see _wait_for_entrypoint_ready and #1704. If the wait
    # fails (container exited, or the bring-up was cancelled), the
    # session is deleted here: the caller never received the client and
    # session, so no later cleanup(scan_id) could reap the container.
    try:
        await _wait_for_entrypoint_ready(client, session)
    except BaseException:
        await _discard_started_session(client, session)
        raise
    return client, session


_BACKENDS: dict[str, SandboxBackend] = {
    "docker": _docker_backend,
}

_BIND_MOUNT_BACKENDS: set[str] = {"docker"}


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


def register_backend(
    name: str,
    backend: SandboxBackend,
    *,
    supports_bind_mounts: bool = False,
) -> None:
    """Register a custom backend under ``name``.

    Intended for downstream users who ship their own runtime — register
    before any ``session_manager.create_or_reuse`` call. Re-registering
    an existing name overwrites the prior entry. ``supports_bind_mounts``
    defaults to False: a remote runtime cannot see the caller's filesystem, so
    it is handed local sources as manifest entries to upload instead.
    """
    _BACKENDS[name] = backend
    if supports_bind_mounts:
        _BIND_MOUNT_BACKENDS.add(name)
    else:
        _BIND_MOUNT_BACKENDS.discard(name)
    logger.info("Registered sandbox backend: %s (bind mounts: %s)", name, supports_bind_mounts)


def backend_supports_bind_mounts(name: str) -> bool:
    return name in _BIND_MOUNT_BACKENDS


def supported_backends() -> list[str]:
    return sorted(_BACKENDS)
