"""Per-scan sandbox session lifecycle."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents.sandbox.manifest import Environment, Manifest

from strix.config import load_settings
from strix.runtime.backends import get_backend
from strix.runtime.caido_bootstrap import bootstrap_caido


if TYPE_CHECKING:
    from strix.runtime.status import StatusSink


logger = logging.getLogger(__name__)


# In-container Caido sidecar port (matches the image's caido-cli bind).
_CONTAINER_CAIDO_PORT = 48080


_SESSION_CACHE: dict[str, dict[str, Any]] = {}

# Manifest root inside the container; entry keys hang off this path.
_WORKSPACE_ROOT = "/workspace"


def _host_identity_env() -> dict[str, str]:
    """Return the host uid/gid for the container to adopt, when it applies.

    Bind mounts keep the host's ownership, so on Linux a container user whose
    uid differs from the host user's cannot write into the mounted tree. The
    image's entrypoint remaps its own user to these ids when they are present.
    Docker Desktop (macOS/Windows) already translates ownership at the
    virtiofs/gRPC-FUSE layer, so the remap is neither needed nor correct there.
    """
    if sys.platform != "linux":
        return {}
    return {"STRIX_HOST_UID": str(os.getuid()), "STRIX_HOST_GID": str(os.getgid())}


def build_bind_mounts(local_sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map local sources onto ``/workspace/<workspace_subdir>`` bind mounts.

    Every source is bind-mounted writable: the agent needs to patch files and
    drop PoC scripts next to the code it is testing, and a bind costs nothing
    regardless of tree size (the alternative — streaming the tree in file by
    file — stalls for minutes on real repositories).

    Writable does not mean unguarded. A source that carries its own history
    (``protect_git``) gets a second, nested read-only bind over ``.git``, so
    reads (``status``, ``diff``, ``log``, ``grep``) keep working while nothing
    the agent runs can rewrite the user's history. Docker applies mounts
    parent-first, so the nested entry lands on top of the tree mount.
    """
    bind_mounts: list[dict[str, Any]] = []
    for src in local_sources:
        ws_subdir = src.get("workspace_subdir") or ""
        host_path = src.get("source_path") or ""
        if not ws_subdir or not host_path:
            continue
        resolved = Path(host_path).expanduser().resolve()
        target = f"{_WORKSPACE_ROOT}/{ws_subdir}"
        bind_mounts.append({"source": str(resolved), "target": target, "read_only": False})
        git_dir = resolved / ".git"
        if src.get("protect_git") and git_dir.is_dir():
            bind_mounts.append(
                {"source": str(git_dir), "target": f"{target}/.git", "read_only": True}
            )
    return bind_mounts


async def create_or_reuse(
    scan_id: str,
    *,
    image: str,
    local_sources: list[dict[str, Any]],
    status_sink: StatusSink | None = None,
) -> dict[str, Any]:
    """Return the existing session bundle for ``scan_id`` or create a new one.

    Each ``local_sources`` entry exposes its host ``source_path`` at
    ``/workspace/<workspace_subdir>`` inside the container as a writable bind
    mount, with ``.git`` re-bound read-only for sources that opt into
    ``protect_git``.

    ``status_sink`` receives short human-readable phase labels so a frontend
    can show what startup is waiting on instead of an opaque spinner.
    """

    def report(phase: str) -> None:
        if status_sink is not None:
            status_sink(phase)

    cached = _SESSION_CACHE.get(scan_id)
    if cached is not None:
        logger.info("Reusing existing sandbox session for scan %s", scan_id)
        return cached

    bind_mounts = build_bind_mounts(local_sources)

    # Caido runs as an in-container sidecar; HTTP(S) traffic from any
    # process started via ``session.exec`` (the SDK's Shell tool, etc.)
    # picks up these env vars automatically. ``NO_PROXY`` keeps the
    # agent-browser CDP daemon's localhost traffic from looping back
    # through Caido.
    container_caido_url = f"http://127.0.0.1:{_CONTAINER_CAIDO_PORT}"
    manifest = Manifest(
        entries={},
        environment=Environment(
            value={
                "PYTHONUNBUFFERED": "1",
                "HOST_GATEWAY": "host.docker.internal",
                # Lets the image's entrypoint align its ``pentester`` user with
                # the owner of the bind-mounted sources, so writes into them
                # are not blocked by a host/container uid mismatch.
                **_host_identity_env(),
                "http_proxy": container_caido_url,
                "https_proxy": container_caido_url,
                "ALL_PROXY": container_caido_url,
                "NO_PROXY": "localhost,127.0.0.1",
            },
        ),
    )

    backend_name = load_settings().runtime.backend
    backend = get_backend(backend_name)

    logger.info(
        "Creating sandbox session for scan %s (backend=%s, image=%s)",
        scan_id,
        backend_name,
        image,
    )
    report("Starting sandbox container")
    client, session = await backend(
        image=image,
        manifest=manifest,
        exposed_ports=(_CONTAINER_CAIDO_PORT,),
        bind_mounts=bind_mounts,
    )

    report("Setting up the proxy")
    caido_endpoint = await session.resolve_exposed_port(_CONTAINER_CAIDO_PORT)
    scheme = "https" if caido_endpoint.tls else "http"
    host_caido_url = f"{scheme}://{caido_endpoint.host}:{caido_endpoint.port}"
    logger.debug("Caido host endpoint resolved: %s", host_caido_url)

    caido_client = await bootstrap_caido(
        session,
        host_url=host_caido_url,
        container_url=container_caido_url,
    )

    bundle = {
        "client": client,
        "session": session,
        "caido_client": caido_client,
    }
    _SESSION_CACHE[scan_id] = bundle
    logger.info("Sandbox session for scan %s ready and cached", scan_id)
    return bundle


async def cleanup(scan_id: str) -> None:
    """Tear down ``scan_id``'s container and drop its cache entry.

    Best-effort: any error during ``client.delete`` is logged and
    swallowed. We never want a cleanup failure to prevent the next
    scan from starting; the worst case is a stranded container that
    Docker's normal reaping will catch on next ``docker prune``.
    """
    bundle = _SESSION_CACHE.pop(scan_id, None)
    if bundle is None:
        logger.debug("cleanup(%s): no cached session", scan_id)
        return

    caido_client = bundle.get("caido_client")
    if caido_client is not None:
        try:
            await caido_client.aclose()
        except Exception:  # noqa: BLE001
            logger.debug("cleanup(%s): caido_client.aclose() raised", scan_id, exc_info=True)

    client = bundle["client"]
    try:
        await client.delete(bundle["session"])
        logger.info("Cleaned up sandbox session for scan %s", scan_id)
    except Exception:
        logger.exception(
            "cleanup(%s): client.delete raised; container may need manual reaping",
            scan_id,
        )

    docker_client = getattr(client, "docker_client", None)
    if docker_client is not None:
        try:
            docker_client.close()
        except Exception:  # noqa: BLE001
            logger.debug("cleanup(%s): docker_client.close() raised", scan_id, exc_info=True)
