"""Per-scan OOB sidecar session lifecycle.

Mirrors ``strix/runtime/session_manager.py`` for the interactsh-client sidecar:
``create_or_reuse`` brings up the OOB listener (or reuses a cached one) and
returns a ready ``OobProvider`` bound to the scan's run directory.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents.sandbox.entries import BaseEntry, LocalDir
from agents.sandbox.manifest import Environment, Manifest

from strix.config import load_settings
from strix.core.oob.models import OobConfig
from strix.core.paths import run_dir_for
from strix.runtime.backends import get_backend
from strix.runtime.oob.bootstrap import bootstrap_interactsh


if TYPE_CHECKING:
    from strix.runtime.oob.provider import OobProvider

logger = logging.getLogger(__name__)


# In-container interactsh-client port is informational; the client writes
# interactions to a log file in the mounted workspace.
_CONTAINER_OOB_LOG_PORT = 49090

_SESSION_CACHE: dict[str, dict[str, Any]] = {}


async def create_or_reuse(
    scan_id: str,
    *,
    image: str,
    run_name: str,
    local_sources: list[dict[str, str]],
    server_url: str | None = None,
    auth_token: str | None = None,
) -> dict[str, Any]:
    """Return an existing OOB session bundle for ``scan_id`` or create one.

    Each ``local_sources`` entry mounts its host ``source_path`` at
    ``/workspace/<workspace_subdir>`` inside the container, which is also
    where the interactsh-client log is written.
    """
    cached = _SESSION_CACHE.get(scan_id)
    if cached is not None:
        logger.info("Reusing existing OOB session for scan %s", scan_id)
        return cached

    entries: dict[str | Path, BaseEntry] = {}
    for src in local_sources:
        ws_subdir = src.get("workspace_subdir") or ""
        host_path = src.get("source_path") or ""
        if not ws_subdir or not host_path:
            continue
        entries[ws_subdir] = LocalDir(src=Path(host_path).expanduser().resolve())

    manifest = Manifest(
        entries=entries,
        environment=Environment(
            value={
                "PYTHONUNBUFFERED": "1",
                "HOST_GATEWAY": "host.docker.internal",
            },
        ),
    )

    backend_name = load_settings().runtime.backend
    backend = get_backend(backend_name)

    logger.info(
        "Creating OOB sandbox session for scan %s (backend=%s, image=%s)",
        scan_id,
        backend_name,
        image,
    )
    client, session = await backend(
        image=image,
        manifest=manifest,
        exposed_ports=(_CONTAINER_OOB_LOG_PORT,),
    )

    run_dir = run_dir_for(run_name)
    provider = await bootstrap_interactsh(
        session,
        run_dir=run_dir,
        config=OobConfig(server_url=server_url, auth_token=auth_token),
    )

    bundle = {
        "client": client,
        "session": session,
        "provider": provider,
    }
    _SESSION_CACHE[scan_id] = bundle
    logger.info("OOB session for scan %s ready and cached", scan_id)
    return bundle


async def get_provider(scan_id: str) -> OobProvider | None:
    """Return the cached provider for ``scan_id`` if one exists."""
    cached = _SESSION_CACHE.get(scan_id)
    if cached is None:
        return None
    return cached.get("provider")


async def cleanup(scan_id: str) -> None:
    """Tear down ``scan_id``'s OOB container and drop its cache entry."""
    bundle = _SESSION_CACHE.pop(scan_id, None)
    if bundle is None:
        logger.debug("cleanup(%s): no cached OOB session", scan_id)
        return

    provider = bundle.get("provider")
    if provider is not None:
        try:
            await provider.stop()
        except Exception:  # noqa: BLE001
            logger.debug("cleanup(%s): provider.stop() raised", scan_id, exc_info=True)

    try:
        await bundle["client"].delete(bundle["session"])
        logger.info("Cleaned up OOB sandbox session for scan %s", scan_id)
    except Exception:
        logger.exception(
            "cleanup(%s): client.delete raised; container may need manual reaping",
            scan_id,
        )
