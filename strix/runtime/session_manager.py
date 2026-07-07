"""Per-scan sandbox session lifecycle."""

from __future__ import annotations

import contextlib
import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agents.sandbox.entries import BaseEntry, LocalDir
from agents.sandbox.manifest import Environment, Manifest

from strix.config import load_settings
from strix.runtime.backends import get_backend
from strix.runtime.caido_bootstrap import bootstrap_caido


logger = logging.getLogger(__name__)
SetupScriptEventSink = Callable[[dict[str, Any]], None]


# In-container Caido sidecar port (matches the image's caido-cli bind).
_CONTAINER_CAIDO_PORT = 48080


_SESSION_CACHE: dict[str, dict[str, Any]] = {}

# Manifest root inside the container; entry keys hang off this path.
_WORKSPACE_ROOT = "/workspace"
_SETUP_SCRIPT_CONTAINER_PATH = "/tmp/strix-setup-script.sh"
_SETUP_SCRIPT_TIMEOUT_SECONDS = 3600


def build_session_entries(
    local_sources: list[dict[str, Any]],
) -> tuple[dict[str | Path, BaseEntry], list[dict[str, Any]]]:
    """Split local sources into copied manifest entries and host bind mounts.

    Sources flagged ``mount`` are bind-mounted read-only at
    ``/workspace/<workspace_subdir>`` (not added to the manifest, so the SDK
    does not stream them in file-by-file). Every other source becomes a
    ``LocalDir`` entry copied into the container as before.
    """
    entries: dict[str | Path, BaseEntry] = {}
    bind_mounts: list[dict[str, Any]] = []
    for src in local_sources:
        ws_subdir = src.get("workspace_subdir") or ""
        host_path = src.get("source_path") or ""
        if not ws_subdir or not host_path:
            continue
        resolved = Path(host_path).expanduser().resolve()
        if src.get("mount"):
            bind_mounts.append(
                {
                    "source": str(resolved),
                    "target": f"{_WORKSPACE_ROOT}/{ws_subdir}",
                    "read_only": True,
                }
            )
        else:
            entries[ws_subdir] = LocalDir(src=resolved)
    return entries, bind_mounts


def build_setup_script_mount(setup_script: str | None) -> dict[str, Any] | None:
    """Return the Docker bind-mount spec for a host setup script, if configured."""
    if not setup_script:
        return None

    resolved = Path(setup_script).expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(
            f"Setup script does not exist or is not a file: {setup_script}"
        )

    return {
        "source": str(resolved),
        "target": _SETUP_SCRIPT_CONTAINER_PATH,
        "read_only": True,
    }


def _exec_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")


def _emit_setup_script_event(
    event_sink: SetupScriptEventSink | None,
    data: dict[str, Any],
) -> None:
    if event_sink is None:
        return
    try:
        event_sink(data)
    except Exception:
        logger.exception("Setup script event sink failed")


async def execute_setup_script(
    session: Any,
    *,
    source_path: str,
    event_sink: SetupScriptEventSink | None = None,
) -> None:
    """Run the configured setup script inside the already-started sandbox."""
    logger.info("Running setup script inside sandbox: %s", _SETUP_SCRIPT_CONTAINER_PATH)
    command = f"bash {_SETUP_SCRIPT_CONTAINER_PATH}"
    started = time.perf_counter()
    _emit_setup_script_event(
        event_sink,
        {
            "status": "running",
            "source_path": source_path,
            "container_path": _SETUP_SCRIPT_CONTAINER_PATH,
            "command": command,
        },
    )
    result = await session.exec(
        "bash",
        _SETUP_SCRIPT_CONTAINER_PATH,
        timeout=_SETUP_SCRIPT_TIMEOUT_SECONDS,
    )
    elapsed = time.perf_counter() - started
    stdout = _exec_text(getattr(result, "stdout", "")).strip()
    stderr = _exec_text(getattr(result, "stderr", "")).strip()
    exit_code = getattr(result, "exit_code", "unknown")
    if result.ok():
        _emit_setup_script_event(
            event_sink,
            {
                "status": "completed",
                "source_path": source_path,
                "container_path": _SETUP_SCRIPT_CONTAINER_PATH,
                "command": command,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "duration_seconds": elapsed,
            },
        )
        if stdout:
            logger.info("Setup script completed successfully: %s", stdout[-1000:])
        else:
            logger.info("Setup script completed successfully")
        return

    _emit_setup_script_event(
        event_sink,
        {
            "status": "failed",
            "source_path": source_path,
            "container_path": _SETUP_SCRIPT_CONTAINER_PATH,
            "command": command,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "duration_seconds": elapsed,
        },
    )
    raise RuntimeError(
        "Setup script failed inside sandbox "
        f"(exit {exit_code}). stdout: {stdout[-2000:]!r} stderr: {stderr[-2000:]!r}"
    )


async def create_or_reuse(
    scan_id: str,
    *,
    image: str,
    local_sources: list[dict[str, Any]],
    setup_script: str | None = None,
    setup_script_event_sink: SetupScriptEventSink | None = None,
) -> dict[str, Any]:
    """Return the existing session bundle for ``scan_id`` or create a new one.

    Each ``local_sources`` entry exposes its host ``source_path`` at
    ``/workspace/<workspace_subdir>`` inside the container — copied in, or
    bind-mounted read-only when the entry is flagged ``mount``.
    """
    cached = _SESSION_CACHE.get(scan_id)
    if cached is not None:
        logger.info("Reusing existing sandbox session for scan %s", scan_id)
        return cached

    entries, bind_mounts = build_session_entries(local_sources)
    setup_script_mount = build_setup_script_mount(setup_script)
    if setup_script_mount is not None:
        bind_mounts.append(setup_script_mount)

    # Caido runs as an in-container sidecar; HTTP(S) traffic from any
    # process started via ``session.exec`` (the SDK's Shell tool, etc.)
    # picks up these env vars automatically. ``NO_PROXY`` keeps the
    # agent-browser CDP daemon's localhost traffic from looping back
    # through Caido.
    container_caido_url = f"http://127.0.0.1:{_CONTAINER_CAIDO_PORT}"
    manifest = Manifest(
        entries=entries,
        environment=Environment(
            value={
                "PYTHONUNBUFFERED": "1",
                "HOST_GATEWAY": "host.docker.internal",
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
    client, session = await backend(
        image=image,
        manifest=manifest,
        exposed_ports=(_CONTAINER_CAIDO_PORT,),
        bind_mounts=bind_mounts,
    )

    caido_endpoint = await session.resolve_exposed_port(_CONTAINER_CAIDO_PORT)
    host_caido_url = f"http://{caido_endpoint.host}:{caido_endpoint.port}"
    logger.debug("Caido host endpoint resolved: %s", host_caido_url)

    caido_client = await bootstrap_caido(
        session,
        host_url=host_caido_url,
        container_url=container_caido_url,
    )

    if setup_script_mount is not None:
        await execute_setup_script(
            session,
            source_path=str(setup_script_mount["source"]),
            event_sink=setup_script_event_sink,
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

    try:
        await bundle["client"].delete(bundle["session"])
        logger.info("Cleaned up sandbox session for scan %s", scan_id)
    except Exception:
        logger.exception(
            "cleanup(%s): client.delete raised; container may need manual reaping",
            scan_id,
        )
