"""Per-scan sandbox session lifecycle."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import tarfile
import tempfile
from pathlib import Path
from typing import Any

from agents.sandbox.manifest import Environment, Manifest

from strix.config import load_settings
from strix.runtime.backends import get_backend
from strix.runtime.caido_bootstrap import bootstrap_caido


logger = logging.getLogger(__name__)


# In-container Caido sidecar port (matches the image's caido-cli bind).
_CONTAINER_CAIDO_PORT = 48080


_SESSION_CACHE: dict[str, dict[str, Any]] = {}

# Workspace root inside the container; sources land at ``<root>/<workspace_subdir>``.
_WORKSPACE_ROOT = "/workspace"

# Preferred non-root account on the default Strix sandbox image.
_DEFAULT_SANDBOX_USER = "pentester"


def _is_safe_workspace_subdir(ws_subdir: str) -> bool:
    """Reject subdirs that would escape ``/workspace`` when joined.

    ``ws_subdir`` becomes both a tar member prefix and a ``chown`` target, so a
    value containing ``..`` (or an absolute path) could write outside the
    intended ``/workspace/<subdir>`` tree. Callers pass values with surrounding
    slashes already stripped.
    """
    if not ws_subdir:
        return False
    return not any(part in ("..", "") for part in ws_subdir.split("/"))


def split_local_sources(
    local_sources: list[dict[str, Any]],
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    """Split local sources into tar-copied entries and host bind mounts.

    Sources flagged ``mount`` are bind-mounted read-only at
    ``/workspace/<workspace_subdir>`` (applied by Docker at container-create
    time). Every other source is copied into the container after start via a
    single tar ``put_archive`` (see :func:`_import_local_sources`).
    """
    copied: list[dict[str, str]] = []
    bind_mounts: list[dict[str, Any]] = []
    for src in local_sources:
        ws_subdir = (src.get("workspace_subdir") or "").strip("/")
        host_path = src.get("source_path") or ""
        if not ws_subdir or not host_path:
            continue
        if not _is_safe_workspace_subdir(ws_subdir):
            logger.warning("Skipping local source with unsafe workspace_subdir: %r", ws_subdir)
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
            copied.append({"source_path": str(resolved), "workspace_subdir": ws_subdir})
    return copied, bind_mounts


def _walk_onerror(err: OSError) -> None:
    """Fail the import when a directory cannot be listed.

    Default ``os.walk`` swallows listdir errors and silently omits subtrees,
    which would leave the agent with an incomplete ``/workspace`` and no signal
    that files are missing.
    """
    raise err


def _build_source_tar(src_root: Path, arc_prefix: str) -> tuple[Path, int, int]:
    """Pack ``src_root`` into a temporary tar file rooted at ``arc_prefix``.

    Returns ``(tar_path, added, skipped)``. The caller must delete ``tar_path``.
    Spills to disk (not an in-memory ``BytesIO``) so multi-GB trees do not OOM
    the host process before Docker receives the archive.

    Regular files and directories — including dotfiles such as ``.git`` and
    empty dirs — are packed as-is. Symlinks are skipped (and counted) rather
    than followed. Unreadable directories raise via :func:`_walk_onerror`.
    """
    tmp = tempfile.NamedTemporaryFile(  # noqa: SIM115 - closed explicitly below
        prefix="strix-src-",
        suffix=".tar",
        delete=False,
    )
    tar_path = Path(tmp.name)
    added = 0
    skipped = 0
    try:
        with tarfile.open(fileobj=tmp, mode="w") as tar:
            for dirpath, dirnames, filenames in os.walk(
                src_root,
                followlinks=False,
                onerror=_walk_onerror,
            ):
                kept_dirs: list[str] = []
                for name in dirnames:
                    if Path(dirpath, name).is_symlink():
                        skipped += 1
                        continue
                    kept_dirs.append(name)
                dirnames[:] = kept_dirs

                dir_abs = Path(dirpath)
                rel = dir_abs.relative_to(src_root).as_posix()
                dir_arcname = arc_prefix if rel == "." else f"{arc_prefix}/{rel}"
                tar.add(str(dir_abs), arcname=dir_arcname, recursive=False)

                for name in filenames:
                    full = dir_abs / name
                    if full.is_symlink() or not full.is_file():
                        skipped += 1
                        continue
                    arcname = f"{arc_prefix}/{full.relative_to(src_root).as_posix()}"
                    tar.add(str(full), arcname=arcname, recursive=False)
                    added += 1
        tmp.close()
    except Exception:
        tmp.close()
        with contextlib.suppress(OSError):
            tar_path.unlink(missing_ok=True)
        raise
    return tar_path, added, skipped


def _container_of(session: Any) -> Any:
    """Reach the underlying docker-py ``Container`` from an SDK session.

    The SDK wraps the backend session in an outer object; the docker backend
    exposes the real container as ``_inner._container``. Pinned to
    openai-agents==0.14.6 — re-check these private attrs on SDK bumps.
    """
    inner = getattr(session, "_inner", session)
    container = getattr(inner, "_container", None)
    if container is None:
        raise RuntimeError("could not locate docker container on sandbox session")
    return container


def _run_checked(container: Any, cmd: list[str]) -> None:
    """Run ``cmd`` in the container as root and raise on non-zero exit."""
    result = container.exec_run(cmd, user="root")
    if result.exit_code:
        output = result.output
        detail = output.decode("utf-8", "replace").strip() if isinstance(output, bytes) else output
        raise RuntimeError(f"container command {cmd!r} failed (exit {result.exit_code}): {detail}")


def _decode_exec_output(output: Any) -> str:
    if isinstance(output, bytes):
        return output.decode("utf-8", "replace").strip()
    return str(output or "").strip()


def _detect_runtime_owner(container: Any) -> str | None:
    """Return ``user:group`` for workspace ownership, or None if unknown.

    Prefers the image ``Config.User`` (works for custom images), then probes
    for the default Strix sandbox account. Never assumes a fixed username is
    always present.
    """
    try:
        attrs = getattr(container, "attrs", None)
        if not isinstance(attrs, dict) and hasattr(container, "reload"):
            with contextlib.suppress(Exception):
                container.reload()
                attrs = getattr(container, "attrs", None)
        cfg_user = str(((attrs or {}).get("Config") or {}).get("User") or "").strip()
        if cfg_user and cfg_user not in {"0", "root", "0:0"}:
            if ":" in cfg_user:
                return cfg_user
            return f"{cfg_user}:{cfg_user}"
    except Exception:  # noqa: BLE001
        logger.debug("Could not read container Config.User", exc_info=True)

    # Probe preferred default only when it actually exists in this image.
    probe = container.exec_run(
        [
            "sh",
            "-c",
            f"id -u {_DEFAULT_SANDBOX_USER} >/dev/null 2>&1 "
            f"&& printf '%s' {_DEFAULT_SANDBOX_USER}",
        ],
        user="root",
    )
    if probe.exit_code == 0 and _decode_exec_output(probe.output) == _DEFAULT_SANDBOX_USER:
        return f"{_DEFAULT_SANDBOX_USER}:{_DEFAULT_SANDBOX_USER}"
    return None


def _fix_workspace_ownership(container: Any, path: str) -> None:
    """Best-effort chown of imported sources to the container runtime user.

    ``put_archive`` extracts as root with host UIDs. On the default image we
    reassign to ``pentester``; on custom images we use ``Config.User`` when
    set. Missing users or chown failures log a warning instead of aborting
    import — the container is still usable (often as root).
    """
    owner = _detect_runtime_owner(container)
    if owner is None:
        logger.warning(
            "No non-root container user detected; leaving %s root-owned "
            "(set USER in the sandbox image or create a runtime account)",
            path,
        )
        return
    result = container.exec_run(["chown", "-R", owner, path], user="root")
    if result.exit_code:
        detail = _decode_exec_output(result.output)
        logger.warning(
            "chown %s to %s failed (exit %s): %s — continuing; tools may lack write access",
            path,
            owner,
            result.exit_code,
            detail,
        )


def _put_source_archive(container: Any, tar_path: Path, subdir: str) -> None:
    """Stream a tar file into the container and fix ownership."""
    _run_checked(container, ["mkdir", "-p", _WORKSPACE_ROOT])
    with tar_path.open("rb") as tar_stream:
        if not container.put_archive(_WORKSPACE_ROOT, tar_stream):
            raise RuntimeError(f"put_archive failed for {_WORKSPACE_ROOT}/{subdir}")
    _fix_workspace_ownership(container, f"{_WORKSPACE_ROOT}/{subdir}")


async def _import_local_sources(
    session: Any,
    copied_sources: list[dict[str, str]],
) -> None:
    """Copy each host source tree into the container via a single tar import.

    Replaces the SDK's per-file ``LocalDir`` materialization, which issues
    several ``docker exec`` calls per file. On large trees that serializes into
    thousands of exec round-trips against a non-thread-safe docker-py client,
    causing multi-minute hangs (the "stuck on loading" symptom) and occasional
    ``ExecTransportError``. ``put_archive`` lands the whole tree in one shot.

    Archives are written to a temporary file (not fully buffered in RAM) so
    large repos do not OOM the host process.
    """
    if not copied_sources:
        return

    container = _container_of(session)
    loop = asyncio.get_running_loop()

    for src in copied_sources:
        ws_subdir = src["workspace_subdir"]
        src_root = Path(src["source_path"])
        if not src_root.is_dir():
            logger.warning("Skipping non-directory local source: %s", src_root)
            continue

        tar_path, added, skipped = await loop.run_in_executor(
            None,
            _build_source_tar,
            src_root,
            ws_subdir,
        )
        logger.info(
            "Importing %d files into %s/%s (skipped %d symlink entries)",
            added,
            _WORKSPACE_ROOT,
            ws_subdir,
            skipped,
        )
        try:
            await loop.run_in_executor(
                None,
                _put_source_archive,
                container,
                tar_path,
                ws_subdir,
            )
        finally:
            with contextlib.suppress(OSError):
                tar_path.unlink(missing_ok=True)


async def _teardown_session(client: Any, session: Any) -> None:
    """Best-effort delete of a session that never made it into the cache."""
    try:
        await client.delete(session)
    except Exception:
        logger.exception(
            "Failed to tear down sandbox session after setup error; "
            "container may need manual reaping",
        )


async def create_or_reuse(
    scan_id: str,
    *,
    image: str,
    local_sources: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return the existing session bundle for ``scan_id`` or create a new one.

    Each ``local_sources`` entry exposes its host ``source_path`` at
    ``/workspace/<workspace_subdir>`` inside the container — copied in via a
    single tar ``put_archive`` after start, or bind-mounted read-only when the
    entry is flagged ``mount``.
    """
    cached = _SESSION_CACHE.get(scan_id)
    if cached is not None:
        logger.info("Reusing existing sandbox session for scan %s", scan_id)
        return cached

    copied_sources, bind_mounts = split_local_sources(local_sources)

    # Copied source trees are imported after start() via a single tar
    # ``put_archive`` (see ``_import_local_sources``) instead of the SDK's
    # per-file ``LocalDir`` exec loop, which hangs on large trees. So the
    # manifest itself carries no source entries.
    #
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
        "Creating sandbox session for scan %s (backend=%s, image=%s, copy_sources=%d, mounts=%d)",
        scan_id,
        backend_name,
        image,
        len(copied_sources),
        len(bind_mounts),
    )
    client, session = await backend(
        image=image,
        manifest=manifest,
        exposed_ports=(_CONTAINER_CAIDO_PORT,),
        bind_mounts=bind_mounts,
    )

    # Import / Caido bootstrap can fail after the container is already
    # running. Tear it down before re-raising so we never leak an uncached
    # container that ``cleanup(scan_id)`` cannot see.
    try:
        await _import_local_sources(session, copied_sources)

        caido_endpoint = await session.resolve_exposed_port(_CONTAINER_CAIDO_PORT)
        scheme = "https" if caido_endpoint.tls else "http"
        host_caido_url = f"{scheme}://{caido_endpoint.host}:{caido_endpoint.port}"
        logger.debug("Caido host endpoint resolved: %s", host_caido_url)

        caido_client = await bootstrap_caido(
            session,
            host_url=host_caido_url,
            container_url=container_caido_url,
        )
    except Exception:
        logger.exception(
            "Sandbox setup failed for scan %s after container start; tearing down",
            scan_id,
        )
        await _teardown_session(client, session)
        raise

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
