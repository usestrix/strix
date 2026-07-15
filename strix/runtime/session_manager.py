"""Per-scan sandbox session lifecycle."""

from __future__ import annotations

import asyncio
import io
import logging
import os
import tarfile
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

# Container user that runs the agent / shell tools (from the image).
_CONTAINER_USER = "pentester"


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


def _is_within(target: Path, root: Path) -> bool:
    """Return whether ``target`` is ``root`` itself or nested under it."""
    if target == root:
        return True
    try:
        target.relative_to(root)
    except ValueError:
        return False
    return True


def _pack_dir(
    tar: tarfile.TarFile,
    src: Path,
    arc_dir: str,
    root: Path,
    seen: frozenset[Path],
) -> tuple[int, int]:
    """Recursively pack ``src``'s contents into ``tar`` under ``arc_dir``.

    Returns ``(added, skipped)`` where ``added`` counts regular files (real or
    materialized from an in-tree symlink) and ``skipped`` counts dropped
    symlinks and non-regular entries. Symlinks whose target stays inside
    ``root`` are dereferenced in place; links that escape the tree, dangle, or
    form a cycle are dropped so no host / out-of-tree content leaks in.
    """
    added = 0
    skipped = 0
    for entry in os.scandir(src):
        entry_path = Path(entry.path)
        arcname = f"{arc_dir}/{entry.name}"

        if entry.is_symlink():
            target = Path(os.path.realpath(entry_path))
            if not _is_within(target, root):
                logger.warning("tar: dropping out-of-tree symlink %s -> %s", entry_path, target)
                skipped += 1
                continue
            if not target.exists():
                logger.warning("tar: dropping dangling symlink %s", entry_path)
                skipped += 1
                continue
            if target in seen:
                logger.warning("tar: dropping cyclic symlink %s -> %s", entry_path, target)
                skipped += 1
                continue
            if target.is_dir():
                tar.add(str(target), arcname=arcname, recursive=False)
                sub_added, sub_skipped = _pack_dir(tar, target, arcname, root, seen | {target})
                added += sub_added
                skipped += sub_skipped
            else:
                tar.add(str(target), arcname=arcname, recursive=False)
                added += 1
        elif entry.is_dir(follow_symlinks=False):
            tar.add(str(entry_path), arcname=arcname, recursive=False)
            sub_added, sub_skipped = _pack_dir(tar, entry_path, arcname, root, seen)
            added += sub_added
            skipped += sub_skipped
        elif entry.is_file(follow_symlinks=False):
            tar.add(str(entry_path), arcname=arcname, recursive=False)
            added += 1
        else:
            # Sockets, FIFOs, devices — not part of a source tree; skip.
            logger.debug("tar: skipping non-regular entry %s", entry_path)
            skipped += 1
    return added, skipped


def _build_source_tar(src_root: Path, arc_prefix: str) -> tuple[bytes, int, int]:
    """Pack ``src_root`` into an in-memory tar rooted at ``arc_prefix``.

    Returns ``(tar_bytes, added, skipped)``. Regular files and directories —
    including dotfiles such as ``.git`` and directories with no files — are
    packed as-is so source-aware and git-diff analysis keep working and
    committed empty dirs survive. Symlinks pointing inside the tree are
    dereferenced (their target content is materialized in place) so committed
    workspace / shared-config links still resolve inside the container; links
    that escape the tree, dangle, or form a cycle are dropped (and counted),
    avoiding host path escapes and the dangling links a naive copy would create.
    """
    buf = io.BytesIO()
    root = src_root.resolve()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        # Always pack the arc-prefix root so the workspace subdir exists even
        # when the source tree is empty.
        tar.add(str(root), arcname=arc_prefix, recursive=False)
        added, skipped = _pack_dir(tar, root, arc_prefix, root, frozenset({root}))
    return buf.getvalue(), added, skipped


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
    """Run ``cmd`` in the container as root and raise on non-zero exit.

    ``exec_run`` reports failures only via its result; an ignored ``chown``
    failure would leave sources root-owned and unwritable while session setup
    still "succeeds", so surface it here with the command's own diagnostics.
    """
    result = container.exec_run(cmd, user="root")
    if result.exit_code:
        output = result.output
        detail = output.decode("utf-8", "replace").strip() if isinstance(output, bytes) else output
        raise RuntimeError(f"container command {cmd!r} failed (exit {result.exit_code}): {detail}")


async def _import_local_sources(
    session: Any,
    copied_sources: list[dict[str, str]],
) -> None:
    """Copy each host source tree into the container via a single tar import.

    Replaces the SDK's per-file ``LocalDir`` materialization, which issues
    several ``docker exec`` calls per file. On large trees that serializes into
    thousands of exec round-trips against a non-thread-safe docker-py client,
    causing multi-minute hangs (the "stuck on loading" symptom) and occasional
    ``ExecTransportError``. ``put_archive`` lands the whole tree in one shot
    (sub-second for thousands of files).

    Safe here because the copy path attaches no Docker volume-driver mounts —
    the SDK avoids ``put_archive`` only to sidestep volume plugins that re-run
    mount setup during archive ops (docker.py:709). ``--mount`` sources use
    plain read-only bind mounts at a different subdir, which have no such
    driver.
    """
    container = _container_of(session)
    loop = asyncio.get_running_loop()

    for src in copied_sources:
        ws_subdir = src["workspace_subdir"]
        src_root = Path(src["source_path"])
        if not src_root.is_dir():
            logger.warning("Skipping non-directory local source: %s", src_root)
            continue

        tar_bytes, added, skipped = await loop.run_in_executor(
            None, _build_source_tar, src_root, ws_subdir
        )
        logger.info(
            "Importing %d files into %s/%s (skipped %d symlink entries)",
            added,
            _WORKSPACE_ROOT,
            ws_subdir,
            skipped,
        )

        def _put(tar_bytes: bytes = tar_bytes, ws_subdir: str = ws_subdir) -> None:
            _run_checked(container, ["mkdir", "-p", _WORKSPACE_ROOT])
            if not container.put_archive(_WORKSPACE_ROOT, tar_bytes):
                raise RuntimeError(f"put_archive failed for {_WORKSPACE_ROOT}/{ws_subdir}")
            # put_archive unpacks as root with the tar's host uids; hand the
            # tree to the agent's runtime user so tools can read/write it.
            _run_checked(
                container,
                [
                    "chown",
                    "-R",
                    f"{_CONTAINER_USER}:{_CONTAINER_USER}",
                    f"{_WORKSPACE_ROOT}/{ws_subdir}",
                ],
            )

        await loop.run_in_executor(None, _put)


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
