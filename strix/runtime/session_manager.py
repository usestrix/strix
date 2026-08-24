"""Per-scan sandbox session lifecycle."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents.sandbox.entries import BaseEntry, File, LocalDir
from agents.sandbox.manifest import Environment, Manifest

from strix.config import load_settings
from strix.core.paths import run_dir_for, runtime_state_dir
from strix.runtime.backends import backend_supports_bind_mounts, get_backend
from strix.runtime.caido_bootstrap import bootstrap_caido
from strix.runtime.caido_handle import CaidoBootstrapHandle


if TYPE_CHECKING:
    from strix.runtime.status import StatusSink


logger = logging.getLogger(__name__)


# In-container Caido sidecar port (matches the image's caido-cli bind).
_CONTAINER_CAIDO_PORT = 48080


_SESSION_CACHE: dict[str, dict[str, Any]] = {}

# Manifest root inside the container; entry keys hang off this path.
_WORKSPACE_ROOT = "/workspace"

_PROTECTED_METADATA_NAMES = (".git", ".agents", ".codex")


def _host_identity_env() -> dict[str, str]:
    # Read the platform through a local so it is not narrowed to whichever OS is
    # type-checking: comparing sys.platform directly makes one of these branches
    # statically dead, and which one flips between Linux and macOS.
    platform_name: str = sys.platform
    if platform_name != "linux":
        return {}
    # Bind-mount ownership only needs mapping on Linux, where the container uid
    # must match the host's.
    return {"STRIX_HOST_UID": str(os.getuid()), "STRIX_HOST_GID": str(os.getgid())}


def build_bind_mounts(local_sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    bind_mounts: list[dict[str, Any]] = []
    for src in local_sources:
        ws_subdir = src.get("workspace_subdir") or ""
        host_path = src.get("source_path") or ""
        if not ws_subdir or not host_path:
            continue
        resolved = Path(host_path).expanduser().resolve()
        target = f"{_WORKSPACE_ROOT}/{ws_subdir}"
        bind_mounts.append({"source": str(resolved), "target": target, "read_only": False})
        if src.get("protect_metadata"):
            bind_mounts.extend(_metadata_mounts(resolved, target))
    return bind_mounts


def build_manifest_entries(local_sources: list[dict[str, Any]]) -> dict[str | Path, BaseEntry]:
    entries: dict[str | Path, BaseEntry] = {}
    for src in local_sources:
        ws_subdir = src.get("workspace_subdir") or ""
        host_path = src.get("source_path") or ""
        if not ws_subdir or not host_path:
            continue
        entries[ws_subdir] = LocalDir(src=Path(host_path).expanduser().resolve())
    return entries


def _extra_file_rel_path(workspace_path: str) -> str | None:
    """Validate an extra-file target path and return it relative to /workspace.

    Only absolute paths under the workspace root are accepted; anything else
    (including ``..`` traversal segments) is rejected so callers cannot place
    orchestrator-provided content outside the sandbox workspace.
    """
    prefix = f"{_WORKSPACE_ROOT}/"
    if not workspace_path.startswith(prefix):
        return None
    rel = workspace_path[len(prefix) :].strip("/")
    if not rel or any(part in ("", ".", "..") for part in rel.split("/")):
        return None
    # Control characters would let a path break out of the single line it is
    # rendered on in the agent task, so the path is rejected rather than escaped.
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in rel):
        return None
    return rel


def _source_root_rels(local_sources: list[dict[str, Any]] | None) -> list[str]:
    """Workspace-relative roots the local sources occupy (e.g. ``["repo"]``)."""
    if not local_sources:
        return []
    return [
        str(src.get("workspace_subdir") or "").strip("/")
        for src in local_sources
        if src.get("workspace_subdir") and src.get("source_path")
    ]


def _collides_with_source_root(rel: str, source_roots: list[str]) -> bool:
    """True when an extra-file path would land on or inside a source tree.

    An exact match would replace the whole source tree with one file (a
    manifest ``entries`` key collision); a path nested under a source root
    would race the source upload; a path that is an ancestor of a source root
    would shadow the directory the source materializes into.
    """
    for root in source_roots:
        if not root:
            continue
        if rel == root or rel.startswith(f"{root}/") or root.startswith(f"{rel}/"):
            return True
    return False


def _extra_file_content(extra_file: dict[str, Any]) -> bytes | None:
    content = extra_file.get("content")
    if isinstance(content, bytes | bytearray):
        return bytes(content)
    if isinstance(content, str):
        return content.encode("utf-8")
    return None


def build_extra_file_entries(
    extra_files: list[dict[str, Any]],
    local_sources: list[dict[str, Any]] | None = None,
) -> dict[str | Path, BaseEntry]:
    """Map extra files to in-memory ``File`` manifest entries.

    Each item is ``{"workspace_path": "/workspace/<rel>", "content": bytes|str}``;
    manifest backends materialize the entry at the requested path alongside the
    ``LocalDir`` source uploads. Invalid items — including paths that collide
    with a ``local_sources`` tree or with an earlier extra file, which would
    otherwise replace its manifest entry — are skipped with a warning.
    """
    source_roots = _source_root_rels(local_sources)
    placed: list[str] = []
    entries: dict[str | Path, BaseEntry] = {}
    for extra_file in extra_files:
        rel = _extra_file_rel_path(str(extra_file.get("workspace_path") or ""))
        content = _extra_file_content(extra_file)
        if rel is None or content is None:
            logger.warning(
                "Skipping invalid extra file entry (workspace_path=%r)",
                extra_file.get("workspace_path"),
            )
            continue
        if _collides_with_source_root(rel, source_roots + placed):
            logger.warning(
                "Skipping extra file colliding with a local source tree or an "
                "earlier extra file (workspace_path=%r)",
                extra_file.get("workspace_path"),
            )
            continue
        placed.append(rel)
        entries[rel] = File(content=content)
    return entries


def build_extra_file_bind_mounts(
    extra_files: list[dict[str, Any]],
    staging_dir: Path,
    local_sources: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Stage extra files on the host and map them to read-only bind mounts.

    Bind-mount backends bypass the manifest, so the content is written under
    ``staging_dir`` (one numbered subdirectory per file to avoid basename
    collisions) and mounted read-only at the same ``/workspace/<rel>`` path the
    manifest path would use. Invalid items — including paths that collide with
    a ``local_sources`` tree or with an earlier extra file, which would
    duplicate or shadow its mount target — are skipped with a warning.
    """
    source_roots = _source_root_rels(local_sources)
    placed: list[str] = []
    mounts: list[dict[str, Any]] = []
    for index, extra_file in enumerate(extra_files):
        rel = _extra_file_rel_path(str(extra_file.get("workspace_path") or ""))
        content = _extra_file_content(extra_file)
        if rel is None or content is None:
            logger.warning(
                "Skipping invalid extra file entry (workspace_path=%r)",
                extra_file.get("workspace_path"),
            )
            continue
        if _collides_with_source_root(rel, source_roots + placed):
            logger.warning(
                "Skipping extra file colliding with a local source tree or an "
                "earlier extra file (workspace_path=%r)",
                extra_file.get("workspace_path"),
            )
            continue
        placed.append(rel)
        host_file = staging_dir / str(index) / Path(rel).name
        host_file.parent.mkdir(parents=True, exist_ok=True)
        host_file.write_bytes(content)
        mounts.append(
            {
                "source": str(host_file),
                "target": f"{_WORKSPACE_ROOT}/{rel}",
                "read_only": True,
            }
        )
    return mounts


def _metadata_mounts(tree: Path, target: str) -> list[dict[str, Any]]:
    mounts: list[dict[str, Any]] = []
    for name in _PROTECTED_METADATA_NAMES:
        metadata = tree / name
        if not metadata.is_dir() and not metadata.is_file():
            continue
        if not metadata.resolve().is_relative_to(tree):
            continue
        mounts.append({"source": str(metadata), "target": f"{target}/{name}", "read_only": True})
        gitdir = _gitdir_from_pointer(metadata) if metadata.is_file() else None
        if gitdir is not None and gitdir.exists() and gitdir.is_relative_to(tree):
            relative = gitdir.relative_to(tree).as_posix()
            mounts.append(
                {"source": str(gitdir), "target": f"{target}/{relative}", "read_only": True}
            )
    return mounts


def _gitdir_from_pointer(git_file: Path) -> Path | None:
    try:
        content = git_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in content.splitlines():
        prefix, _, value = line.partition(":")
        if prefix.strip() == "gitdir" and value.strip():
            candidate = Path(value.strip()).expanduser()
            if not candidate.is_absolute():
                candidate = git_file.parent / candidate
            return candidate.resolve()
    return None


async def create_or_reuse(
    scan_id: str,
    *,
    image: str,
    local_sources: list[dict[str, Any]],
    extra_files: list[dict[str, Any]] | None = None,
    status_sink: StatusSink | None = None,
) -> dict[str, Any]:
    """Return the existing session bundle for ``scan_id`` or create a new one.

    Each ``local_sources`` entry exposes its host ``source_path`` at
    ``/workspace/<workspace_subdir>`` inside the container.

    Each ``extra_files`` entry (``{"workspace_path": "/workspace/<rel>",
    "content": bytes | str}``) lands as a single file at its ``workspace_path``
    regardless of backend: an in-memory ``File`` manifest entry on manifest
    backends, a read-only bind mount of a host-staged copy on bind-mount
    backends.
    """

    def report(phase: str) -> None:
        if status_sink is not None:
            status_sink(phase)

    cached = _SESSION_CACHE.get(scan_id)
    if cached is not None:
        logger.info("Reusing existing sandbox session for scan %s", scan_id)
        return cached

    backend_name = load_settings().runtime.backend
    backend = get_backend(backend_name)

    if backend_supports_bind_mounts(backend_name):
        bind_mounts = build_bind_mounts(local_sources)
        entries: dict[str | Path, BaseEntry] = {}
        if extra_files:
            staging_dir = runtime_state_dir(run_dir_for(scan_id)) / "extra_files"
            bind_mounts.extend(
                build_extra_file_bind_mounts(extra_files, staging_dir, local_sources)
            )
    else:
        bind_mounts = []
        entries = build_manifest_entries(local_sources)
        if extra_files:
            entries.update(build_extra_file_entries(extra_files, local_sources))

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
                **_host_identity_env(),
                "http_proxy": container_caido_url,
                "https_proxy": container_caido_url,
                "ALL_PROXY": container_caido_url,
                "NO_PROXY": "localhost,127.0.0.1",
            },
        ),
    )

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

    # The Caido login + project setup polls the guest for a couple of seconds
    # and nothing needs the client before the first proxy tool call, so it
    # runs concurrently with the rest of scan start; consumers resolve the
    # handle at first use (see CaidoBootstrapHandle).
    caido_client = CaidoBootstrapHandle(
        asyncio.create_task(
            bootstrap_caido(
                session,
                host_url=host_caido_url,
                container_url=container_caido_url,
            ),
            name=f"caido-bootstrap-{scan_id}",
        )
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
