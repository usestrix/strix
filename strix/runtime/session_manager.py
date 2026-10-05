"""Per-scan sandbox session lifecycle."""

from __future__ import annotations

import asyncio
import io
import logging
import os
import sys
import tarfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents.sandbox.entries import BaseEntry, LocalDir
from agents.sandbox.manifest import Environment, Manifest

from strix.config import load_settings
from strix.runtime.backends import backend_supports_bind_mounts, get_backend
from strix.runtime.caido_bootstrap import bootstrap_caido
from strix.runtime.caido_handle import CaidoBootstrapHandle


if TYPE_CHECKING:
    from agents.sandbox.session import BaseSandboxSession

    from strix.runtime.status import StatusSink


logger = logging.getLogger(__name__)


# In-container Caido sidecar port (matches the image's caido-cli bind).
_CONTAINER_CAIDO_PORT = 48080


_SESSION_CACHE: dict[str, dict[str, Any]] = {}

# Manifest root inside the container; entry keys hang off this path.
_WORKSPACE_ROOT = "/workspace"

_PROTECTED_METADATA_NAMES = (".git", ".agents", ".codex")

# Extra files travel as one tar archive: a single upload plus one extraction
# inside the sandbox, instead of several round trips per file.
_EXTRA_FILE_ARCHIVE_REL = ".strix-extra-files.tar"
_EXTRA_FILE_ARCHIVE = f"{_WORKSPACE_ROOT}/{_EXTRA_FILE_ARCHIVE_REL}"
_EXTRA_FILE_EXTRACT_TIMEOUT_S = 120
_EXTRA_FILE_MODE = 0o644


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
        read_only = bool(src.get("read_only"))
        bind_mounts.append({"source": str(resolved), "target": target, "read_only": read_only})
        if src.get("protect_metadata") and not read_only:
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


def build_extra_file_archive(
    extra_files: list[dict[str, Any]],
    local_sources: list[dict[str, Any]] | None = None,
) -> bytes | None:
    """Pack extra files into one tar archive rooted at ``/workspace``.

    Each item is ``{"workspace_path": "/workspace/<rel>", "content": bytes|str}``
    and becomes a regular-file member at ``<rel>``. Extracting the archive as
    the sandbox user (see ``stage_extra_files``) leaves every file owned by
    that user, so the agent can edit it and create siblings. Invalid items —
    including paths that collide with a ``local_sources`` tree or with an
    earlier extra file — are skipped with a warning. Returns ``None`` when no
    valid file remains.
    """
    source_roots = _source_root_rels(local_sources)
    placed: list[str] = [_EXTRA_FILE_ARCHIVE_REL]
    buffer = io.BytesIO()
    mtime = int(time.time())
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for extra_file in extra_files:
            rel, content = _validated_extra_file(extra_file, source_roots + placed)
            if rel is None or content is None:
                continue
            placed.append(rel)
            info = tarfile.TarInfo(name=rel)
            info.size = len(content)
            info.mode = _EXTRA_FILE_MODE
            info.mtime = mtime
            archive.addfile(info, io.BytesIO(content))
    if len(placed) == 1:
        return None
    return buffer.getvalue()


def _validated_extra_file(
    extra_file: dict[str, Any], taken: list[str]
) -> tuple[str | None, bytes | None]:
    rel = _extra_file_rel_path(str(extra_file.get("workspace_path") or ""))
    content = _extra_file_content(extra_file)
    if rel is None or content is None:
        logger.warning(
            "Skipping invalid extra file entry (workspace_path=%r)",
            extra_file.get("workspace_path"),
        )
        return None, None
    if _collides_with_source_root(rel, taken):
        logger.warning(
            "Skipping extra file colliding with a local source tree or an "
            "earlier extra file (workspace_path=%r)",
            extra_file.get("workspace_path"),
        )
        return None, None
    return rel, content


async def stage_extra_files(session: BaseSandboxSession, archive: bytes) -> None:
    """Upload ``archive`` and unpack it under ``/workspace`` as the sandbox user.

    ``--no-same-owner`` keeps ownership with the extracting user even where
    the session runs as root, so the agent user can always write the files.
    """
    await session.write(Path(_EXTRA_FILE_ARCHIVE), io.BytesIO(archive))
    result = await session.exec(
        "sh",
        "-c",
        'tar --no-same-owner -xf "$1" -C "$2" && rm -f -- "$1"',
        "sh",
        _EXTRA_FILE_ARCHIVE,
        _WORKSPACE_ROOT,
        timeout=_EXTRA_FILE_EXTRACT_TIMEOUT_S,
    )
    if not result.ok():
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"unpacking extra files in the sandbox failed (exit {result.exit_code}): {stderr}"
        )


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
    "content": bytes | str}``) lands as a regular, agent-writable file at its
    ``workspace_path`` on every backend: the files are uploaded as one archive
    and unpacked inside the sandbox right after bring-up.
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
    else:
        bind_mounts = []
        entries = build_manifest_entries(local_sources)
    extra_file_archive = (
        build_extra_file_archive(extra_files, local_sources) if extra_files else None
    )

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

    if extra_file_archive is not None:
        report("Placing workspace files")
        try:
            await stage_extra_files(session, extra_file_archive)
        except BaseException:
            await _discard_session(client, session)
            raise

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


async def _discard_session(client: Any, session: Any) -> None:
    """Best-effort teardown of a session that never made it into the cache."""
    try:
        await client.delete(session)
    except Exception:  # noqa: BLE001
        logger.warning("Discarding a half-started sandbox session failed", exc_info=True)


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
