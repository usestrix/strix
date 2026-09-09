"""Sandbox backend registry — selected via STRIX_RUNTIME_BACKEND (default: docker)."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import shutil
import subprocess  # nosec B404
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from agents.sandbox.manifest import Manifest


logger = logging.getLogger(__name__)


SandboxBackend = Callable[..., Awaitable[tuple[Any, Any]]]


def get_host_gateway(backend: str | None = None) -> str:
    """Return the container-to-host gateway hostname for ``backend``.

    For docker, returns ``"host.docker.internal"``.
    For podman, returns ``"host.containers.internal"`` so container-to-host
    networking works out of the box with Podman's built-in DNS.
    """
    if backend is None:
        try:
            from strix.config import load_settings

            backend = load_settings().runtime.backend
        except Exception:  # noqa: BLE001
            backend = "docker"
    if (backend or "").lower() == "podman":
        return "host.containers.internal"
    return "host.docker.internal"


def _extract_machine_socket(m: dict[str, Any]) -> str | None:
    """Extract socket path from a machine inspect dictionary."""
    conn_info: object = m.get("ConnectionInfo")
    if isinstance(conn_info, dict):
        podman_sock: object = conn_info.get("PodmanSocket")  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        if isinstance(podman_sock, dict):
            p: object = podman_sock.get("Path")  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
            if isinstance(p, str) and p.strip():
                return p.strip()
        elif isinstance(podman_sock, str) and podman_sock.strip():
            return podman_sock.strip()
    elif isinstance(conn_info, str) and conn_info.strip():
        return conn_info.strip()

    direct_sock: object = m.get("PodmanSocket")
    if isinstance(direct_sock, dict):
        direct_path: object = direct_sock.get("Path")  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        if isinstance(direct_path, str) and direct_path.strip():
            return direct_path.strip()
    elif isinstance(direct_sock, str) and direct_sock.strip():
        return direct_sock.strip()

    return None


def _normalize_inspect_payload(
    output: str | bytes | list[Any] | dict[str, Any],
) -> list[dict[str, Any]]:
    """Convert raw input into a list of machine inspection dictionaries."""
    if isinstance(output, bytes | bytearray):
        output = output.decode("utf-8", errors="replace")

    data: object
    if isinstance(output, str):
        text = output.strip()
        if not text:
            return []
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return []
    else:
        data = output

    if isinstance(data, dict):
        return [data]  # pyright: ignore[reportUnknownVariableType]
    if isinstance(data, list):
        return [m for m in data if isinstance(m, dict)]  # pyright: ignore[reportUnknownVariableType]
    return []


def parse_podman_machine_inspect(output: str | bytes | list[Any] | dict[str, Any]) -> list[str]:
    """Parse JSON output from ``podman machine inspect``.

    Returns a list of discovered socket paths. Handles errors, missing keys,
    single-machine dicts, and multi-machine arrays (prioritizing running machines).
    """
    machines = _normalize_inspect_payload(output)
    if not machines:
        return []

    running_sockets: list[str] = []
    other_sockets: list[str] = []

    for m in machines:
        is_running = bool(m.get("Running")) or str(m.get("State") or "").lower() == "running"
        socket_path = _extract_machine_socket(m)
        if socket_path:
            if is_running:
                running_sockets.append(socket_path)
            else:
                other_sockets.append(socket_path)

    seen: set[str] = set()
    result: list[str] = []
    for s in running_sockets + other_sockets:
        if s not in seen:
            seen.add(s)
            result.append(s)
    return result


def _run_podman_machine_inspect() -> list[str]:
    """Execute ``podman machine inspect`` and return discovered socket paths."""
    podman_bin = shutil.which("podman")
    if not podman_bin:
        return []
    try:
        proc = subprocess.run(  # nosec B603 # noqa: S603
            [podman_bin, "machine", "inspect"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if proc.returncode != 0:
            return []
        return parse_podman_machine_inspect(proc.stdout)
    except Exception:  # noqa: BLE001
        logger.debug("Failed to run podman machine inspect", exc_info=True)
        return []


def get_podman_socket_candidates(
    platform: str | None = None,
    *,
    uid: int | None = None,
    xdg_runtime_dir: str | None = None,
    home: Path | str | None = None,
) -> list[Path]:
    """Generate candidate filesystem paths for the Podman socket.

    Covers Linux (rootless and rootful) and macOS (applehv, libkrun, podman machine).
    """
    plat = (platform or sys.platform).lower()
    candidates: list[Path] = []

    if plat == "linux":
        # 1. Linux rootless via XDG_RUNTIME_DIR
        xdg_dir = (
            xdg_runtime_dir if xdg_runtime_dir is not None else os.environ.get("XDG_RUNTIME_DIR")
        )
        if xdg_dir:
            candidates.append(Path(xdg_dir) / "podman" / "podman.sock")

        # 2. Linux rootless via UID
        effective_uid = uid
        if effective_uid is None and hasattr(os, "getuid"):
            try:
                effective_uid = os.getuid()
            except (AttributeError, OSError):
                effective_uid = None
        if effective_uid is not None:
            candidates.append(Path(f"/run/user/{effective_uid}/podman/podman.sock"))
            candidates.append(
                Path(f"/tmp/podman-run-{effective_uid}/podman/podman.sock")  # nosec B108 # noqa: S108
            )

        # 3. Linux rootful
        candidates.append(Path("/run/podman/podman.sock"))
        candidates.append(Path("/var/run/podman/podman.sock"))

    elif plat == "darwin":
        user_home = Path(home) if home is not None else Path.home()

        # Dynamic machine inspect discovery (applehv / libkrun / qemu VMs)
        candidates.extend(Path(sock) for sock in _run_podman_machine_inspect())

        # Standard macOS VM socket locations (applehv, libkrun, qemu, default)
        machine_dir = user_home / ".local" / "share" / "containers" / "podman" / "machine"
        candidates.append(machine_dir / "applehv" / "podman.sock")
        candidates.append(machine_dir / "libkrun" / "podman.sock")
        candidates.append(machine_dir / "qemu" / "podman.sock")
        candidates.append(machine_dir / "podman-machine-default" / "podman.sock")
        candidates.append(machine_dir / "podman.sock")

    else:
        user_home = Path(home) if home is not None else Path.home()
        machine_dir = user_home / ".local" / "share" / "containers" / "podman" / "machine"
        candidates.append(machine_dir / "podman-machine-default" / "podman.sock")
        candidates.append(machine_dir / "podman.sock")

    seen: set[Path] = set()
    result: list[Path] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            result.append(c)
    return result


def auto_detect_podman_socket() -> str | None:
    """Look for an existing Podman socket on the host."""
    try:
        candidates = get_podman_socket_candidates()
        for candidate in candidates:
            try:
                if candidate.exists() or candidate.is_socket():
                    return f"unix://{candidate.resolve()}"
            except OSError:
                continue
    except Exception:  # noqa: BLE001
        logger.debug("Podman socket auto-detection failed", exc_info=True)
    return None


def auto_detect_docker_socket() -> str | None:
    """Look for an existing Docker daemon socket on the host."""
    candidates = [
        Path("/var/run/docker.sock"),
        Path("/run/docker.sock"),
        Path.home() / ".docker" / "run" / "docker.sock",
        Path.home() / ".docker" / "desktop" / "docker.sock",
    ]
    for c in candidates:
        try:
            if c.exists() or c.is_socket():
                return f"unix://{c.resolve()}"
        except OSError:
            continue
    return None


def normalize_socket_url(socket_path_or_url: str) -> str:
    """Normalize a socket path or URL into a docker-compatible base_url."""
    s = socket_path_or_url.strip()
    if not s:
        return ""
    if "://" in s:
        return s
    if s.startswith((r"\\.\pipe", "//./pipe")):
        return f"npipe://{s}"
    return f"unix://{s}"


def resolve_runtime_socket(backend: str = "docker") -> str | None:
    """Resolve the runtime socket URL using multi-layer fallthrough:

    1. STRIX_RUNTIME_SOCKET (env var or settings)
    2. DOCKER_HOST (env var)
    3. Per-backend auto-detection (for podman or docker)
    4. None (falls back to docker.from_env() default)
    """
    # Layer 1: STRIX_RUNTIME_SOCKET
    runtime_socket = os.environ.get("STRIX_RUNTIME_SOCKET", "").strip()
    if not runtime_socket:
        with contextlib.suppress(Exception):
            from strix.config import load_settings

            cfg_socket = getattr(load_settings().runtime, "socket", None)
            if cfg_socket:
                runtime_socket = str(cfg_socket).strip()
    if runtime_socket:
        return normalize_socket_url(runtime_socket)

    # Layer 2: DOCKER_HOST
    docker_host = os.environ.get("DOCKER_HOST", "").strip()
    if docker_host:
        return normalize_socket_url(docker_host)

    # Layer 3: Per-backend auto-detection
    b = backend.lower()
    if b == "podman":
        detected = auto_detect_podman_socket()
        if detected:
            return detected
    elif b == "docker":
        detected = auto_detect_docker_socket()
        if detected:
            return detected

    # Layer 4: Fall back to default
    return None


def get_runtime_client(backend: str = "docker") -> Any:
    """Create a container runtime client for ``backend`` using multi-layer socket fallthrough:

    STRIX_RUNTIME_SOCKET → DOCKER_HOST → per-backend auto-detection → docker.from_env() default.
    Gracefully falls through to docker.from_env() on connection/ping failure.
    """
    import docker

    socket_url = resolve_runtime_socket(backend)
    if socket_url:
        try:
            client: Any = docker.DockerClient(base_url=socket_url)
            client.ping()
        except Exception:  # noqa: BLE001
            logger.warning(
                "Failed to connect to %s via socket %s; falling through to default",
                backend,
                socket_url,
                exc_info=True,
            )
        else:
            logger.info("Connected to %s runtime via socket: %s", backend, socket_url)
            return client

    logger.debug("Using docker.from_env() default for backend %s", backend)
    return docker.from_env()


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

    ``session.start()`` is what materializes the manifest into the running
    container — the SDK's ``client.create()`` only builds the inner session
    object without applying it. ``async with session:`` would call it too, but
    Strix manages session lifetime explicitly via ``client.delete()`` so we
    trigger ``start()`` ourselves.
    """
    from agents.sandbox.sandboxes.docker import DockerSandboxClientOptions

    from strix.runtime.docker_client import StrixDockerSandboxClient

    raw_client = get_runtime_client("docker")
    client = StrixDockerSandboxClient(raw_client)
    client.host_gateway = get_host_gateway("docker")
    client.backend_name = "docker"
    client.strix_bind_mounts = bind_mounts or []
    options = DockerSandboxClientOptions(image=image, exposed_ports=exposed_ports)
    session = await client.create(options=options, manifest=manifest)
    await session.start()
    return client, session


async def _podman_backend(
    *,
    image: str,
    manifest: Manifest,
    exposed_ports: tuple[int, ...],
    bind_mounts: list[dict[str, Any]] | None = None,
) -> tuple[Any, Any]:
    """Bring up a session backed by the local Podman engine.

    Uses :class:`StrixDockerSandboxClient` with Podman socket detection
    and host-gateway hostname (``host.containers.internal``).
    """
    from agents.sandbox.sandboxes.docker import DockerSandboxClientOptions

    from strix.runtime.docker_client import StrixDockerSandboxClient

    raw_client = get_runtime_client("podman")
    client = StrixDockerSandboxClient(raw_client)
    client.host_gateway = get_host_gateway("podman")
    client.backend_name = "podman"
    client.strix_bind_mounts = bind_mounts or []
    options = DockerSandboxClientOptions(image=image, exposed_ports=exposed_ports)
    session = await client.create(options=options, manifest=manifest)
    await session.start()
    return client, session


_BACKENDS: dict[str, SandboxBackend] = {
    "docker": _docker_backend,
    "podman": _podman_backend,
}

_BIND_MOUNT_BACKENDS: set[str] = {"docker", "podman"}


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
