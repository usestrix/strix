"""StrixDockerSandboxClient — preserves the image's ENTRYPOINT and adds
NET_ADMIN/NET_RAW capabilities + host-gateway.

The SDK's ``DockerSandboxClient._create_container`` does not expose a hook for
extending ``create_kwargs`` before ``containers.create`` is called. We subclass
and reimplement the method body verbatim from the SDK source, with three
deltas:

1. Drop the SDK's ``entrypoint=["tail"]`` override; supply ``["tail", "-f",
   "/dev/null"]`` as ``command`` instead. This lets our image's
   ``docker-entrypoint.sh`` actually run — without it, ``caido-cli`` never
   starts inside the container and ``bootstrap_caido`` retries against a
   dead port.
2. Append NET_ADMIN/NET_RAW to ``cap_add`` (required by ``nmap -sS`` and
   other raw-socket tools).
3. Add ``host.docker.internal`` → host-gateway to ``extra_hosts`` so the
   agent can reach host-served apps.

Pinned to ``openai-agents==0.14.6``. Bumping the SDK requires
re-merging the parent body. Track upstream for an injection hook.
"""

from __future__ import annotations

import contextlib
import logging
import os
import uuid
from typing import Any, cast

from agents.sandbox.errors import ExposedPortUnavailableError
from agents.sandbox.manifest import Manifest
from agents.sandbox.sandboxes.docker import (
    DockerSandboxClient,
    DockerSandboxSession,
    _build_docker_volume_mounts,
    _docker_port_key,
    _manifest_requires_fuse,
    _manifest_requires_sys_admin,
)
from agents.sandbox.session.sandbox_session import SandboxSession
from agents.sandbox.types import ExposedPortEndpoint
from docker import errors as docker_errors  # type: ignore[import-untyped, unused-ignore]
from docker.models.containers import Container  # type: ignore[import-untyped, unused-ignore]
from docker.types import LogConfig  # type: ignore[import-untyped, unused-ignore]
from docker.types import Mount as DockerSDKMount  # type: ignore[import-untyped, unused-ignore]
from docker.utils import parse_repository_tag  # type: ignore[import-untyped, unused-ignore]
from requests.exceptions import RequestException


logger = logging.getLogger(__name__)


_SANDBOX_NETWORK_ENV = "STRIX_DOCKER_SANDBOX_NETWORK"


def _sandbox_network() -> str | None:
    value = os.environ.get(_SANDBOX_NETWORK_ENV, "").strip()
    return value or None


def _apply_sandbox_network(create_kwargs: dict[str, Any]) -> None:
    network = _sandbox_network()
    if network:
        create_kwargs["network"] = network
        create_kwargs.pop("ports", None)


def _apply_resource_limits(create_kwargs: dict[str, Any]) -> None:
    """Apply optional cgroup resource caps from the environment. Unset/blank
    values leave docker's default (unbounded), so this is opt-in per host."""
    mem_limit = os.environ.get("STRIX_SANDBOX_MEM_LIMIT", "").strip()
    if mem_limit:
        create_kwargs["mem_limit"] = mem_limit

    shm_size = os.environ.get("STRIX_SANDBOX_SHM_SIZE", "").strip()
    if shm_size:
        create_kwargs["shm_size"] = shm_size

    cpus = os.environ.get("STRIX_SANDBOX_CPUS", "").strip()
    if cpus:
        with contextlib.suppress(ValueError, OverflowError):
            nano_cpus = int(float(cpus) * 1_000_000_000)
            if 0 < nano_cpus <= 2**63 - 1:
                create_kwargs["nano_cpus"] = nano_cpus

    pids_limit = os.environ.get("STRIX_SANDBOX_PIDS_LIMIT", "").strip()
    if pids_limit:
        with contextlib.suppress(ValueError):
            create_kwargs["pids_limit"] = int(pids_limit)


def _apply_log_limits(create_kwargs: dict[str, Any]) -> None:
    """Bound the container's json-file log so a runaway process in the sandbox
    (e.g. a tool that busy-loops writing to stdout) cannot fill the host disk
    and take the Docker daemon down with it.

    Unlike the cgroup caps above, this defaults **on** — docker's own default
    is an unbounded json-file, which is unsafe for an autonomous agent that
    executes arbitrary commands. ``max-file`` rotation means the on-disk cap is
    ``max-size * max-file``. Set ``STRIX_SANDBOX_LOG_MAX_SIZE`` to ``0``/``off``
    to opt back out to docker's default."""
    max_size = os.environ.get("STRIX_SANDBOX_LOG_MAX_SIZE", "50m").strip()
    if max_size.lower() in ("0", "off", "none", "unlimited"):
        return
    max_file = os.environ.get("STRIX_SANDBOX_LOG_MAX_FILE", "3").strip() or "3"
    create_kwargs["log_config"] = LogConfig(
        type=LogConfig.types.JSON,
        config={"max-size": max_size, "max-file": max_file},
    )


class StrixDockerSandboxSession(DockerSandboxSession):
    sandbox_network: str = ""

    async def _resolve_exposed_port(self, port: int) -> ExposedPortEndpoint:
        try:
            self._container.reload()
        except docker_errors.APIError as e:
            raise ExposedPortUnavailableError(
                port=port,
                exposed_ports=self.state.exposed_ports,
                reason="backend_unavailable",
                context={
                    "backend": "docker",
                    "detail": "container_reload_failed",
                    "network": self.sandbox_network,
                },
                cause=e,
            ) from e

        attrs = getattr(self._container, "attrs", {}) or {}
        networks = attrs.get("NetworkSettings", {}).get("Networks", {})
        endpoint = networks.get(self.sandbox_network) or {}
        ip = endpoint.get("IPAddress") or endpoint.get("GlobalIPv6Address")
        if not isinstance(ip, str) or not ip:
            raise ExposedPortUnavailableError(
                port=port,
                exposed_ports=self.state.exposed_ports,
                reason="backend_unavailable",
                context={
                    "backend": "docker",
                    "detail": "container_not_on_network",
                    "network": self.sandbox_network,
                },
            )
        host = f"[{ip}]" if ":" in ip else ip
        return ExposedPortEndpoint(host=host, port=port, tls=False)


class StrixDockerSandboxClient(DockerSandboxClient):
    # Host directories to bind-mount into the container, set by the docker
    # backend before ``create()``. Each item is ``{source, target, read_only}``.
    strix_bind_mounts: list[dict[str, Any]] | None = None

    async def _create_container(
        self,
        image: str,
        *,
        manifest: Manifest | None = None,
        exposed_ports: tuple[int, ...] = (),
        session_id: uuid.UUID | None = None,
    ) -> Container:
        # ----- BEGIN VERBATIM COPY of DockerSandboxClient._create_container -----
        # SDK ref: src/agents/sandbox/sandboxes/docker.py:1434-1477 (v0.14.6).
        if not self.image_exists(image):
            repo, tag = parse_repository_tag(image)
            self.docker_client.images.pull(repo, tag=tag or None, all_tags=False)

        assert self.image_exists(image)
        environment: dict[str, str] | None = None
        if manifest:
            environment = await manifest.environment.resolve()
        # Strix delta from the SDK body: drop ``entrypoint`` override and
        # supply ``tail -f /dev/null`` as ``command`` so the image's
        # ENTRYPOINT (``docker-entrypoint.sh``) runs setup, then ``exec
        # "$@"`` becomes ``exec tail -f /dev/null`` for the keep-alive.
        # Without this, caido-cli + the in-container CA trust never get
        # initialized.
        create_kwargs: dict[str, Any] = {
            "image": image,
            "detach": True,
            "command": ["tail", "-f", "/dev/null"],
            "environment": environment,
        }
        if manifest is not None:
            docker_mounts = _build_docker_volume_mounts(
                manifest,
                session_id=session_id,
            )
            if docker_mounts:
                create_kwargs["mounts"] = docker_mounts
            if _manifest_requires_fuse(manifest):
                create_kwargs.update(
                    devices=["/dev/fuse"],
                    cap_add=["SYS_ADMIN"],
                    security_opt=["apparmor:unconfined"],
                )
            elif _manifest_requires_sys_admin(manifest):
                create_kwargs.update(
                    cap_add=["SYS_ADMIN"],
                    security_opt=["apparmor:unconfined"],
                )
        if exposed_ports:
            create_kwargs["ports"] = {
                _docker_port_key(port): ("127.0.0.1", None) for port in exposed_ports
            }
        # ----- END VERBATIM COPY -----

        # Strix injections — append, don't overwrite, so FUSE/SYS_ADMIN survives.
        cap_add = create_kwargs.setdefault("cap_add", [])
        if not isinstance(cap_add, list):
            cap_add = list(cap_add)
            create_kwargs["cap_add"] = cap_add
        for cap in ("NET_ADMIN", "NET_RAW"):
            if cap not in cap_add:
                cap_add.append(cap)

        extra_hosts = create_kwargs.setdefault("extra_hosts", {})
        extra_hosts["host.docker.internal"] = "host-gateway"

        _apply_sandbox_network(create_kwargs)
        _apply_resource_limits(create_kwargs)
        _apply_log_limits(create_kwargs)

        # Strix injection: host bind mounts (e.g. large repos passed via --mount)
        # that bypass the SDK's file-by-file LocalDir copy.
        bind_mounts = getattr(self, "strix_bind_mounts", ())
        if bind_mounts:
            mounts = create_kwargs.setdefault("mounts", [])
            for spec in bind_mounts:
                mounts.append(
                    DockerSDKMount(
                        target=spec["target"],
                        source=spec["source"],
                        type="bind",
                        read_only=spec.get("read_only", True),
                    )
                )

        logger.debug(
            "Creating sandbox container: image=%s caps=%s exposed_ports=%s",
            image,
            cap_add,
            list(exposed_ports),
        )
        container = self.docker_client.containers.create(**create_kwargs)
        logger.info(
            "Sandbox container created: id=%s image=%s",
            container.short_id if hasattr(container, "short_id") else "?",
            image,
        )
        return container

    async def create(self, **kwargs: Any) -> SandboxSession:
        session = await super().create(**kwargs)
        network = _sandbox_network()
        inner = session._inner
        if network and isinstance(inner, DockerSandboxSession):
            inner.__class__ = StrixDockerSandboxSession
            cast("StrixDockerSandboxSession", inner).sandbox_network = network
        return session

    async def delete(self, session: SandboxSession) -> SandboxSession:
        container_id = getattr(getattr(session._inner, "state", None), "container_id", None)
        if container_id:
            # Best-effort kill: NotFound/APIError cover a gone or unhappy
            # container. RequestException covers a torn-down daemon socket —
            # containers.get() -> inspect_container raises requests'
            # ConnectionError, which is a sibling of docker.errors.APIError
            # under requests.RequestException (not a subclass), so it escapes
            # an APIError-only suppress and surfaces a full traceback even
            # though this teardown is meant to be best-effort.
            with contextlib.suppress(
                docker_errors.NotFound, docker_errors.APIError, RequestException
            ):
                self.docker_client.containers.get(container_id).kill()
        return await super().delete(session)
