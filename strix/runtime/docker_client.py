"""StrixDockerSandboxClient — preserves the image's ENTRYPOINT and adds
NET_ADMIN/NET_RAW capabilities + host-gateway.

The SDK's ``DockerSandboxClient._create_container`` does not expose a hook for
extending ``create_kwargs`` before ``containers.create`` is called. We subclass
and reimplement the method body verbatim from the SDK source, with five
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
4. Honor ``STRIX_DOCKER_SANDBOX_NETWORK``. ``host`` omits published ports,
   tells the entrypoint to bind Caido to loopback, and resolves exposed
   ports on the daemon loopback. Any other name attaches that network and
   resolves the container IP. Unset keeps the SDK published-port path.
5. Merge ``STRIX_DOCKER_EXTRA_HOSTS`` (a JSON hostname-to-IP object) into
   ``extra_hosts``. ``host.docker.internal`` stays reserved for host-gateway.

Pinned to ``openai-agents==0.14.6``. Bumping the SDK requires
re-merging the parent body. Track upstream for an injection hook.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
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
_EXTRA_HOSTS_ENV = "STRIX_DOCKER_EXTRA_HOSTS"
_HOST_GATEWAY_HOSTNAME = "host.docker.internal"
_HOST_NETWORK_NAME = "host"
_DAEMON_LOOPBACK = "127.0.0.1"
# Read by containers/docker-entrypoint.sh. Set only for host networking so the
# unauthenticated Caido listener stays on loopback instead of 0.0.0.0.
_CAIDO_LISTEN_ADDRESS_ENV = "STRIX_CAIDO_LISTEN_ADDRESS"
_CAIDO_LOOPBACK_LABEL = "strix.sandbox.caido-loopback"


def _sandbox_network() -> str | None:
    value = os.environ.get(_SANDBOX_NETWORK_ENV, "").strip()
    return value or None


def _apply_host_network_listener(create_kwargs: dict[str, Any]) -> None:
    """Point the entrypoint at loopback when the sandbox uses host networking.

    ``docker-entrypoint.sh`` otherwise runs ``caido-cli --listen 0.0.0.0:48080``
    with guest access enabled. Host networking would expose that proxy on every
    host interface. Named and bridge networks keep the bridge listener.
    """
    raw_environment = create_kwargs.get("environment")
    if isinstance(raw_environment, dict):
        environment: dict[str, Any] = dict(cast("dict[str, Any]", raw_environment))
    else:
        environment = {}
    environment[_CAIDO_LISTEN_ADDRESS_ENV] = _DAEMON_LOOPBACK
    create_kwargs["environment"] = environment


def _require_host_network_image(docker_client: Any, image: str) -> None:
    """Reject host mode when a cached image may still bind Caido on 0.0.0.0."""
    try:
        attrs = docker_client.images.get(image).attrs
    except docker_errors.ImageNotFound:
        attrs = None
    config = attrs.get("Config") if isinstance(attrs, dict) else None
    labels = config.get("Labels") if isinstance(config, dict) else None
    if isinstance(labels, dict) and labels.get(_CAIDO_LOOPBACK_LABEL) == "true":
        return
    raise ValueError(
        f"{_SANDBOX_NETWORK_ENV}=host requires label {_CAIDO_LOOPBACK_LABEL}=true "
        f"so {_CAIDO_LISTEN_ADDRESS_ENV} is honored. Cached older images bind "
        "Caido to 0.0.0.0 with guest access."
    )


def _apply_sandbox_network(create_kwargs: dict[str, Any], docker_client: Any, image: str) -> None:
    network = _sandbox_network()
    if not network:
        return
    if network == _HOST_NETWORK_NAME:
        _require_host_network_image(docker_client, image)
    create_kwargs["network"] = network
    create_kwargs.pop("ports", None)
    if network == _HOST_NETWORK_NAME:
        _apply_host_network_listener(create_kwargs)


def _extra_host_mappings() -> dict[str, str]:
    """Hostname → literal IP entries from ``STRIX_DOCKER_EXTRA_HOSTS``.

    Unset or blank leaves the built-in host-gateway mapping untouched. A
    malformed value raises before the container is created.
    """
    raw = os.environ.get(_EXTRA_HOSTS_ENV, "").strip()
    if not raw:
        return {}

    try:
        parsed: object = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{_EXTRA_HOSTS_ENV} must be a JSON object mapping hostnames to "
            f"IP addresses ({exc.msg})"
        ) from exc

    if not isinstance(parsed, dict):
        got = "array" if isinstance(parsed, list) else type(parsed).__name__
        raise TypeError(
            f"{_EXTRA_HOSTS_ENV} must be a JSON object mapping hostnames to IP addresses, got {got}"
        )

    mappings: dict[str, str] = {}
    for name, address in cast("dict[object, object]", parsed).items():
        hostname = _extra_hostname(name)
        mappings[hostname] = _extra_host_address(hostname, address)
    return mappings


def _extra_hostname(name: object) -> str:
    if not isinstance(name, str):
        raise TypeError(f"{_EXTRA_HOSTS_ENV} hostnames must be strings")
    hostname = name.strip()
    if not hostname:
        raise ValueError(f"{_EXTRA_HOSTS_ENV} contains an empty hostname")
    if hostname.lower() == _HOST_GATEWAY_HOSTNAME:
        raise ValueError(
            f"{_EXTRA_HOSTS_ENV} cannot replace the reserved {_HOST_GATEWAY_HOSTNAME} mapping"
        )
    return hostname


def _extra_host_address(hostname: str, address: object) -> str:
    if not isinstance(address, str):
        raise TypeError(
            f"{_EXTRA_HOSTS_ENV} value for {hostname!r} must be an IPv4 or IPv6 address string"
        )
    candidate = address.strip()
    try:
        ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise ValueError(
            f"{_EXTRA_HOSTS_ENV} value for {hostname!r} is not a literal IPv4 or IPv6 address"
        ) from exc
    return candidate


def _apply_extra_hosts(create_kwargs: dict[str, Any]) -> None:
    extra_hosts = create_kwargs.setdefault("extra_hosts", {})
    extra_hosts[_HOST_GATEWAY_HOSTNAME] = "host-gateway"
    extra_hosts.update(_extra_host_mappings())


_SANDBOX_DEVICES_ENV = "STRIX_DOCKER_SANDBOX_DEVICES"


def _sandbox_devices() -> list[str]:
    raw = os.environ.get(_SANDBOX_DEVICES_ENV, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _apply_sandbox_devices(create_kwargs: dict[str, Any]) -> None:
    """Pass the host devices listed in ``STRIX_DOCKER_SANDBOX_DEVICES`` through.

    Comma-separated device paths, each mapped to the same path in the container
    with ``rwm`` access. A tunnel brought up inside the sandbox (OpenVPN,
    Tailscale) needs ``/dev/net/tun``: Docker's default device cgroup denies it
    even with ``NET_ADMIN``. Unset means no extra devices.
    """
    devices = _sandbox_devices()
    if not devices:
        return
    existing = [str(item) for item in (create_kwargs.get("devices") or [])]
    for path in devices:
        spec = f"{path}:{path}:rwm"
        if spec not in existing and path not in existing:
            existing.append(spec)
    create_kwargs["devices"] = existing


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


def _apply_run_labels(create_kwargs: dict[str, Any]) -> None:
    run_id = os.getenv("STRIX_RUN_ID")
    if not run_id:
        return
    labels = create_kwargs.setdefault("labels", {})
    if not isinstance(labels, dict):
        return
    labels["strix-run-id"] = run_id
    run_type = os.getenv("STRIX_RUN_TYPE")
    if run_type:
        labels["strix-run-type"] = run_type


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

        # Host mode has no container IP. The entrypoint binds Caido to the
        # daemon loopback on the requested port.
        if self.sandbox_network == _HOST_NETWORK_NAME:
            return ExposedPortEndpoint(host=_DAEMON_LOOPBACK, port=port, tls=False)

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

        _apply_extra_hosts(create_kwargs)
        _apply_sandbox_network(create_kwargs, self.docker_client, image)
        _apply_sandbox_devices(create_kwargs)
        _apply_resource_limits(create_kwargs)
        _apply_log_limits(create_kwargs)
        _apply_run_labels(create_kwargs)

        # Strix injection: local source trees, sorted shallowest-first so a
        # nested spec lands on top of the tree it covers.
        bind_mounts = self.strix_bind_mounts or ()
        if bind_mounts:
            mounts = create_kwargs.setdefault("mounts", [])
            for spec in sorted(bind_mounts, key=lambda s: str(s["target"]).count("/")):
                mounts.append(
                    DockerSDKMount(
                        target=spec["target"],
                        source=spec["source"],
                        type="bind",
                        read_only=spec.get("read_only", False),
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
