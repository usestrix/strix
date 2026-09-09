"""Pluggable sandbox lifecycle on top of the Agents SDK."""

from strix.runtime.backends import (
    backend_supports_bind_mounts,
    get_backend,
    get_docker_client,
    get_host_gateway,
    get_podman_socket_candidates,
    parse_podman_machine_inspect,
    register_backend,
    resolve_runtime_socket,
    supported_backends,
)


__all__ = [
    "backend_supports_bind_mounts",
    "get_backend",
    "get_docker_client",
    "get_host_gateway",
    "get_podman_socket_candidates",
    "parse_podman_machine_inspect",
    "register_backend",
    "resolve_runtime_socket",
    "supported_backends",
]
