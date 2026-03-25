import sys

import docker

from strix.config import Config


def resolve_docker_base_url() -> str:
    configured = Config.get_str("docker_host")
    if configured:
        return configured

    if sys.platform == "win32":
        return "npipe:////./pipe/docker_engine"

    return "unix:///var/run/docker.sock"


def create_docker_client(timeout: int) -> docker.DockerClient:
    return docker.DockerClient(base_url=resolve_docker_base_url(), timeout=timeout)
