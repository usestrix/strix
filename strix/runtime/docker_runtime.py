import contextlib
import logging
import os
import secrets
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from pathlib import Path
from typing import Any, cast

import docker
from docker.errors import DockerException, ImageNotFound, NotFound
from docker.models.containers import Container
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import Timeout as RequestsTimeout

from strix.config import Config

from . import SandboxInitializationError
from .runtime import AbstractRuntime, SandboxInfo


HOST_GATEWAY_HOSTNAME = "host.docker.internal"
DOCKER_TIMEOUT = 60  # seconds
TOOL_SERVER_HEALTH_REQUEST_TIMEOUT = 5  # seconds per health check request
TOOL_SERVER_HEALTH_RETRIES = 10  # number of retries for health check
logger = logging.getLogger(__name__)


class DockerRuntime(AbstractRuntime):
    def __init__(self) -> None:
        try:
            self.client = docker.from_env(timeout=DOCKER_TIMEOUT)
        except (DockerException, RequestsConnectionError, RequestsTimeout) as e:
            logger.exception("Failed to connect to Docker daemon")
            if isinstance(e, RequestsConnectionError | RequestsTimeout):
                raise SandboxInitializationError(
                    "Docker daemon unresponsive",
                    f"Connection timed out after {DOCKER_TIMEOUT} seconds. "
                    "Please ensure Docker Desktop is installed and running, "
                    "and try running strix again.",
                ) from e
            raise SandboxInitializationError(
                "Docker is not available",
                "Docker is not available or not configured correctly. "
                "Please ensure Docker Desktop is installed and running, "
                "and try running strix again.",
            ) from e

        self._scan_container: Container | None = None
        self._tool_server_port: int | None = None
        self._tool_server_token: str | None = None

    def _generate_sandbox_token(self) -> str:
        return secrets.token_urlsafe(32)

    def _find_available_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            return cast("int", s.getsockname()[1])

    def _exec_run_with_timeout(
        self, container: Container, cmd: str, timeout: int = DOCKER_TIMEOUT, **kwargs: Any
    ) -> Any:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(container.exec_run, cmd, **kwargs)
            try:
                return future.result(timeout=timeout)
            except FuturesTimeoutError:
                logger.exception(f"exec_run timed out after {timeout}s: {cmd[:100]}...")
                raise SandboxInitializationError(
                    "Container command timed out",
                    f"Command timed out after {timeout} seconds. "
                    "Docker may be overloaded or unresponsive. "
                    "Please ensure Docker Desktop is installed and running, "
                    "and try running strix again.",
                ) from None

    def _get_scan_id(self, agent_id: str) -> str:
        try:
            from strix.telemetry.tracer import get_global_tracer

            tracer = get_global_tracer()
            if tracer and tracer.scan_config:
                return str(tracer.scan_config.get("scan_id", "default-scan"))
        except ImportError:
            logger.debug("Failed to import tracer, using fallback scan ID")
        except AttributeError:
            logger.debug("Tracer missing scan_config, using fallback scan ID")

        return f"scan-{agent_id.split('-')[0]}"

    def _verify_image_available(self, image_name: str, max_retries: int = 3) -> None:
        def _validate_image(image: docker.models.images.Image) -> None:
            if not image.id or not image.attrs:
                raise ImageNotFound(f"Image {image_name} metadata incomplete")

        for attempt in range(max_retries):
            try:
                image = self.client.images.get(image_name)
                _validate_image(image)
            except ImageNotFound:
                if attempt == max_retries - 1:
                    logger.exception(f"Image {image_name} not found after {max_retries} attempts")
                    raise
                logger.warning(f"Image {image_name} not ready, attempt {attempt + 1}/{max_retries}")
                time.sleep(2**attempt)
            except DockerException:
                if attempt == max_retries - 1:
                    logger.exception(f"Failed to verify image {image_name}")
                    raise
                logger.warning(f"Docker error verifying image, attempt {attempt + 1}/{max_retries}")
                time.sleep(2**attempt)
            else:
                logger.debug(f"Image {image_name} verified as available")
                return

    def _create_container_with_retry(self, scan_id: str, max_retries: int = 3) -> Container:
        last_exception = None
        container_name = f"strix-scan-{scan_id}"
        image_name = Config.get("strix_image")
        if not image_name:
            raise ValueError("STRIX_IMAGE must be configured")

        for attempt in range(max_retries):
            try:
                self._verify_image_available(image_name)

                try:
                    existing_container = self.client.containers.get(container_name)
                    logger.warning(f"Container {container_name} already exists, removing it")
                    with contextlib.suppress(Exception):
                        existing_container.stop(timeout=5)
                    existing_container.remove(force=True)
                    time.sleep(1)
                except NotFound:
                    pass
                except DockerException as e:
                    logger.warning(f"Error checking/removing existing container: {e}")

                caido_port = self._find_available_port()
                tool_server_port = self._find_available_port()
                tool_server_token = self._generate_sandbox_token()

                self._tool_server_port = tool_server_port
                self._tool_server_token = tool_server_token

                container = self.client.containers.run(
                    image_name,
                    command="sleep infinity",
                    detach=True,
                    name=container_name,
                    hostname=f"strix-scan-{scan_id}",
                    ports={
                        f"{caido_port}/tcp": caido_port,
                        f"{tool_server_port}/tcp": tool_server_port,
                    },
                    cap_add=["NET_ADMIN", "NET_RAW"],
                    labels={"strix-scan-id": scan_id},
                    environment={
                        "PYTHONUNBUFFERED": "1",
                        "CAIDO_PORT": str(caido_port),
                        "TOOL_SERVER_PORT": str(tool_server_port),
                        "TOOL_SERVER_TOKEN": tool_server_token,
                        "HOST_GATEWAY": HOST_GATEWAY_HOSTNAME,
                    },
                    extra_hosts=self._get_extra_hosts(),
                    tty=True,
                )

                self._scan_container = container
                logger.info("Created container %s for scan %s", container.id, scan_id)

                self._initialize_container(
                    container, caido_port, tool_server_port, tool_server_token
                )
            except (DockerException, RequestsConnectionError, RequestsTimeout) as e:
                last_exception = e
                if attempt == max_retries - 1:
                    logger.exception(f"Failed to create container after {max_retries} attempts")
                    break

                logger.warning(f"Container creation attempt {attempt + 1}/{max_retries} failed")

                self._tool_server_port = None
                self._tool_server_token = None

                sleep_time = (2**attempt) + (0.1 * attempt)
                time.sleep(sleep_time)
            else:
                return container

        if isinstance(last_exception, RequestsConnectionError | RequestsTimeout):
            raise SandboxInitializationError(
                "Failed to create sandbox container",
                f"Docker daemon unresponsive after {max_retries} attempts "
                f"(timed out after {DOCKER_TIMEOUT}s). "
                "Please ensure Docker Desktop is installed and running, "
                "and try running strix again.",
            ) from last_exception
        raise SandboxInitializationError(
            "Failed to create sandbox container",
            f"Container creation failed after {max_retries} attempts: {last_exception}. "
            "Please ensure Docker Desktop is installed and running, "
            "and try running strix again.",
        ) from last_exception

    def _get_or_create_scan_container(self, scan_id: str) -> Container:  # noqa: PLR0912
        container_name = f"strix-scan-{scan_id}"

        if self._scan_container:
            try:
                self._scan_container.reload()
                if self._scan_container.status == "running":
                    return self._scan_container
            except NotFound:
                self._scan_container = None
                self._tool_server_port = None
                self._tool_server_token = None

        try:
            container = self.client.containers.get(container_name)
            container.reload()

            if (
                "strix-scan-id" not in container.labels
                or container.labels["strix-scan-id"] != scan_id
            ):
                logger.warning(
                    f"Container {container_name} exists but missing/wrong label, updating"
                )

            if container.status != "running":
                logger.info(f"Starting existing container {container_name}")
                container.start()
                time.sleep(2)

            self._scan_container = container

            for env_var in container.attrs["Config"]["Env"]:
                if env_var.startswith("TOOL_SERVER_PORT="):
                    self._tool_server_port = int(env_var.split("=")[1])
                elif env_var.startswith("TOOL_SERVER_TOKEN="):
                    self._tool_server_token = env_var.split("=")[1]

            logger.info(f"Reusing existing container {container_name}")

        except NotFound:
            pass
        except (DockerException, RequestsConnectionError, RequestsTimeout) as e:
            logger.warning(f"Failed to get container by name {container_name}: {e}")
        else:
            return container

        try:
            containers = self.client.containers.list(
                all=True, filters={"label": f"strix-scan-id={scan_id}"}
            )
            if containers:
                container = containers[0]
                if container.status != "running":
                    container.start()
                    time.sleep(2)
                self._scan_container = container

                for env_var in container.attrs["Config"]["Env"]:
                    if env_var.startswith("TOOL_SERVER_PORT="):
                        self._tool_server_port = int(env_var.split("=")[1])
                    elif env_var.startswith("TOOL_SERVER_TOKEN="):
                        self._tool_server_token = env_var.split("=")[1]

                logger.info(f"Found existing container by label for scan {scan_id}")
                return container
        except (DockerException, RequestsConnectionError, RequestsTimeout) as e:
            logger.warning("Failed to find existing container by label for scan %s: %s", scan_id, e)

        logger.info("Creating new Docker container for scan %s", scan_id)
        return self._create_container_with_retry(scan_id)

    def _initialize_container(
        self, container: Container, caido_port: int, tool_server_port: int, tool_server_token: str
    ) -> None:
        logger.info("Initializing Caido proxy on port %s", caido_port)
        self._exec_run_with_timeout(
            container,
            f"bash -c 'export CAIDO_PORT={caido_port} && /usr/local/bin/docker-entrypoint.sh true'",
            detach=False,
        )

        time.sleep(5)

        result = self._exec_run_with_timeout(
            container,
            "bash -c 'source /etc/profile.d/proxy.sh && echo $CAIDO_API_TOKEN'",
            user="pentester",
        )
        caido_token = result.output.decode().strip() if result.exit_code == 0 else ""

        container.exec_run(
            f"bash -c 'source /etc/profile.d/proxy.sh && cd /app && "
            f"STRIX_SANDBOX_MODE=true CAIDO_API_TOKEN={caido_token} CAIDO_PORT={caido_port} "
            f"poetry run python strix/runtime/tool_server.py --token {tool_server_token} "
            f"--host 0.0.0.0 --port {tool_server_port} &'",
            detach=True,
            user="pentester",
        )

        time.sleep(2)

        host = self._resolve_docker_host()
        health_url = f"http://{host}:{tool_server_port}/health"
        self._wait_for_tool_server_health(health_url)

    def _wait_for_tool_server_health(
        self,
        health_url: str,
        max_retries: int = TOOL_SERVER_HEALTH_RETRIES,
        request_timeout: int = TOOL_SERVER_HEALTH_REQUEST_TIMEOUT,
    ) -> None:
        import httpx

        logger.info(f"Waiting for tool server health at {health_url}")

        for attempt in range(max_retries):
            try:
                with httpx.Client(trust_env=False, timeout=request_timeout) as client:
                    response = client.get(health_url)
                    response.raise_for_status()
                    health_data = response.json()

                    if health_data.get("status") == "healthy":
                        logger.info(
                            f"Tool server is healthy after {attempt + 1} attempt(s): {health_data}"
                        )
                        return

                    logger.warning(f"Tool server returned unexpected status: {health_data}")

            except httpx.ConnectError:
                logger.debug(
                    f"Tool server not ready (attempt {attempt + 1}/{max_retries}): "
                    f"Connection refused"
                )
            except httpx.TimeoutException:
                logger.debug(
                    f"Tool server not ready (attempt {attempt + 1}/{max_retries}): "
                    f"Request timed out"
                )
            except (httpx.RequestError, httpx.HTTPStatusError) as e:
                logger.debug(f"Tool server not ready (attempt {attempt + 1}/{max_retries}): {e}")

            sleep_time = min(2**attempt * 0.5, 5)
            time.sleep(sleep_time)

        raise SandboxInitializationError(
            "Tool server failed to start",
            "Please ensure Docker Desktop is installed and running, and try running strix again.",
        )

    def _copy_local_directory_to_container(
        self, container: Container, local_path: str, target_name: str | None = None
    ) -> None:
        import tarfile
        from io import BytesIO

        try:
            local_path_obj = Path(local_path).resolve()
            if not local_path_obj.exists() or not local_path_obj.is_dir():
                logger.warning(f"Local path does not exist or is not directory: {local_path_obj}")
                return

            if target_name:
                logger.info(
                    f"Copying local directory {local_path_obj} to container at "
                    f"/workspace/{target_name}"
                )
            else:
                logger.info(f"Copying local directory {local_path_obj} to container")

            tar_buffer = BytesIO()
            with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
                for item in local_path_obj.rglob("*"):
                    if item.is_file():
                        rel_path = item.relative_to(local_path_obj)
                        arcname = Path(target_name) / rel_path if target_name else rel_path
                        tar.add(item, arcname=arcname)

            tar_buffer.seek(0)
            container.put_archive("/workspace", tar_buffer.getvalue())

            container.exec_run(
                "chown -R pentester:pentester /workspace && chmod -R 755 /workspace",
                user="root",
            )

            logger.info("Successfully copied local directory to /workspace")

        except (OSError, DockerException):
            logger.exception("Failed to copy local directory to container")

    async def create_sandbox(
        self,
        agent_id: str,
        existing_token: str | None = None,
        local_sources: list[dict[str, str]] | None = None,
    ) -> SandboxInfo:
        scan_id = self._get_scan_id(agent_id)
        container = self._get_or_create_scan_container(scan_id)

        source_copied_key = f"_source_copied_{scan_id}"
        if local_sources and not hasattr(self, source_copied_key):
            for index, source in enumerate(local_sources, start=1):
                source_path = source.get("source_path")
                if not source_path:
                    continue

                target_name = source.get("workspace_subdir")
                if not target_name:
                    target_name = Path(source_path).name or f"target_{index}"

                self._copy_local_directory_to_container(container, source_path, target_name)
            setattr(self, source_copied_key, True)

        container_id = container.id
        if container_id is None:
            raise RuntimeError("Docker container ID is unexpectedly None")

        token = existing_token if existing_token is not None else self._tool_server_token

        if self._tool_server_port is None or token is None:
            raise RuntimeError("Tool server not initialized or no token available")

        api_url = await self.get_sandbox_url(container_id, self._tool_server_port)

        await self._register_agent_with_tool_server(api_url, agent_id, token)

        return {
            "workspace_id": container_id,
            "api_url": api_url,
            "auth_token": token,
            "tool_server_port": self._tool_server_port,
            "agent_id": agent_id,
        }

    async def _register_agent_with_tool_server(
        self, api_url: str, agent_id: str, token: str
    ) -> None:
        import httpx

        try:
            async with httpx.AsyncClient(trust_env=False) as client:
                response = await client.post(
                    f"{api_url}/register_agent",
                    params={"agent_id": agent_id},
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=30,
                )
                response.raise_for_status()
                logger.info(f"Registered agent {agent_id} with tool server")
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.warning(f"Failed to register agent {agent_id}: {e}")

    async def get_sandbox_url(self, container_id: str, port: int) -> str:
        try:
            container = self.client.containers.get(container_id)
            container.reload()

            host = self._resolve_docker_host()

        except NotFound:
            raise ValueError(f"Container {container_id} not found.") from None
        except DockerException as e:
            raise RuntimeError(f"Failed to get container URL for {container_id}: {e}") from e
        else:
            return f"http://{host}:{port}"

    def _resolve_docker_host(self) -> str:
        docker_host = os.getenv("DOCKER_HOST", "")
        if not docker_host:
            return "127.0.0.1"

        from urllib.parse import urlparse

        parsed = urlparse(docker_host)

        if parsed.scheme in ("tcp", "http", "https") and parsed.hostname:
            return parsed.hostname

        return "127.0.0.1"

    def _get_extra_hosts(self) -> dict[str, str]:
        return {HOST_GATEWAY_HOSTNAME: "host-gateway"}

    async def destroy_sandbox(self, container_id: str) -> None:
        logger.info("Destroying scan container %s", container_id)
        try:
            container = self.client.containers.get(container_id)
            container.stop()
            container.remove()
            logger.info("Successfully destroyed container %s", container_id)

            self._scan_container = None
            self._tool_server_port = None
            self._tool_server_token = None

        except NotFound:
            logger.warning("Container %s not found for destruction.", container_id)
        except DockerException as e:
            logger.warning("Failed to destroy container %s: %s", container_id, e)
