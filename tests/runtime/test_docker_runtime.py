from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from docker.errors import NotFound

from strix.runtime import SandboxInitializationError
from strix.runtime.docker_runtime import HOST_GATEWAY_HOSTNAME, DockerRuntime


def test_get_extra_hosts_includes_host_gateway(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_SANDBOX_EXTRA_HOSTS", raising=False)

    runtime = DockerRuntime.__new__(DockerRuntime)

    assert runtime._get_extra_hosts() == {HOST_GATEWAY_HOSTNAME: "host-gateway"}


def test_get_extra_hosts_merges_configured_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "STRIX_SANDBOX_EXTRA_HOSTS",
        "test.internal.lan=host-gateway, api.local = 192.168.1.20",
    )

    runtime = DockerRuntime.__new__(DockerRuntime)

    assert runtime._get_extra_hosts() == {
        HOST_GATEWAY_HOSTNAME: "host-gateway",
        "test.internal.lan": "host-gateway",
        "api.local": "192.168.1.20",
    }


def test_get_extra_hosts_rejects_invalid_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_EXTRA_HOSTS", "test.internal.lan")

    runtime = DockerRuntime.__new__(DockerRuntime)

    with pytest.raises(ValueError, match="hostname=address"):
        runtime._get_extra_hosts()


def test_get_extra_hosts_rejects_multiple_equals(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_EXTRA_HOSTS", "test.internal.lan==host-gateway")

    runtime = DockerRuntime.__new__(DockerRuntime)

    with pytest.raises(ValueError, match="hostname=address"):
        runtime._get_extra_hosts()


def test_create_container_passes_configured_extra_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_EXTRA_HOSTS", "test.internal.lan=host-gateway")

    run = MagicMock(return_value=object())
    containers = SimpleNamespace(get=MagicMock(side_effect=NotFound("missing")), run=run)
    runtime = DockerRuntime.__new__(DockerRuntime)
    runtime.client = SimpleNamespace(containers=containers)
    runtime._verify_image_available = MagicMock()
    runtime._find_available_port = MagicMock(side_effect=[12345, 12346])
    runtime._wait_for_tool_server = MagicMock()
    runtime._scan_container = None

    runtime._create_container("scan-id")

    assert run.call_args.kwargs["extra_hosts"] == {
        HOST_GATEWAY_HOSTNAME: "host-gateway",
        "test.internal.lan": "host-gateway",
    }


def test_create_container_wraps_invalid_extra_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_EXTRA_HOSTS", "test.internal.lan")

    run = MagicMock()
    containers = SimpleNamespace(get=MagicMock(side_effect=NotFound("missing")), run=run)
    runtime = DockerRuntime.__new__(DockerRuntime)
    runtime.client = SimpleNamespace(containers=containers)
    runtime._verify_image_available = MagicMock()
    runtime._find_available_port = MagicMock(side_effect=[12345, 12346])
    runtime._wait_for_tool_server = MagicMock()
    runtime._scan_container = None

    with pytest.raises(SandboxInitializationError, match="Invalid Docker sandbox host mapping"):
        runtime._create_container("scan-id")

    run.assert_not_called()
