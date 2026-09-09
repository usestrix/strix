"""Unit tests for Podman runtime backend, socket candidate generation,
host-gateway resolution, and multi-layer socket fallthrough.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from strix.config.settings import RuntimeSettings
from strix.interface.environment import check_runtime_installed
from strix.interface.utils import check_runtime_connection
from strix.runtime.backends import (
    _BACKENDS,
    _BIND_MOUNT_BACKENDS,
    auto_detect_podman_socket,
    backend_supports_bind_mounts,
    get_backend,
    get_host_gateway,
    get_podman_socket_candidates,
    get_runtime_client,
    normalize_socket_url,
    parse_podman_machine_inspect,
    register_backend,
    resolve_runtime_socket,
    supported_backends,
)


# ============================================================================
# 1. Host Gateway Resolution (3 tests)
# ============================================================================


def test_get_host_gateway_docker() -> None:
    """Docker backend maps to host.docker.internal."""
    assert get_host_gateway("docker") == "host.docker.internal"


def test_get_host_gateway_podman() -> None:
    """Podman backend maps to host.containers.internal (case-insensitive)."""
    assert get_host_gateway("podman") == "host.containers.internal"
    assert get_host_gateway("Podman") == "host.containers.internal"
    assert get_host_gateway("PODMAN") == "host.containers.internal"


def test_get_host_gateway_default_and_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default or unknown backend falls back to host.docker.internal."""
    monkeypatch.delenv("STRIX_RUNTIME_BACKEND", raising=False)
    monkeypatch.setattr(
        "strix.config.load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(backend="docker")),
    )
    assert get_host_gateway(None) == "host.docker.internal"
    assert get_host_gateway("unknown_backend") == "host.docker.internal"


# ============================================================================
# 2. Backend Registry (4 tests)
# ============================================================================


def test_backend_registry_get_docker() -> None:
    """Docker backend is registered and callable."""
    backend = get_backend("docker")
    assert callable(backend)
    assert "docker" in supported_backends()
    assert backend_supports_bind_mounts("docker") is True


def test_backend_registry_get_podman() -> None:
    """Podman backend is registered, callable, and supports bind mounts."""
    backend = get_backend("podman")
    assert callable(backend)
    assert "podman" in supported_backends()
    assert backend_supports_bind_mounts("podman") is True


def test_backend_registry_unknown_raises() -> None:
    """Querying an unknown backend raises ValueError listing supported options."""
    with pytest.raises(ValueError, match="Unknown STRIX_RUNTIME_BACKEND: 'unknown_rt'"):
        get_backend("unknown_rt")


def test_backend_registry_custom_registration() -> None:
    """Custom backend can be registered and looked up with bind-mount support."""

    async def _dummy_backend(**_kwargs: Any) -> tuple[Any, Any]:
        return MagicMock(), MagicMock()

    try:
        register_backend("test_custom", _dummy_backend, supports_bind_mounts=True)
        assert get_backend("test_custom") is _dummy_backend
        assert backend_supports_bind_mounts("test_custom") is True
        assert "test_custom" in supported_backends()
    finally:
        _BACKENDS.pop("test_custom", None)
        _BIND_MOUNT_BACKENDS.discard("test_custom")


# ============================================================================
# 3. podman machine inspect JSON Parsing (6 tests)
# ============================================================================


def test_parse_machine_inspect_single_machine() -> None:
    """Extract socket path from a single machine inspect dictionary or list."""
    sock_path = "/Users/user/.local/share/containers/podman/machine/applehv/podman.sock"
    payload = json.dumps(
        [
            {
                "Name": "podman-machine-default",
                "Running": True,
                "ConnectionInfo": {
                    "PodmanSocket": {
                        "Path": sock_path,
                    }
                },
            }
        ]
    )
    result = parse_podman_machine_inspect(payload)
    assert result == [sock_path]


def test_parse_machine_inspect_multi_machine_running_priority() -> None:
    """When multiple machines exist, running machines take priority."""
    payload = json.dumps(
        [
            {
                "Name": "machine-stopped",
                "Running": False,
                "State": "stopped",
                "ConnectionInfo": {"PodmanSocket": {"Path": "/path/to/stopped.sock"}},
            },
            {
                "Name": "machine-active",
                "Running": True,
                "State": "running",
                "ConnectionInfo": {"PodmanSocket": {"Path": "/path/to/active.sock"}},
            },
        ]
    )
    result = parse_podman_machine_inspect(payload)
    assert result == ["/path/to/active.sock", "/path/to/stopped.sock"]


def test_parse_machine_inspect_string_socket_path() -> None:
    """Handle ConnectionInfo where PodmanSocket is directly a string path."""
    payload = json.dumps(
        [
            {
                "Name": "default",
                "Running": True,
                "ConnectionInfo": {"PodmanSocket": "/var/run/podman-direct.sock"},
            }
        ]
    )
    result = parse_podman_machine_inspect(payload)
    assert result == ["/var/run/podman-direct.sock"]


def test_parse_machine_inspect_invalid_json() -> None:
    """Invalid JSON returns empty list without raising."""
    assert parse_podman_machine_inspect("Error: machine not found") == []
    assert parse_podman_machine_inspect("{not-valid-json") == []


def test_parse_machine_inspect_empty_or_missing_keys() -> None:
    """Empty string, empty array, or machines without socket path return empty list."""
    assert parse_podman_machine_inspect("") == []
    assert parse_podman_machine_inspect("   ") == []
    assert parse_podman_machine_inspect("[]") == []
    assert parse_podman_machine_inspect(json.dumps([{"Name": "empty"}])) == []
    assert (
        parse_podman_machine_inspect(
            json.dumps([{"Name": "null_path", "ConnectionInfo": {"PodmanSocket": None}}])
        )
        == []
    )


def test_parse_machine_inspect_non_dict_elements() -> None:
    """Lists with non-dict elements are handled gracefully."""
    payload = json.dumps([None, 123, "random-string", False])
    assert parse_podman_machine_inspect(payload) == []


# ============================================================================
# 4. Podman Socket Candidates Across Platform Variants (6 tests)
# ============================================================================


def test_socket_candidates_linux_rootless_xdg() -> None:
    """Linux rootless candidate incorporates XDG_RUNTIME_DIR."""
    candidates = get_podman_socket_candidates(
        platform="linux",
        xdg_runtime_dir="/run/user/1000",
    )
    expected = Path("/run/user/1000/podman/podman.sock")
    assert expected in candidates


def test_socket_candidates_linux_rootless_uid() -> None:
    """Linux rootless candidate incorporates UID and /tmp fallback."""
    candidates = get_podman_socket_candidates(platform="linux", uid=1001)
    assert Path("/run/user/1001/podman/podman.sock") in candidates
    assert Path("/tmp/podman-run-1001/podman/podman.sock") in candidates  # noqa: S108


def test_socket_candidates_linux_rootful() -> None:
    """Linux rootful candidates include system socket paths."""
    candidates = get_podman_socket_candidates(platform="linux")
    assert Path("/run/podman/podman.sock") in candidates
    assert Path("/var/run/podman/podman.sock") in candidates


def test_socket_candidates_darwin_applehv() -> None:
    """macOS candidate includes applehv VM socket path."""
    home = Path("/Users/developer")
    candidates = get_podman_socket_candidates(platform="darwin", home=home)
    expected = home / ".local/share/containers/podman/machine/applehv/podman.sock"
    assert expected in candidates


def test_socket_candidates_darwin_libkrun() -> None:
    """macOS candidate includes libkrun VM socket path."""
    home = Path("/Users/developer")
    candidates = get_podman_socket_candidates(platform="darwin", home=home)
    expected = home / ".local/share/containers/podman/machine/libkrun/podman.sock"
    assert expected in candidates


def test_socket_candidates_darwin_machine_inspect_integration() -> None:
    """macOS candidates prioritize sockets discovered via machine inspect."""
    home = Path("/Users/developer")
    with patch(
        "strix.runtime.backends._run_podman_machine_inspect",
        return_value=["/custom/machine/inspect.sock"],
    ):
        candidates = get_podman_socket_candidates(platform="darwin", home=home)
    assert candidates[0] == Path("/custom/machine/inspect.sock")


# ============================================================================
# 5. Socket Detection and Multi-Layer Fallthrough (5 tests)
# ============================================================================


def test_socket_fallthrough_strix_runtime_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """STRIX_RUNTIME_SOCKET takes highest precedence in socket resolution."""
    monkeypatch.setenv("STRIX_RUNTIME_SOCKET", "unix:///custom/strix.sock")
    monkeypatch.setenv("DOCKER_HOST", "unix:///custom/docker_host.sock")
    resolved = resolve_runtime_socket("podman")
    assert resolved == "unix:///custom/strix.sock"


def test_socket_fallthrough_docker_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """DOCKER_HOST is used when STRIX_RUNTIME_SOCKET is unset."""
    monkeypatch.delenv("STRIX_RUNTIME_SOCKET", raising=False)
    monkeypatch.setenv("DOCKER_HOST", "unix:///custom/docker_host.sock")
    resolved = resolve_runtime_socket("podman")
    assert resolved == "unix:///custom/docker_host.sock"


def test_socket_fallthrough_autodetect_podman(monkeypatch: pytest.MonkeyPatch) -> None:
    """Auto-detects first existing, live socket candidate when env vars are unset."""
    monkeypatch.delenv("STRIX_RUNTIME_SOCKET", raising=False)
    monkeypatch.delenv("DOCKER_HOST", raising=False)

    fake_sock = Path("/run/user/1000/podman/podman.sock")
    with (
        patch(
            "strix.runtime.backends.get_podman_socket_candidates",
            return_value=[fake_sock],
        ),
        patch.object(Path, "exists", return_value=True),
        patch.object(Path, "resolve", return_value=fake_sock),
        patch("strix.runtime.backends._socket_is_live", return_value=True),
    ):
        detected = auto_detect_podman_socket()
        assert detected == f"unix://{fake_sock}"


def test_socket_fallthrough_autodetect_podman_skips_stale_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stale/unreachable candidate is skipped in favor of the next live one."""
    monkeypatch.delenv("STRIX_RUNTIME_SOCKET", raising=False)
    monkeypatch.delenv("DOCKER_HOST", raising=False)

    stale_sock = Path("/run/user/1000/podman/podman.sock")
    live_sock = Path("/run/podman/podman.sock")

    def fake_is_live(url: str) -> bool:
        return url == f"unix://{live_sock}"

    with (
        patch(
            "strix.runtime.backends.get_podman_socket_candidates",
            return_value=[stale_sock, live_sock],
        ),
        patch.object(Path, "exists", return_value=True),
        patch.object(Path, "resolve", side_effect=[stale_sock, live_sock]),
        patch("strix.runtime.backends._socket_is_live", side_effect=fake_is_live),
    ):
        detected = auto_detect_podman_socket()
        assert detected == f"unix://{live_sock}"


def test_socket_fallthrough_graceful_on_missing_or_failed_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Docker backend connection failure gracefully falls through to docker.from_env()."""
    monkeypatch.delenv("STRIX_RUNTIME_SOCKET", raising=False)
    monkeypatch.delenv("DOCKER_HOST", raising=False)

    mock_docker = MagicMock()
    mock_bad_client = MagicMock()
    mock_bad_client.ping.side_effect = ConnectionRefusedError("Daemon unreachable")
    mock_docker.DockerClient.return_value = mock_bad_client

    mock_default_client = MagicMock()
    mock_docker.from_env.return_value = mock_default_client

    with (
        patch.dict("sys.modules", {"docker": mock_docker}),
        patch(
            "strix.runtime.backends.resolve_runtime_socket",
            return_value="unix:///unreachable.sock",
        ),
    ):
        client = get_runtime_client("docker")

    assert client is mock_default_client
    mock_docker.from_env.assert_called_once()


def test_get_runtime_client_podman_raises_instead_of_falling_back_to_docker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed Podman socket connection raises rather than silently using Docker."""
    monkeypatch.delenv("STRIX_RUNTIME_SOCKET", raising=False)
    monkeypatch.delenv("DOCKER_HOST", raising=False)

    mock_docker = MagicMock()
    mock_bad_client = MagicMock()
    mock_bad_client.ping.side_effect = ConnectionRefusedError("Daemon unreachable")
    mock_docker.DockerClient.return_value = mock_bad_client

    with (
        patch.dict("sys.modules", {"docker": mock_docker}),
        patch(
            "strix.runtime.backends.resolve_runtime_socket",
            return_value="unix:///unreachable.sock",
        ),
        pytest.raises(RuntimeError, match="podman"),
    ):
        get_runtime_client("podman")

    mock_docker.from_env.assert_not_called()


def test_get_runtime_client_podman_raises_when_no_socket_resolved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No resolvable Podman socket at all raises rather than defaulting to Docker."""
    monkeypatch.delenv("STRIX_RUNTIME_SOCKET", raising=False)
    monkeypatch.delenv("DOCKER_HOST", raising=False)

    mock_docker = MagicMock()
    with (
        patch.dict("sys.modules", {"docker": mock_docker}),
        patch("strix.runtime.backends.resolve_runtime_socket", return_value=None),
        pytest.raises(RuntimeError, match="podman"),
    ):
        get_runtime_client("podman")

    mock_docker.from_env.assert_not_called()


def test_socket_fallthrough_strix_runtime_socket_raw_path_normalization() -> None:
    """Raw socket path is normalized to unix:// URI scheme."""
    assert normalize_socket_url("/run/podman/podman.sock") == "unix:///run/podman/podman.sock"
    assert normalize_socket_url("unix:///var/run/podman.sock") == "unix:///var/run/podman.sock"
    assert normalize_socket_url("tcp://127.0.0.1:2375") == "tcp://127.0.0.1:2375"


# ============================================================================
# 7. CLI Check and Connection for Podman Runtime (4 tests)
# ============================================================================


def test_check_runtime_installed_podman_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """When STRIX_RUNTIME_BACKEND=podman, succeeds if podman is in PATH even if docker is not."""
    monkeypatch.setenv("STRIX_RUNTIME_BACKEND", "podman")

    def fake_which(cmd: str) -> str | None:
        if cmd == "podman":
            return "/usr/bin/podman"
        return None

    monkeypatch.setattr("shutil.which", fake_which)
    # Should not raise or sys.exit
    check_runtime_installed()


def test_check_runtime_installed_podman_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """When STRIX_RUNTIME_BACKEND=podman and neither podman nor docker in PATH, exits with error."""
    monkeypatch.setenv("STRIX_RUNTIME_BACKEND", "podman")
    monkeypatch.setattr("shutil.which", lambda _cmd: None)

    with pytest.raises(SystemExit) as exc_info:
        check_runtime_installed()
    assert exc_info.value.code == 1


def test_check_runtime_installed_docker_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """When backend is docker and docker is missing from PATH, exits with error."""
    monkeypatch.setenv("STRIX_RUNTIME_BACKEND", "docker")

    def fake_which(cmd: str) -> str | None:
        if cmd == "podman":
            return "/usr/bin/podman"
        return None

    monkeypatch.setattr("shutil.which", fake_which)

    with pytest.raises(SystemExit) as exc_info:
        check_runtime_installed()
    assert exc_info.value.code == 1


def test_check_runtime_connection_podman_uses_podman_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """check_runtime_connection connects and pings backend client."""
    monkeypatch.setenv("STRIX_RUNTIME_BACKEND", "podman")

    mock_client = MagicMock()
    with patch("strix.runtime.backends.get_runtime_client", return_value=mock_client) as mock_get:
        client = check_runtime_connection()
        mock_get.assert_called_once_with("podman")
        mock_client.ping.assert_called_once()
        assert client is mock_client


# ============================================================================
# 8. Runtime Backend Setting Normalization (2 tests)
# ============================================================================


def test_runtime_settings_backend_is_lowercased(monkeypatch: pytest.MonkeyPatch) -> None:
    """A mixed-case STRIX_RUNTIME_BACKEND is normalized so get_backend() finds it."""
    monkeypatch.setenv("STRIX_RUNTIME_BACKEND", "Podman")
    settings = RuntimeSettings()
    assert settings.backend == "podman"
    assert get_backend(settings.backend) is not None


def test_runtime_settings_backend_defaults_when_blank(monkeypatch: pytest.MonkeyPatch) -> None:
    """A blank/whitespace-only STRIX_RUNTIME_BACKEND still normalizes to the docker default."""
    monkeypatch.setenv("STRIX_RUNTIME_BACKEND", "  ")
    settings = RuntimeSettings()
    assert settings.backend == "docker"
