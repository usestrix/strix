from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Generator
from unittest import mock

import pytest

from strix.runtime.backends import (
    _macos_podman_machine_sockets,
    _podman_socket_candidates,
    get_backend,
    get_host_gateway,
    register_backend,
    supported_backends,
)


@pytest.fixture
def no_machine_inspect() -> Generator[None, None, None]:
    """Prevent real ``podman machine inspect`` calls during tests."""
    with mock.patch("strix.runtime.backends._macos_podman_machine_sockets", return_value=[]):
        yield


# -- get_host_gateway ------------------------------------------------------


def test_host_gateway_docker() -> None:
    assert get_host_gateway("docker") == "host.docker.internal"


def test_host_gateway_podman() -> None:
    assert get_host_gateway("podman") == "host.containers.internal"


def test_host_gateway_defaults_to_docker_for_unknown() -> None:
    assert get_host_gateway("unknown-backend") == "host.docker.internal"


# -- get_backend -----------------------------------------------------------


def test_get_backend_docker_returns_callable() -> None:
    backend = get_backend("docker")
    assert callable(backend)


def test_get_backend_podman_returns_callable() -> None:
    backend = get_backend("podman")
    assert callable(backend)


def test_get_backend_unknown_raises_valueerror() -> None:
    with pytest.raises(ValueError, match="Unknown STRIX_RUNTIME_BACKEND"):
        get_backend("nonexistent")


def test_get_backend_error_includes_supported_list() -> None:
    with pytest.raises(ValueError, match=r"\(supported: .*docker.*podman"):
        get_backend("nonexistent")


# -- register_backend ------------------------------------------------------


async def _stub_backend(**kwargs: object) -> tuple[str, str]:
    return ("stub_client", "stub_session")


def test_register_backend_adds_new_entry() -> None:
    register_backend("custom", _stub_backend)
    try:
        backend = get_backend("custom")
        assert backend is _stub_backend
        assert "custom" in supported_backends()
    finally:
        # Clean up so other tests aren't affected
        from strix.runtime.backends import _BACKENDS

        _BACKENDS.pop("custom", None)


def test_register_backend_overwrites_existing() -> None:
    original = get_backend("docker")
    register_backend("docker", _stub_backend)
    try:
        assert get_backend("docker") is _stub_backend
    finally:
        register_backend("docker", original)


def test_register_backend_overwrite_preserves_count() -> None:
    count_before = len(supported_backends())
    original = get_backend("docker")
    register_backend("docker", _stub_backend)
    try:
        assert len(supported_backends()) == count_before
    finally:
        register_backend("docker", original)


# -- supported_backends ----------------------------------------------------


def test_supported_backends_returns_sorted_list() -> None:
    backends = supported_backends()
    assert backends == sorted(backends)


def test_supported_backends_includes_docker_and_podman() -> None:
    backends = supported_backends()
    assert "docker" in backends
    assert "podman" in backends


# -- _podman_socket_candidates --------------------------------------------


@pytest.mark.usefixtures("clean_env", "no_machine_inspect")
class TestPodmanSocketCandidates:
    def test_always_includes_rootful_socket(self) -> None:
        candidates = _podman_socket_candidates()
        assert "unix:///run/podman/podman.sock" in candidates

    def test_includes_xdg_runtime_when_set(self) -> None:
        os.environ["XDG_RUNTIME_DIR"] = "/run/user/1000"
        candidates = _podman_socket_candidates()
        assert "unix:///run/user/1000/podman/podman.sock" in candidates

    def test_falls_back_to_uid_path_when_no_xdg(self) -> None:
        candidates = _podman_socket_candidates()
        uid = os.getuid()
        assert f"unix:///run/user/{uid}/podman/podman.sock" in candidates

    def test_includes_tmpdir_when_set(self) -> None:
        os.environ["TMPDIR"] = "/tmp/"
        candidates = _podman_socket_candidates()
        assert "unix:///tmp/podman/podman-machine-default-api.sock" in candidates

    def test_no_tmpdir_entry_when_not_set(self) -> None:
        candidates = _podman_socket_candidates()
        tmpdir_candidates = [c for c in candidates if "podman-machine-default-api" in c]
        assert len(tmpdir_candidates) == 0


# -- _macos_podman_machine_sockets ----------------------------------------


class TestMacOSPodmanMachineSockets:
    def test_returns_empty_when_podman_not_found(self) -> None:
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            assert _macos_podman_machine_sockets() == []

    def test_returns_empty_on_timeout(self) -> None:
        timeout_error = subprocess.TimeoutExpired(cmd="podman", timeout=5)
        with mock.patch("subprocess.run", side_effect=timeout_error):
            assert _macos_podman_machine_sockets() == []

    def test_returns_empty_on_nonzero_returncode(self) -> None:
        with mock.patch("subprocess.run", return_value=mock.Mock(returncode=1)):
            assert _macos_podman_machine_sockets() == []

    def test_returns_empty_on_invalid_json(self) -> None:
        proc_mock = mock.Mock(returncode=0, stdout="not valid json")
        with mock.patch("subprocess.run", return_value=proc_mock):
            assert _macos_podman_machine_sockets() == []

    def test_extracts_podman_socket_from_machine_inspect(self) -> None:
        inspect_output = json.dumps(
            [
                {
                    "ConnectionInfo": {
                        "PodmanSocket": {"Path": "/var/run/podman.sock"},
                    },
                },
            ]
        )
        proc_mock = mock.Mock(returncode=0, stdout=inspect_output)
        with mock.patch("subprocess.run", return_value=proc_mock):
            sockets = _macos_podman_machine_sockets()
            assert "unix:///var/run/podman.sock" in sockets

    def test_skips_machines_without_socket(self) -> None:
        inspect_output = json.dumps(
            [
                {"ConnectionInfo": {}},
                {
                    "ConnectionInfo": {
                        "PodmanSocket": {"Path": "/tmp/podman.sock"},
                    },
                },
            ]
        )
        proc_mock = mock.Mock(returncode=0, stdout=inspect_output)
        with mock.patch("subprocess.run", return_value=proc_mock):
            sockets = _macos_podman_machine_sockets()
            assert sockets == ["unix:///tmp/podman.sock"]

    def test_handles_multiple_machines(self) -> None:
        inspect_output = json.dumps(
            [
                {"ConnectionInfo": {"PodmanSocket": {"Path": "/run/podman1.sock"}}},
                {"ConnectionInfo": {"PodmanSocket": {"Path": "/run/podman2.sock"}}},
            ]
        )
        proc_mock = mock.Mock(returncode=0, stdout=inspect_output)
        with mock.patch("subprocess.run", return_value=proc_mock):
            sockets = _macos_podman_machine_sockets()
            assert len(sockets) == 2
            assert "unix:///run/podman1.sock" in sockets
            assert "unix:///run/podman2.sock" in sockets
