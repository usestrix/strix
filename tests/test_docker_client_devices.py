"""``STRIX_DOCKER_SANDBOX_DEVICES`` passes host devices through to the sandbox container."""

from __future__ import annotations

from typing import TYPE_CHECKING

from strix.runtime import docker_client


if TYPE_CHECKING:
    import pytest


def test_unset_adds_no_devices(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(docker_client._SANDBOX_DEVICES_ENV, raising=False)
    kwargs: dict[str, object] = {}
    docker_client._apply_sandbox_devices(kwargs)
    assert kwargs == {}


def test_devices_are_mapped_to_the_same_path_rwm(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(docker_client._SANDBOX_DEVICES_ENV, " /dev/net/tun, /dev/kvm ,,")
    kwargs: dict[str, object] = {}
    docker_client._apply_sandbox_devices(kwargs)
    assert kwargs["devices"] == ["/dev/net/tun:/dev/net/tun:rwm", "/dev/kvm:/dev/kvm:rwm"]


def test_existing_devices_are_kept_and_not_duplicated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(docker_client._SANDBOX_DEVICES_ENV, "/dev/fuse,/dev/net/tun")
    kwargs: dict[str, object] = {"devices": ["/dev/fuse"]}
    docker_client._apply_sandbox_devices(kwargs)
    assert kwargs["devices"] == ["/dev/fuse", "/dev/net/tun:/dev/net/tun:rwm"]
