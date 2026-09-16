"""Tests for the SSRF guard on the host-side git-repo probe in interface.utils.

Covers https://github.com/usestrix/strix/issues/1132: `_is_http_git_repo` runs
on the Strix host (not the sandbox), so an attacker-influenced target string
must not be able to use it to probe internal/private network services.
"""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING, Any

import pytest
import requests

from strix.interface import utils


if TYPE_CHECKING:
    from typing import Self


class _FakeResponse:
    def __init__(self, status_code: int, headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self.headers = headers or {}

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "127.53.0.1",
        "::1",
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.1",
        "169.254.169.254",  # cloud metadata endpoint
        "0.0.0.0",  # nosec B104
        "224.0.0.1",  # multicast
    ],
)
def test_is_ssrf_safe_host_rejects_disallowed_ip_literals(host: str) -> None:
    assert utils._is_ssrf_safe_host(host) is False


@pytest.mark.parametrize("host", ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
def test_is_ssrf_safe_host_accepts_public_ip_literals(host: str) -> None:
    assert utils._is_ssrf_safe_host(host) is True


def test_is_ssrf_safe_host_rejects_hostname_resolving_to_private_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_a, **_kw: [(None, None, None, "", ("10.1.2.3", 0))],
    )
    assert utils._is_ssrf_safe_host("internal.corp.example") is False


def test_is_ssrf_safe_host_accepts_hostname_resolving_to_public_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_a, **_kw: [(None, None, None, "", ("93.184.216.34", 0))],
    )
    assert utils._is_ssrf_safe_host("example.com") is True


def test_is_ssrf_safe_host_rejects_unresolvable_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(*_a: object, **_kw: object) -> Any:
        raise OSError("name resolution failed")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    assert utils._is_ssrf_safe_host("nonexistent.invalid") is False


def test_is_http_git_repo_does_not_probe_disallowed_hosts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def _fake_get(*_a: object, **_kw: object) -> _FakeResponse:
        nonlocal called
        called = True
        return _FakeResponse(200)

    monkeypatch.setattr(requests, "get", _fake_get)

    assert utils._is_http_git_repo("http://169.254.169.254/latest/meta-data/") is False
    assert called is False


def test_is_http_git_repo_no_longer_treats_401_as_a_repo_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_a, **_kw: [(None, None, None, "", ("93.184.216.34", 0))],
    )
    monkeypatch.setattr(requests, "get", lambda *_a, **_kw: _FakeResponse(401))

    assert utils._is_http_git_repo("https://internal.example/service") is False


def test_is_http_git_repo_does_not_follow_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_a, **_kw: [(None, None, None, "", ("93.184.216.34", 0))],
    )
    captured_kwargs: dict[str, Any] = {}

    def _fake_get(*_a: object, **kwargs: object) -> _FakeResponse:
        captured_kwargs.update(kwargs)
        return _FakeResponse(200, {"Content-Type": "application/x-git-upload-pack-advertisement"})

    monkeypatch.setattr(requests, "get", _fake_get)

    utils._is_http_git_repo("https://example.com/some/repo")
    assert captured_kwargs.get("allow_redirects") is False


def test_is_http_git_repo_accepts_genuine_200_git_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_a, **_kw: [(None, None, None, "", ("93.184.216.34", 0))],
    )
    monkeypatch.setattr(
        requests,
        "get",
        lambda *_a, **_kw: _FakeResponse(
            200, {"Content-Type": "application/x-git-upload-pack-advertisement"}
        ),
    )

    assert utils._is_http_git_repo("https://example.com/some/repo") is True
