"""Tests for the SSRF guard on the host-side git-repo probe in interface.utils.

Covers https://github.com/usestrix/strix/issues/1132: `_is_http_git_repo` runs
on the Strix host (not the sandbox), so an attacker-influenced target string
must not be able to use it to probe internal/private network services.

The guard must also resist DNS rebinding: the address that gets validated has
to be the exact address the probe connects to. A naive "resolve, check, then
`requests.get(url)`" implementation re-resolves the hostname to actually
connect, giving a malicious DNS server a second lookup — answered with a
private address — to bypass the check made against the first one.
"""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING, Any

import pytest

from strix.interface import utils


if TYPE_CHECKING:
    from typing import Self


class _FakeResponse:
    def __init__(self, status: int, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self.headers = headers or {}
        self.released = False

    def release_conn(self) -> None:
        self.released = True


def _make_fake_pool_class(
    response: _FakeResponse | Exception,
    calls: list[dict[str, Any]],
    instances: list[Any],
) -> type:
    class _FakePool:
        def __init__(self, host: str, port: int, **kwargs: Any) -> None:
            self.host = host
            self.port = port
            self.kwargs = kwargs
            instances.append(self)

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def request(
            self, method: str, path: str, headers: dict[str, str] | None = None, **kwargs: Any
        ) -> _FakeResponse:
            calls.append({"method": method, "path": path, "headers": headers, **kwargs})
            if isinstance(response, Exception):
                raise response
            return response

    return _FakePool


def _patch_pools(monkeypatch: pytest.MonkeyPatch, pool_class: type) -> None:
    monkeypatch.setattr(utils.urllib3, "HTTPSConnectionPool", pool_class)
    monkeypatch.setattr(utils.urllib3, "HTTPConnectionPool", pool_class)


# --- _resolve_pinned_probe_ip -------------------------------------------------


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
def test_resolve_pinned_probe_ip_rejects_disallowed_ip_literals(host: str) -> None:
    assert utils._resolve_pinned_probe_ip(host, 443) is None


@pytest.mark.parametrize("host", ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
def test_resolve_pinned_probe_ip_accepts_public_ip_literals(host: str) -> None:
    assert utils._resolve_pinned_probe_ip(host, 443) == host


def test_resolve_pinned_probe_ip_rejects_hostname_resolving_only_to_private_ips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_a, **_kw: [(None, None, None, "", ("10.1.2.3", 0))],
    )
    assert utils._resolve_pinned_probe_ip("internal.corp.example", 443) is None


def test_resolve_pinned_probe_ip_returns_the_first_allowed_resolved_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_a, **_kw: [
            (None, None, None, "", ("169.254.169.254", 0)),
            (None, None, None, "", ("93.184.216.34", 0)),
        ],
    )
    assert utils._resolve_pinned_probe_ip("example.com", 443) == "93.184.216.34"


def test_resolve_pinned_probe_ip_rejects_unresolvable_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(*_a: object, **_kw: object) -> Any:
        raise OSError("name resolution failed")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    assert utils._resolve_pinned_probe_ip("nonexistent.invalid", 443) is None


# --- _is_http_git_repo ---------------------------------------------------------


def test_is_http_git_repo_does_not_connect_to_disallowed_hosts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_a, **_kw: [(None, None, None, "", ("169.254.169.254", 0))],
    )
    calls: list[dict[str, Any]] = []
    instances: list[Any] = []
    _patch_pools(monkeypatch, _make_fake_pool_class(_FakeResponse(200), calls, instances))

    assert utils._is_http_git_repo("http://metadata.internal/latest/meta-data/") is False
    assert instances == []
    assert calls == []


def test_is_http_git_repo_rejects_non_http_schemes_without_resolving(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(*_a: object, **_kw: object) -> Any:
        raise AssertionError("must not resolve a non-http(s) scheme")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    assert utils._is_http_git_repo("ftp://example.com/repo") is False


def test_is_http_git_repo_pins_the_connection_to_the_validated_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The core regression test for the DNS-rebinding bypass.

    A rebinding DNS server answers the first (validation) lookup with a
    public address and would answer any later lookup with a private one. The
    probe must connect to the address it already validated instead of
    re-resolving the hostname, so it must end up talking to the public
    address here even though a second lookup would be unsafe.
    """
    lookups = 0

    def _rebinding_getaddrinfo(*_a: object, **_kw: object) -> list[Any]:
        nonlocal lookups
        lookups += 1
        ip = "93.184.216.34" if lookups == 1 else "10.0.0.1"
        return [(None, None, None, "", (ip, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _rebinding_getaddrinfo)

    calls: list[dict[str, Any]] = []
    instances: list[Any] = []
    response = _FakeResponse(200, {"Content-Type": "application/x-git-upload-pack-advertisement"})
    _patch_pools(monkeypatch, _make_fake_pool_class(response, calls, instances))

    assert utils._is_http_git_repo("https://example.com/org/repo") is True
    assert len(instances) == 1
    assert instances[0].host == "93.184.216.34"
    assert instances[0].kwargs.get("server_hostname") == "example.com"
    assert instances[0].kwargs.get("assert_hostname") == "example.com"
    assert calls[0]["headers"]["Host"] == "example.com"


def test_is_http_git_repo_no_longer_treats_401_as_a_repo_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_a, **_kw: [(None, None, None, "", ("93.184.216.34", 0))],
    )
    calls: list[dict[str, Any]] = []
    instances: list[Any] = []
    _patch_pools(monkeypatch, _make_fake_pool_class(_FakeResponse(401), calls, instances))

    assert utils._is_http_git_repo("https://internal.example/service") is False


def test_is_http_git_repo_does_not_follow_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_a, **_kw: [(None, None, None, "", ("93.184.216.34", 0))],
    )
    calls: list[dict[str, Any]] = []
    instances: list[Any] = []
    _patch_pools(monkeypatch, _make_fake_pool_class(_FakeResponse(200), calls, instances))

    utils._is_http_git_repo("https://example.com/some/repo")
    assert calls[0]["redirect"] is False


def test_is_http_git_repo_accepts_genuine_200_git_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_a, **_kw: [(None, None, None, "", ("93.184.216.34", 0))],
    )
    calls: list[dict[str, Any]] = []
    instances: list[Any] = []
    response = _FakeResponse(200, {"Content-Type": "application/x-git-upload-pack-advertisement"})
    _patch_pools(monkeypatch, _make_fake_pool_class(response, calls, instances))

    assert utils._is_http_git_repo("https://example.com/some/repo") is True


def test_is_http_git_repo_returns_false_on_connection_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_a, **_kw: [(None, None, None, "", ("93.184.216.34", 0))],
    )
    calls: list[dict[str, Any]] = []
    instances: list[Any] = []
    _patch_pools(
        monkeypatch,
        _make_fake_pool_class(utils.urllib3.exceptions.HTTPError("boom"), calls, instances),
    )

    assert utils._is_http_git_repo("https://example.com/some/repo") is False
