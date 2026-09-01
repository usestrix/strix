"""Security tests for the wallet payment loopback bridge."""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Any

import pytest

from strix.interface.cloud import payment_proxy


if TYPE_CHECKING:
    from collections.abc import Iterator


class _StreamingResponse:
    status_code = 200

    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.closed = False
        self.headers = {"Content-Type": "application/json"}

    def iter_content(self, *, chunk_size: int) -> Iterator[bytes]:
        assert chunk_size > 0
        yield from self.chunks

    def close(self) -> None:
        self.closed = True


def _post(url: str, body: bytes, headers: dict[str, str] | None = None) -> bytes:
    request = urllib.request.Request(  # noqa: S310
        url,
        data=body,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=2) as response:  # noqa: S310
        return response.read()


def test_bridge_bounds_decompressed_upstream_response(monkeypatch: pytest.MonkeyPatch) -> None:
    response = _StreamingResponse([b"1234", b"5"])

    def fake_request(*_args: Any, **kwargs: Any) -> _StreamingResponse:
        assert kwargs["stream"] is True
        return response

    monkeypatch.setattr(payment_proxy, "_MAX_UPSTREAM_RESPONSE_BYTES", 4)
    monkeypatch.setattr(payment_proxy.requests, "request", fake_request)

    with payment_proxy.wallet_payment_bridge(
        upstream_url="https://app.example.test/api/v1/billing/topup",
        api_token="strix-secret",  # noqa: S106
        expected_body=b"{}",
    ) as wallet_url:
        request = urllib.request.Request(  # noqa: S310
            wallet_url,
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(request, timeout=2)  # noqa: S310

    assert exc_info.value.code == 502
    assert response.closed is True


def test_bridge_forwards_only_the_approved_request_and_protected_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[dict[str, Any]] = []
    observed: list[payment_proxy.WalletUpstreamResponse] = []

    def fake_request(*_args: Any, **kwargs: Any) -> _StreamingResponse:
        captured.append(kwargs)
        return _StreamingResponse([b'{"ok":true}'])

    monkeypatch.setattr(payment_proxy.requests, "request", fake_request)
    with payment_proxy.wallet_payment_bridge(
        upstream_url="https://app.example.test/api/v1/billing/topup",
        api_token="strix-secret",  # noqa: S106
        workspace_id="org_trusted",
        expected_body=b'{"credits":5}',
        response_observer=observed.append,
    ) as wallet_url:
        result = _post(
            wallet_url,
            b'{"credits":5}',
            {
                "Authorization": "Payment wallet-proof",
                "Proxy-Authorization": "Basic drop-me",
                "X-Strix-Authorization": "Bearer attacker",
                "X-Strix-Workspace": "org_attacker",
            },
        )

        assert result == b'{"ok":true}'
        headers = captured[0]["headers"]
        assert headers["Authorization"] == "Payment wallet-proof"
        assert headers["X-Strix-Authorization"] == "Bearer strix-secret"
        assert headers["X-Strix-Workspace"] == "org_trusted"
        assert "Proxy-Authorization" not in headers
        assert not any(name.lower() in {"host", "content-length"} for name in headers)
        assert observed == [
            payment_proxy.WalletUpstreamResponse(status_code=200, body=b'{"ok":true}')
        ]

        with pytest.raises(urllib.error.HTTPError) as wrong_body:
            _post(wallet_url, b'{"credits":500}')
        assert wrong_body.value.code == 403
        assert len(captured) == 1


def test_bridge_limits_valid_wallet_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def fake_request(*_args: Any, **_kwargs: Any) -> _StreamingResponse:
        nonlocal calls
        calls += 1
        return _StreamingResponse([b"{}"])

    monkeypatch.setattr(payment_proxy.requests, "request", fake_request)
    with payment_proxy.wallet_payment_bridge(
        upstream_url="https://app.example.test/api/v1/billing/topup",
        api_token="strix-secret",  # noqa: S106
        expected_body=b"{}",
    ) as wallet_url:
        assert _post(wallet_url, b"{}") == b"{}"
        assert _post(wallet_url, b"{}") == b"{}"
        assert _post(wallet_url, b"{}") == b"{}"
        with pytest.raises(urllib.error.HTTPError) as extra_request:
            _post(wallet_url, b"{}")

    assert extra_request.value.code == 429
    assert calls == payment_proxy._MAX_WALLET_REQUESTS
