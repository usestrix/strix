"""Tests for the shared TLS context used by stdlib ``urllib`` callers."""

from __future__ import annotations

import ssl
from typing import Any

import certifi
import pytest

from strix import net


@pytest.fixture(autouse=True)
def _reset_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    # tls_context() memoizes into a module global; clear it so each test builds fresh.
    monkeypatch.setattr(net, "_context", None)


def test_tls_context_verifies_certificates() -> None:
    context = net.tls_context()
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_tls_context_is_cached() -> None:
    assert net.tls_context() is net.tls_context()


def test_tls_context_falls_back_to_certifi_when_os_store_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The frozen-build case: an empty platform store must fall back to certifi."""
    real_create = ssl.create_default_context
    calls: list[dict[str, Any]] = []

    def fake_create(*args: Any, **kwargs: Any) -> ssl.SSLContext:
        calls.append(kwargs)
        context = real_create(*args, **kwargs)
        if "cafile" not in kwargs:
            # Simulate the frozen build: platform trust store resolves to nothing.
            monkeypatch.setattr(context, "cert_store_stats", lambda: {"x509_ca": 0})
        return context

    monkeypatch.setattr(ssl, "create_default_context", fake_create)

    net.tls_context()

    # Empty store on the first (platform) call → a second call loading certifi.
    assert calls[-1].get("cafile") == certifi.where()
