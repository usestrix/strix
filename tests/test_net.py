from __future__ import annotations

import ssl
from typing import Any

import certifi
import pytest

from strix.utils import net


@pytest.fixture(autouse=True)
def _reset_cache(monkeypatch: pytest.MonkeyPatch) -> None:
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
    real_create = ssl.create_default_context
    calls: list[dict[str, Any]] = []

    def fake_create(*args: Any, **kwargs: Any) -> ssl.SSLContext:
        calls.append(kwargs)
        context = real_create(*args, **kwargs)
        if "cafile" not in kwargs:
            monkeypatch.setattr(context, "cert_store_stats", lambda: {"x509_ca": 0})
        return context

    monkeypatch.setattr(ssl, "create_default_context", fake_create)

    net.tls_context()

    assert calls[-1].get("cafile") == certifi.where()
