"""Tests for SDK model configuration, including SOCKS-proxy startup resilience."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING

import socksio

from strix.config import models


if TYPE_CHECKING:
    import pytest


def _make_settings() -> SimpleNamespace:
    """Build a minimal settings stub with no API key / base configured."""
    llm = SimpleNamespace(api_key=None, api_base=None, model=None)
    return SimpleNamespace(llm=llm)


def test_socksio_importable() -> None:
    """socksio must be declared so httpx can build a SOCKS transport at startup."""
    assert socksio is not None


def test_configure_tolerates_tracing_import_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing SOCKS transport during tracing init must not crash startup.

    With a SOCKS proxy env var set, ``set_tracing_disabled`` eagerly builds an
    httpx client that can raise ImportError. That failure is non-fatal and must
    be swallowed so the rest of the SDK configuration still runs.
    """

    def _raise(_disabled: bool) -> None:
        raise ImportError("Using SOCKS proxy, but the 'socksio' package is not installed")

    monkeypatch.setattr(models, "set_tracing_disabled", _raise)
    monkeypatch.setattr(models, "_configure_litellm_compatibility", lambda: None)

    # Should not raise despite set_tracing_disabled blowing up.
    models.configure_sdk_model_defaults(_make_settings())
