"""Tests for LLM_EXTRA_HEADERS: custom default headers on OpenAI-compatible endpoints."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import litellm
import pytest
from agents.models import _openai_shared

from strix.config import loader
from strix.config.loader import load_settings
from strix.config.models import configure_sdk_model_defaults


if TYPE_CHECKING:
    from collections.abc import Iterator


_ENV_KEYS = ["STRIX_LLM", "LLM_API_KEY", "LLM_API_BASE", "LLM_EXTRA_HEADERS"]


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)

    saved_headers = litellm.headers
    saved_client = _openai_shared.get_default_openai_client()
    litellm.headers = None
    try:
        yield
    finally:
        litellm.headers = saved_headers
        _openai_shared.set_default_openai_client(saved_client)  # type: ignore[arg-type]


def test_extra_headers_parsed_from_json_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_EXTRA_HEADERS", json.dumps({"X-A": "1", "X-B": "2"}))
    settings = load_settings()
    assert settings.llm.extra_headers == {"X-A": "1", "X-B": "2"}


def test_extra_headers_merged_into_litellm_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "litellm/openai/some-model")
    monkeypatch.setenv("LLM_API_BASE", "https://gateway.example/v1")
    monkeypatch.setenv("LLM_API_KEY", "token")
    headers = {"X-Feature-Key": "svc", "X-Tenant": "acme"}
    monkeypatch.setenv("LLM_EXTRA_HEADERS", json.dumps(headers))

    configure_sdk_model_defaults(load_settings())

    current: object = litellm.headers
    assert isinstance(current, dict)
    assert current["X-Feature-Key"] == "svc"
    assert current["X-Tenant"] == "acme"


def test_extra_headers_applied_to_native_openai_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/some-model")
    monkeypatch.setenv("LLM_API_BASE", "https://gateway.example/v1")
    monkeypatch.setenv("LLM_API_KEY", "token")
    monkeypatch.setenv("LLM_EXTRA_HEADERS", json.dumps({"X-Feature-Key": "svc"}))

    configure_sdk_model_defaults(load_settings())

    client = _openai_shared.get_default_openai_client()
    assert client is not None
    assert client.default_headers.get("X-Feature-Key") == "svc"
    assert str(client.base_url).rstrip("/") == "https://gateway.example/v1"


def test_extra_headers_applied_to_native_openai_without_custom_base(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-5")
    monkeypatch.setenv("LLM_API_KEY", "token")
    monkeypatch.setenv("LLM_EXTRA_HEADERS", json.dumps({"X-Feature-Key": "svc"}))

    configure_sdk_model_defaults(load_settings())

    client = _openai_shared.get_default_openai_client()
    assert client is not None
    assert client.default_headers.get("X-Feature-Key") == "svc"


def test_no_extra_headers_leaves_litellm_headers_untouched(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/some-model")
    monkeypatch.setenv("LLM_API_BASE", "https://gateway.example/v1")
    monkeypatch.setenv("LLM_API_KEY", "token")

    configure_sdk_model_defaults(load_settings())

    assert litellm.headers is None
