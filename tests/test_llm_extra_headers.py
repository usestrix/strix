"""Tests for route-bound custom request headers."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import litellm
import pytest
from agents.model_settings import ModelSettings

from strix.config import loader
from strix.config.loader import load_settings
from strix.config.models import (
    configure_sdk_model_defaults,
    model_extra_headers,
    with_model_request_headers,
)


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
    litellm.headers = None
    try:
        yield
    finally:
        litellm.headers = saved_headers


def test_extra_headers_parsed_from_json_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_EXTRA_HEADERS", json.dumps({"X-A": "1", "X-B": "2"}))

    settings = load_settings()

    assert settings.llm.extra_headers == {"X-A": "1", "X-B": "2"}
    assert "X-A" not in repr(settings.llm)


def test_extra_headers_are_bound_to_configured_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-5")
    monkeypatch.setenv("LLM_EXTRA_HEADERS", json.dumps({"X-Feature-Key": "svc"}))
    settings = load_settings()

    assert model_extra_headers(settings, "openai/gpt-5-mini") == {"X-Feature-Key": "svc"}
    assert model_extra_headers(settings, "anthropic/claude") is None


def test_sdk_configuration_does_not_install_global_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_LLM", "litellm/openai/some-model")
    monkeypatch.setenv("LLM_API_BASE", "https://gateway.example/v1")
    monkeypatch.setenv("LLM_API_KEY", "token")
    monkeypatch.setenv("LLM_EXTRA_HEADERS", json.dumps({"X-Feature-Key": "svc"}))

    configure_sdk_model_defaults(load_settings())

    assert litellm.headers is None


def test_openrouter_attribution_merges_with_user_headers() -> None:
    settings = ModelSettings(
        extra_headers={
            "X-Feature-Key": "svc",
            "X-Title": "Custom title",
        }
    )

    resolved = with_model_request_headers(settings, "openrouter/openai/gpt-5")

    assert resolved.extra_headers == {
        "HTTP-Referer": "https://strix.ai",
        "X-Title": "Custom title",
        "X-OpenRouter-Categories": "cli-agent",
        "X-Feature-Key": "svc",
    }


def test_no_extra_headers_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-5")

    assert model_extra_headers(load_settings(), "openai/gpt-5") is None
