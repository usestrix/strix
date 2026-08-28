"""Tests for the dedicated deduplication model configuration."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from agents.extensions.models.litellm_model import LitellmModel
from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing

from strix.config import loader
from strix.config.settings import DedupeSettings
from strix.report.dedupe import _dedupe_model_settings, dedupe_model_provider


if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def _litellm_route(dedupe: DedupeSettings, model_name: str) -> LitellmModel:
    model = dedupe_model_provider(dedupe).get_model(model_name)
    while not isinstance(model, LitellmModel):
        model = model._inner  # type: ignore[attr-defined]
    return model


def test_dedupe_key_bound_to_model_not_via_global_env() -> None:
    dedupe = DedupeSettings(STRIX_DEDUPE_MODEL="deepseek/cheap", DEDUPE_LLM_API_KEY="dedupe-key")
    # The key rides on the dedupe model, so a shared-provider main key can't
    # clobber it (and vice versa) through the global provider env var.
    assert _litellm_route(dedupe, "deepseek/cheap").api_key == "dedupe-key"


def test_dedupe_credentials_never_ride_on_extra_args() -> None:
    # LiteLLM already receives an explicit api_key on every call; a copy in
    # extra_args reaches acompletion() twice and fails the call outright.
    dedupe = DedupeSettings(
        STRIX_DEDUPE_MODEL="deepseek/cheap",
        DEDUPE_LLM_API_KEY="dedupe-key",
        DEDUPE_LLM_API_BASE="https://dedupe.example/v1",
    )
    settings = _dedupe_model_settings(dedupe, "deepseek/cheap", 300)
    assert "api_key" not in (settings.extra_args or {})
    assert "api_base" not in (settings.extra_args or {})


def test_dedupe_settings_omit_api_key_when_unset() -> None:
    dedupe = DedupeSettings(STRIX_DEDUPE_MODEL="deepseek/cheap")
    settings = _dedupe_model_settings(dedupe, "deepseek/cheap", 300)
    assert "api_key" not in (settings.extra_args or {})
    assert "api_base" not in (settings.extra_args or {})
    assert _litellm_route(dedupe, "deepseek/cheap").api_key is None


def test_dedupe_endpoint_bound_to_model() -> None:
    dedupe = DedupeSettings(
        STRIX_DEDUPE_MODEL="deepseek/cheap",
        DEDUPE_LLM_API_KEY="dedupe-key",
        DEDUPE_LLM_API_BASE="https://dedupe.example/v1",
    )
    # A distinct dedupe endpoint rides on the dedupe model instead of the
    # process-wide base URL, so it can't clobber the main model's endpoint.
    route = _litellm_route(dedupe, "deepseek/cheap")
    assert route.base_url == "https://dedupe.example/v1"
    assert route.api_key == "dedupe-key"


def test_fallback_dedupe_model_keeps_global_credentials() -> None:
    # Without a dedicated dedupe model the main model's global config applies.
    route = _litellm_route(DedupeSettings(DEDUPE_LLM_API_KEY="dedupe-key"), "deepseek/cheap")
    assert route.api_key is None
    assert route.base_url is None


async def test_dedupe_call_does_not_duplicate_litellm_api_key() -> None:
    """Regression for #1095: the dedupe call reached litellm with two api_key values."""
    dedupe = DedupeSettings(
        STRIX_DEDUPE_MODEL="deepseek/cheap",
        DEDUPE_LLM_API_KEY="dedupe-key",
        DEDUPE_LLM_API_BASE="https://dedupe.example/v1",
    )
    model = dedupe_model_provider(dedupe).get_model("deepseek/cheap")
    settings = _dedupe_model_settings(dedupe, "deepseek/cheap", 300)
    settings = settings.resolve(
        ModelSettings(extra_args={**(settings.extra_args or {}), "mock_response": "OK"})
    )
    response = await model.get_response(
        system_instructions="You are a helpful assistant.",
        input="Reply with just 'OK'.",
        model_settings=settings,
        tools=[],
        output_schema=None,
        handoffs=[],
        tracing=ModelTracing.DISABLED,
        previous_response_id=None,
        conversation_id=None,
        prompt=None,
    )
    assert response.output


def test_dedicated_dedupe_model_uses_own_headers_not_main() -> None:
    dedupe = DedupeSettings(
        STRIX_DEDUPE_MODEL="deepseek/cheap",
        DEDUPE_LLM_EXTRA_HEADERS={"X-Dedupe": "yes"},
    )
    settings = _dedupe_model_settings(dedupe, "deepseek/cheap", 300)
    assert settings.extra_headers == {"X-Dedupe": "yes"}


def test_dedicated_dedupe_model_gets_no_main_headers_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LLM_EXTRA_HEADERS", json.dumps({"X-Main": "secret"}))
    loader._cached = None
    try:
        dedupe = DedupeSettings(STRIX_DEDUPE_MODEL="deepseek/cheap")
        settings = _dedupe_model_settings(dedupe, "deepseek/cheap", 300)
        assert settings.extra_headers is None
    finally:
        loader._cached = None


def test_fallback_dedupe_inherits_main_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_EXTRA_HEADERS", json.dumps({"X-Main": "svc"}))
    loader._cached = None
    try:
        settings = _dedupe_model_settings(DedupeSettings(), "openai/main-model", 300)
        assert settings.extra_headers == {"X-Main": "svc"}
    finally:
        loader._cached = None


def test_dedupe_defaults_are_empty() -> None:
    settings = DedupeSettings()
    assert settings.model is None
    assert settings.reasoning_effort is None
    assert settings.api_key is None


def test_dedupe_model_read_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_DEDUPE_MODEL", "deepseek/deepseek-v4-flash")
    monkeypatch.setenv("STRIX_DEDUPE_REASONING_EFFORT", "low")

    settings = DedupeSettings()

    assert settings.model == "deepseek/deepseek-v4-flash"
    assert settings.reasoning_effort == "low"


def test_config_file_loads_dedupe_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in ("STRIX_LLM", "STRIX_DEDUPE_MODEL", "STRIX_DEDUPE_REASONING_EFFORT"):
        monkeypatch.delenv(key, raising=False)
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "env": {
                    "STRIX_LLM": "openai/root",
                    "STRIX_DEDUPE_MODEL": "deepseek/cheap",
                    "STRIX_DEDUPE_REASONING_EFFORT": "minimal",
                }
            }
        ),
        encoding="utf-8",
    )
    loader._cached = None
    loader._override = path
    try:
        settings = loader.load_settings()
    finally:
        loader._cached = None
        loader._override = None

    assert settings.dedupe.model == "deepseek/cheap"
    assert settings.dedupe.reasoning_effort == "minimal"
    # Main model stays independent of the dedupe override.
    assert settings.llm.model == "openai/root"
