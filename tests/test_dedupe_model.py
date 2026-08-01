"""Tests for the dedicated deduplication model configuration."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from strix.config import loader
from strix.config.settings import DedupeSettings
from strix.report.dedupe import _dedupe_model_settings


if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def test_dedupe_key_sent_per_call_not_via_global_env() -> None:
    dedupe = DedupeSettings(STRIX_DEDUPE_MODEL="deepseek/cheap", DEDUPE_LLM_API_KEY="dedupe-key")
    settings = _dedupe_model_settings(dedupe, "deepseek/cheap", 300)
    # The key rides on the request, so a shared-provider main key can't clobber
    # it (and vice versa) through the global provider env var.
    assert (settings.extra_args or {})["api_key"] == "dedupe-key"


def test_dedupe_settings_omit_api_key_when_unset() -> None:
    dedupe = DedupeSettings(STRIX_DEDUPE_MODEL="deepseek/cheap")
    settings = _dedupe_model_settings(dedupe, "deepseek/cheap", 300)
    assert "api_key" not in (settings.extra_args or {})
    assert "api_base" not in (settings.extra_args or {})


def test_dedupe_endpoint_sent_per_call() -> None:
    dedupe = DedupeSettings(
        STRIX_DEDUPE_MODEL="openai/cheap",
        DEDUPE_LLM_API_KEY="dedupe-key",
        DEDUPE_LLM_API_BASE="https://dedupe.example/v1",
    )
    settings = _dedupe_model_settings(dedupe, "openai/cheap", 300)
    # A distinct dedupe endpoint rides on the request instead of the
    # process-wide base URL, so it can't clobber the main model's endpoint.
    assert (settings.extra_args or {})["api_base"] == "https://dedupe.example/v1"
    assert (settings.extra_args or {})["api_key"] == "dedupe-key"


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
