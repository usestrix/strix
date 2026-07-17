"""Tests for the dedicated deduplication model configuration."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from strix.config import loader
from strix.config.settings import DedupeSettings


if TYPE_CHECKING:
    from pathlib import Path

    import pytest


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


def test_structured_config_loads_dedupe_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in ("STRIX_LLM", "STRIX_ORCHESTRATOR_MODEL", "STRIX_DEDUPE_MODEL"):
        monkeypatch.delenv(key, raising=False)
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "llm": {"model": "openai/root"},
                "dedupe": {"model": "deepseek/cheap", "reasoning_effort": "minimal"},
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
    # Orchestrator model stays independent of the dedupe override.
    assert settings.llm.model == "openai/root"
