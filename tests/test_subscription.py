"""Tests for the ``strix --sub`` subscription wiring."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from strix.subscription.bringup import _wire_env
from strix.subscription.registry import BACKENDS, SUB_CHOICES


if TYPE_CHECKING:
    import pytest


def test_sub_choices_match_implemented_backends() -> None:
    assert SUB_CHOICES == ["claude", "codex"]
    assert BACKENDS["claude"].default_model == "anthropic/claude-sonnet-4-6"
    assert BACKENDS["codex"].default_model == "openai/gpt-5.4"


def test_wire_env_fills_defaults_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("STRIX_LLM", "LLM_API_BASE", "LLM_API_KEY"):
        monkeypatch.delenv(var, raising=False)

    _wire_env("claude", "anthropic/claude-sonnet-4-6", "http://127.0.0.1:9999/v1")

    assert os.environ["STRIX_LLM"] == "anthropic/claude-sonnet-4-6"
    assert os.environ["LLM_API_BASE"] == "http://127.0.0.1:9999/v1"
    assert os.environ["LLM_API_KEY"]


def test_wire_env_preserves_user_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-sonnet-4-6")
    monkeypatch.delenv("LLM_API_BASE", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    _wire_env("claude", "anthropic/claude-opus-4-8", "http://127.0.0.1:9999/v1")

    assert os.environ["STRIX_LLM"] == "anthropic/claude-sonnet-4-6"
