"""Tests for model-aware token budgets."""

from __future__ import annotations

from typing import TYPE_CHECKING

from strix.config import load_settings
from strix.llm import context_budget


if TYPE_CHECKING:
    import pytest


def test_context_window_known_model() -> None:
    # gpt-4o is mapped by LiteLLM at 128k input tokens.
    assert context_budget.context_window("gpt-4o") == 128_000


def test_context_window_strips_provider_prefix() -> None:
    assert context_budget.context_window("openai/gpt-4o") == 128_000


def test_context_window_unmapped_uses_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    context_budget._model_info.cache_clear()

    def _raise(_model: str) -> dict[str, int]:
        raise ValueError("This model isn't mapped yet.")

    monkeypatch.setattr("strix.llm.context_budget.litellm.get_model_info", _raise)
    expected = load_settings().context.fallback_context_tokens
    assert context_budget.context_window("totally-made-up-model") == expected
    context_budget._model_info.cache_clear()


def test_count_tokens_fallback_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(**_kwargs: object) -> int:
        raise RuntimeError("no tokenizer")

    monkeypatch.setattr("strix.llm.context_budget.litellm.token_counter", _raise)
    # Falls back to UTF-8 byte length (upper bound on tokens).
    assert context_budget.count_tokens("weird-model", "x" * 400) == 400
    assert context_budget.count_tokens("weird-model", "😀" * 10) == 40


def test_count_tokens_empty_is_zero() -> None:
    assert context_budget.count_tokens("gpt-4o", "") == 0
