"""Unit tests for litellm routing predicates in :mod:`strix.report.usage`."""

from __future__ import annotations

import pytest

from strix.report.usage import _is_litellm_routed, _litellm_model_name


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        (None, None),
        ("", None),
        ("   ", None),
        ("gpt-4", "gpt-4"),
        ("litellm/gpt-4", "gpt-4"),
        ("any-llm/gpt-4", "gpt-4"),
        ("openai/gpt-4", "gpt-4"),
        ("deepseek/deepseek-chat", "deepseek/deepseek-chat"),
    ],
)
def test_litellm_model_name(model: str | None, expected: str | None) -> None:
    assert _litellm_model_name(model) == expected


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        (None, False),
        ("gpt-4", False),
        ("openai/gpt-4", False),
        ("deepseek/deepseek-chat", True),
        ("litellm/gpt-4", True),
        ("any-llm/gpt-4", True),
    ],
)
def test_is_litellm_routed(model: str | None, expected: bool) -> None:
    assert _is_litellm_routed(model) is expected
