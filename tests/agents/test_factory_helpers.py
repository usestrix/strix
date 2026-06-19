"""Tests for helper functions added to strix/agents/factory.py."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from strix.agents.factory import _extract_task_hint, _resolve_model


# ---------------------------------------------------------------------------
# _resolve_model
# ---------------------------------------------------------------------------


def test_resolve_model_uses_run_config_model() -> None:
    """Prefers ctx.run_config.model when it is a non-empty string."""
    ctx = MagicMock()
    ctx.run_config.model = "claude-sonnet-4-6"
    assert _resolve_model(ctx) == "claude-sonnet-4-6"


def test_resolve_model_strips_whitespace() -> None:
    ctx = MagicMock()
    ctx.run_config.model = "  claude-haiku-4-5  "
    assert _resolve_model(ctx) == "claude-haiku-4-5"


def test_resolve_model_skips_model_object_falls_back_to_settings() -> None:
    """A non-string run_config.model (e.g. Model object) must be ignored."""
    ctx = MagicMock()
    ctx.run_config.model = object()  # not a str
    with patch("strix.agents.factory.load_settings") as mock_settings:
        mock_settings.return_value.llm.model = "anthropic/claude-3-5-haiku"
        result = _resolve_model(ctx)
    assert result == "anthropic/claude-3-5-haiku"


def test_resolve_model_falls_back_to_settings_when_run_config_is_none() -> None:
    ctx = MagicMock()
    ctx.run_config = None
    with patch("strix.agents.factory.load_settings") as mock_settings:
        mock_settings.return_value.llm.model = "gpt-4o"
        result = _resolve_model(ctx)
    assert result == "gpt-4o"


def test_resolve_model_raises_when_both_none() -> None:
    ctx = MagicMock()
    ctx.run_config.model = None
    with patch("strix.agents.factory.load_settings") as mock_settings:
        mock_settings.return_value.llm.model = None
        with pytest.raises(RuntimeError, match="No LLM model configured"):
            _resolve_model(ctx)


def test_resolve_model_raises_when_settings_model_is_whitespace() -> None:
    ctx = MagicMock()
    ctx.run_config.model = None
    with patch("strix.agents.factory.load_settings") as mock_settings:
        mock_settings.return_value.llm.model = "   "
        with pytest.raises(RuntimeError, match="No LLM model configured"):
            _resolve_model(ctx)


# ---------------------------------------------------------------------------
# _extract_task_hint
# ---------------------------------------------------------------------------


def test_extract_task_hint_returns_cmd_field() -> None:
    raw = json.dumps({"cmd": "semgrep --json --config auto /workspace"})
    assert _extract_task_hint(raw) == "semgrep --json --config auto /workspace"


def test_extract_task_hint_returns_empty_for_invalid_json() -> None:
    assert _extract_task_hint("not json at all") == ""


def test_extract_task_hint_returns_empty_when_cmd_missing() -> None:
    raw = json.dumps({"workdir": "/workspace"})
    assert _extract_task_hint(raw) == ""


def test_extract_task_hint_returns_empty_when_cmd_is_not_string() -> None:
    raw = json.dumps({"cmd": 42})
    assert _extract_task_hint(raw) == ""


def test_extract_task_hint_returns_empty_for_non_object_json() -> None:
    assert _extract_task_hint(json.dumps(["a", "b"])) == ""
