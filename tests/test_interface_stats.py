"""Tests for TUI / CLI usage stats rendering."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from strix.interface.utils import build_final_stats_text, build_live_stats_text


def _report_state_with_usage(usage: dict) -> SimpleNamespace:
    state = SimpleNamespace(vulnerability_reports=[])
    state.get_total_llm_usage = MagicMock(return_value=usage)
    return state


def test_usage_stats_without_cache_uses_simple_input_label() -> None:
    text = build_final_stats_text(
        _report_state_with_usage(
            {
                "requests": 1,
                "input_tokens": 1_000_000,
                "output_tokens": 500_000,
                "cost": 0.5,
            }
        )
    )

    plain = text.plain
    assert "Input Tokens 1.0M" in plain
    assert "Cached" not in plain
    assert "New input" not in plain


def test_live_mode_without_cache_still_shows_cached_row() -> None:
    """Live sidebar always exposes the cache metric, even when it is still zero."""
    text = build_live_stats_text(
        _report_state_with_usage(
            {
                "requests": 1,
                "input_tokens": 1_000_000,
                "output_tokens": 500_000,
            }
        )
    )

    plain = text.plain
    assert "Input Tokens 1.0M" in plain
    assert "Cached (in total) 0" in plain
    assert "New input" not in plain
    assert plain.index("Input Tokens") < plain.index("Cached (in total)")


def test_usage_stats_with_cache_shows_subset_breakdown() -> None:
    text = build_live_stats_text(
        _report_state_with_usage(
            {
                "requests": 1,
                "input_tokens": 20_000_000,
                "output_tokens": 1_000_000,
                "input_tokens_details": {"cached_tokens": 19_000_000},
            }
        )
    )

    plain = text.plain
    assert "Input (total) 20.0M" in plain
    assert "Cached (in total) 19.0M" in plain
    assert "New input 1.0M" in plain
    assert plain.index("Input (total)") < plain.index("Cached (in total)") < plain.index("New input")
