"""Tests for markdown styling in the agent-message TUI renderer."""

from __future__ import annotations

from strix.interface.tui.renderers.agent_message_renderer import _apply_markdown_styles


def test_numbered_list_has_single_space_after_marker() -> None:
    result = _apply_markdown_styles("1. Hello").plain

    assert result == "1. Hello"
    assert "1.  Hello" not in result


def test_numbered_list_paren_marker_normalized_single_space() -> None:
    result = _apply_markdown_styles("2) World").plain

    assert result == "2. World"
    assert "2.  World" not in result


def test_bullet_list_marker_unaffected() -> None:
    assert _apply_markdown_styles("- Item").plain == "• Item"
