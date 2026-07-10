"""Tests for the agent message TUI renderer."""

from __future__ import annotations

from importlib.util import module_from_spec
from importlib.util import spec_from_file_location
from pathlib import Path


def _load_module() -> object:
    module_path = Path(__file__).resolve().parents[1] / "strix" / "interface" / "tui" / "renderers" / "agent_message_renderer.py"
    spec = spec_from_file_location("agent_message_renderer", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_MODULE = _load_module()
_apply_markdown_styles = _MODULE._apply_markdown_styles


def test_ordered_list_dot_marker_uses_single_space() -> None:
    assert _apply_markdown_styles("1. Hello").plain == "1. Hello"


def test_ordered_list_paren_marker_uses_single_space() -> None:
    assert _apply_markdown_styles("2) World").plain == "2. World"


def test_bullet_marker_remains_single_spaced() -> None:
    assert _apply_markdown_styles("- Item").plain == "• Item"
