"""Tests for the proxy tool TUI renderers."""

from __future__ import annotations

from rich.text import Text

from strix.interface.tui.renderers.proxy_renderer import ViewRequestRenderer


def _plain(static: object) -> str:
    content = static.content  # type: ignore[attr-defined]
    return content.plain if isinstance(content, Text) else str(content)


def _render(content: str, *, has_more: bool) -> str:
    tool_data = {
        "status": "completed",
        "result": {
            "content": content,
            "has_more": has_more,
            "page": 1,
            "total_lines": len(content.split("\n")),
        },
    }
    return _plain(ViewRequestRenderer.render(tool_data))


_MARKER = "... more content available"


def test_more_content_hint_shown_when_over_fifteen_lines() -> None:
    content = "\n".join(f"line{i}" for i in range(30))

    assert _MARKER in _render(content, has_more=False)


def test_no_more_content_hint_within_fifteen_lines() -> None:
    content = "\n".join(f"line{i}" for i in range(5))

    assert _MARKER not in _render(content, has_more=False)


def test_more_content_hint_shown_when_has_more_flag_set() -> None:
    content = "\n".join(f"line{i}" for i in range(3))

    assert _MARKER in _render(content, has_more=True)
