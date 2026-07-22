"""Tests for the proxy tool TUI renderers."""

from __future__ import annotations

import pytest
from rich.text import Text

from strix.interface.tui.live_view import _tool_status_from_result
from strix.interface.tui.renderers.proxy_renderer import (
    ListRequestsRenderer,
    ListSitemapRenderer,
    RepeatRequestRenderer,
    ScopeRulesRenderer,
    ViewRequestRenderer,
    ViewSitemapEntryRenderer,
)


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


# Every proxy-tool error payload sets `success: false`, which
# `live_view._tool_status_from_result` maps to status "failed" -- so the
# renderers must show results for that status too, not just "completed".
@pytest.mark.parametrize(
    ("renderer", "args"),
    [
        (ListRequestsRenderer, {}),
        (ViewRequestRenderer, {"request_id": "req-1"}),
        (RepeatRequestRenderer, {"request_id": "req-1"}),
        (ListSitemapRenderer, {}),
        (ViewSitemapEntryRenderer, {"entry_id": "e-1"}),
        (ScopeRulesRenderer, {"action": "list"}),
    ],
)
def test_error_is_rendered_for_failed_status(renderer: object, args: dict[str, object]) -> None:
    tool_data = {
        "args": args,
        "result": {"success": False, "error": "proxy tool failed: boom"},
        "status": _tool_status_from_result({"success": False, "error": "x"}),
    }

    assert "proxy tool failed: boom" in _plain(renderer.render(tool_data))  # type: ignore[attr-defined]


def test_tool_status_from_result_maps_failure_to_failed() -> None:
    # Pins the mapping the renderers' gate has to agree with.
    assert _tool_status_from_result({"success": False, "error": "x"}) == "failed"
    assert _tool_status_from_result({"success": True}) == "completed"


def test_incomplete_replay_says_so_instead_of_showing_an_empty_response() -> None:
    # _format_replay_tool_result sets success=False with no `error` key when the
    # replay never reached DONE; it must not render as a returned response.
    tool_data = {
        "args": {"request_id": "req-1"},
        "result": {
            "success": False,
            "status": "TIMEDOUT",
            "session_id": "s-1",
            "elapsed_ms": 30000,
            "response": None,
        },
        "status": "failed",
    }
    text = _plain(RepeatRequestRenderer.render(tool_data))

    assert "replay did not complete: TIMEDOUT" in text
    assert "<<" not in text, "rendered a response line for a replay that never returned"


def test_successful_replay_still_renders_its_response() -> None:
    tool_data = {
        "args": {"request_id": "req-1"},
        "result": {
            "success": True,
            "status": "DONE",
            "elapsed_ms": 12,
            "response": {"status_code": 200, "body": "ok"},
        },
        "status": "completed",
    }
    text = _plain(RepeatRequestRenderer.render(tool_data))

    assert "200" in text
    assert "replay did not complete" not in text


def test_successful_result_still_renders() -> None:
    tool_data = {
        "args": {},
        "result": {"success": True, "entries": [], "page_info": {"has_next_page": False}},
        "status": "completed",
    }

    assert "[0 found]" in _plain(ListRequestsRenderer.render(tool_data))
