"""Tests for finish_scan TUI result states."""

from __future__ import annotations

from rich.text import Text

from strix.interface.tui.renderers.finish_renderer import FinishScanRenderer


def _plain(tool_data: dict[str, object]) -> str:
    static = FinishScanRenderer.render(tool_data)
    content = static.content
    return content.plain if isinstance(content, Text) else str(content)


def test_pending_finish_renders_generation_status_only() -> None:
    rendered = _plain({"args": {"executive_summary": "Draft section"}})

    assert "Generating final report..." in rendered
    assert "Penetration test completed" not in rendered
    assert "Draft section" not in rendered


def test_completion_nudge_renders_continued_testing_without_draft() -> None:
    rendered = _plain(
        {
            "args": {
                "executive_summary": "Draft executive section",
                "methodology": "Draft methodology section",
                "technical_analysis": "Draft technical section",
                "recommendations": "Draft recommendations section",
            },
            "result": {
                "success": True,
                "scan_completed": False,
                "completion_nudge": True,
            },
        }
    )

    assert "Completion nudged" in rendered
    assert "Testing continues" in rendered
    assert "Penetration test completed" not in rendered
    assert "Draft executive section" not in rendered
    assert "Draft methodology section" not in rendered
    assert "Draft technical section" not in rendered
    assert "Draft recommendations section" not in rendered


def test_failed_finish_renders_error_without_completion() -> None:
    rendered = _plain(
        {
            "result": {
                "success": False,
                "scan_completed": False,
                "error": "Validation failed",
            }
        }
    )

    assert "Final report not accepted" in rendered
    assert "Validation failed" in rendered
    assert "Penetration test completed" not in rendered


def test_completed_finish_renders_accepted_sections() -> None:
    rendered = _plain(
        {
            "args": {
                "executive_summary": "Accepted executive section",
                "methodology": "Accepted methodology section",
                "technical_analysis": "Accepted technical section",
                "recommendations": "Accepted recommendations section",
            },
            "result": {"success": True, "scan_completed": True},
        }
    )

    assert "Penetration test completed" in rendered
    assert "Accepted executive section" in rendered
    assert "Accepted methodology section" in rendered
    assert "Accepted technical section" in rendered
    assert "Accepted recommendations section" in rendered
