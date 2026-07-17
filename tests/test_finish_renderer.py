"""Tests for the finish_scan TUI renderer (section-heading de-duplication)."""

from __future__ import annotations

from rich.text import Text

from strix.interface.tui.renderers.finish_renderer import (
    FinishScanRenderer,
    _strip_leading_heading,
)


def _plain(static: object) -> str:
    content = static.content  # type: ignore[attr-defined]
    return content.plain if isinstance(content, Text) else str(content)


def _render(**args: str) -> str:
    return _plain(FinishScanRenderer.render({"status": "completed", "args": args}))


# --- _strip_leading_heading -------------------------------------------------


def test_strips_matching_leading_heading() -> None:
    assert _strip_leading_heading("# Executive Summary\n\nBody", "Executive Summary") == "Body"
    assert _strip_leading_heading("## Methodology\nSteps", "Methodology") == "Steps"


def test_strip_is_case_and_whitespace_insensitive() -> None:
    assert _strip_leading_heading("#  technical analysis \n\nX", "Technical Analysis") == "X"


def test_keeps_a_different_leading_heading() -> None:
    # A heading that isn't the section label is real content — leave it.
    val = "# Findings Overview\nY"
    assert _strip_leading_heading(val, "Executive Summary") == val


def test_keeps_body_when_no_heading() -> None:
    assert _strip_leading_heading("No heading here", "Methodology") == "No heading here"


def test_keeps_lone_heading_with_no_body() -> None:
    # No trailing newline => not a section split; don't strip to empty.
    assert _strip_leading_heading("# Recommendations", "Recommendations") == "# Recommendations"


# --- end-to-end render ------------------------------------------------------


def test_section_heading_rendered_once_not_twice() -> None:
    # The model is prompted to write markdown and routinely opens each field
    # with a `# <Section>` heading; the renderer also prints a styled label.
    # Regression: both showed, doubling the heading. Now the field's leading
    # heading is stripped so "Executive Summary" appears exactly once.
    out = _render(executive_summary="# Executive Summary\n\nThe app is sound.")
    assert out.count("Executive Summary") == 1
    assert "The app is sound." in out


def test_render_preserves_body_without_heading() -> None:
    out = _render(methodology="White-box review of the diff.")
    assert "Methodology" in out
    assert "White-box review of the diff." in out
