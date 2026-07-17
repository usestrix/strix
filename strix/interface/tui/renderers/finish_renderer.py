import re
from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


FIELD_STYLE = "bold #4ade80"


def _strip_leading_heading(value: str, section: str) -> str:
    """Drop a leading markdown heading that just repeats the section label.

    The finish_scan tool prompts the model to write markdown in every field, and
    the models routinely open each with a ``# <Section>`` heading (e.g.
    ``# Executive Summary``). This renderer also prints its own styled section
    label above the value, so that heading renders twice. Strip a leading
    ``#``-heading whose text matches this section (case-insensitively) so the
    label isn't duplicated; leave all other content — including headings that
    say something else — untouched. Also matches the closing-``#`` ATX form
    (``# Executive Summary #``). If stripping the heading would leave nothing
    (the field was ONLY the heading, e.g. ``# Recommendations\n``), keep the
    original rather than render the field's sole content as blank.
    """
    stripped = value.lstrip()
    pattern = rf"^#{{1,6}}\s+{re.escape(section)}(?:\s+#+)?\s*\n+"
    m = re.match(pattern, stripped, flags=re.IGNORECASE)
    if not m:
        return value
    remainder = stripped[m.end() :]
    return remainder if remainder.strip() else value


@register_tool_renderer
class FinishScanRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "finish_scan"
    css_classes: ClassVar[list[str]] = ["tool-call", "finish-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        executive_summary = args.get("executive_summary", "")
        methodology = args.get("methodology", "")
        technical_analysis = args.get("technical_analysis", "")
        recommendations = args.get("recommendations", "")

        text = Text()
        text.append("◆ ", style="#22c55e")
        text.append("Penetration test completed", style="bold #22c55e")

        if executive_summary:
            text.append("\n\n")
            text.append("Executive Summary", style=FIELD_STYLE)
            text.append("\n")
            text.append(_strip_leading_heading(executive_summary, "Executive Summary"))

        if methodology:
            text.append("\n\n")
            text.append("Methodology", style=FIELD_STYLE)
            text.append("\n")
            text.append(_strip_leading_heading(methodology, "Methodology"))

        if technical_analysis:
            text.append("\n\n")
            text.append("Technical Analysis", style=FIELD_STYLE)
            text.append("\n")
            text.append(_strip_leading_heading(technical_analysis, "Technical Analysis"))

        if recommendations:
            text.append("\n\n")
            text.append("Recommendations", style=FIELD_STYLE)
            text.append("\n")
            text.append(_strip_leading_heading(recommendations, "Recommendations"))

        if not (executive_summary or methodology or technical_analysis or recommendations):
            text.append("\n  ")
            text.append("Generating final report...", style="dim")

        padded = Text()
        padded.append("\n\n")
        padded.append_text(text)
        padded.append("\n\n")

        css_classes = cls.get_css_classes("completed")
        return Static(padded, classes=css_classes)
