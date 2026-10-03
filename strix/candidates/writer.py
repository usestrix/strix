"""Render candidate (lead) records to markdown for the run dir and the report.

Kept separate from ``strix.report.writer`` (and importing nothing from it) so the
lead artifacts stay additive and rebaseable. Produces ``LEADS.md`` in the run dir
and the "Leads (unvalidated)" section appended to the executive report.
"""

from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from pathlib import Path

    from strix.candidates.schema import Candidate


_LEADS_INTRO = (
    "These are unvalidated leads — scanner/recon output whose impact was **not** "
    "demonstrated. They are not findings and are not counted as such. Each needs a "
    "validated proof-of-concept before it becomes a finding, or a stated reason to "
    "dismiss it."
)


def render_leads_markdown(candidates: list[Candidate]) -> str:
    """Render all candidates grouped by status, open ones first and by domain."""
    if not candidates:
        return ""

    open_ = [c for c in candidates if c.status == "open"]
    promoted = [c for c in candidates if c.status == "promoted"]
    dismissed = [c for c in candidates if c.status == "dismissed"]

    lines: list[str] = ["# Leads (unvalidated)", "", _LEADS_INTRO, ""]
    lines.append(
        f"**{len(open_)} open**, {len(promoted)} promoted to findings, "
        f"{len(dismissed)} dismissed.\n"
    )

    if open_:
        lines.append("## Open leads\n")
        by_domain: dict[str, list[Candidate]] = {}
        for c in open_:
            by_domain.setdefault(c.domain, []).append(c)
        for domain in sorted(by_domain):
            lines.append(f"### {domain}\n")
            for c in by_domain[domain]:
                lines.append(f"- **{c.id}** — {c.title}")
                lines.append(f"  - Target: `{c.target}`")
                lines.append(f"  - Source: {c.source}")
                lines.append(f"  - Why it might matter / what's unproven: {c.rationale}")
            lines.append("")

    if promoted:
        lines.append("## Promoted to findings\n")
        for c in promoted:
            to = f" → `{c.promoted_to}`" if c.promoted_to else ""
            lines.append(f"- **{c.id}** — {c.title}{to}")
        lines.append("")

    if dismissed:
        lines.append("## Dismissed\n")
        lines.extend(f"- **{c.id}** — {c.title}: {c.resolution or 'ruled out'}" for c in dismissed)
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_leads(run_dir: Path, candidates: list[Candidate]) -> None:
    """Write ``LEADS.md`` to the run dir (or remove it when there are no candidates)."""
    path = run_dir / "LEADS.md"
    body = render_leads_markdown(candidates)
    if not body:
        path.unlink(missing_ok=True)
        return
    path.write_text(body, encoding="utf-8")
