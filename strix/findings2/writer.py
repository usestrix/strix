"""Render finding annotations to ``FRAMEWORK_MAP.md`` beside the run's reports."""

from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

    from strix.findings2.schema import FindingAnnotation


def render_framework_map(annotations: Iterable[FindingAnnotation]) -> str:
    """Render the framework/domain mapping table as markdown."""
    rows = list(annotations)
    lines = ["# Framework & domain mapping", ""]
    if not rows:
        lines.append("_No finding annotations recorded._")
        return "\n".join(lines) + "\n"
    lines.append("Optional ATT&CK / CIS / domain metadata for validated findings (never a gate).")
    lines.append("")
    lines.append("| Finding | Domain | MITRE ATT&CK | CIS | Evidence notes |")
    lines.append("|---|---|---|---|---|")
    for ann in rows:
        mitre = ", ".join(ann.mitre_attack) or "—"
        cis = ", ".join(ann.cis_benchmark) or "—"
        notes = (ann.notes or "—").replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {ann.vuln_report_id} | {ann.domain or '—'} | {mitre} | {cis} | {notes} |"
        )
    return "\n".join(lines) + "\n"


def write_framework_map(run_dir: Path, annotations: Iterable[FindingAnnotation]) -> None:
    """Write ``FRAMEWORK_MAP.md`` into the run directory."""
    (run_dir / "FRAMEWORK_MAP.md").write_text(render_framework_map(annotations), encoding="utf-8")
