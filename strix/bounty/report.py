"""Write submission-ready bug-bounty artifacts from a run's validated findings.

For a bounty run this reshapes Strix's finding records into a per-program submission
format: one ``bounty/submissions/<id>.md`` per validated finding with a duplicate
check, plus ``program.json`` (the compiled program), ``dedupe.md`` (the known
reports), and a ``README.md`` summarizing scope + rules. It is a no-op outside a
bounty run.

Called at report finalization (so it reflects the final findings) and runnable
standalone as ``python -m strix.bounty.report <run_dir>``.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from strix.bounty.compile import compile_to_scope
from strix.bounty.dedupe import (
    KnownReportsStore,
    get_known_reports,
    load_known_reports_file,
    render_dedupe_md,
    reset_known_reports,
)
from strix.bounty.loaders.fromfile import load_program_file
from strix.bounty.roe import evaluate_roe
from strix.bounty.runtime import BountyContext, get_bounty_context, set_bounty_context


if TYPE_CHECKING:
    from strix.bounty.roe import RoeGate
    from strix.bounty.schema import BountyProgram


logger = logging.getLogger(__name__)

# A finding's CWE is more useful to dedupe as the vuln class it names than as a bare
# "CWE-89", so title overlap can match a disclosed report that spells the class out.
_CWE_VULN_TYPE = {
    "89": "SQL injection",
    "79": "cross-site scripting",
    "918": "server-side request forgery",
    "352": "cross-site request forgery",
    "639": "insecure direct object reference",
    "284": "broken access control",
    "22": "path traversal",
    "78": "OS command injection",
    "94": "code injection",
    "611": "XML external entity",
    "601": "open redirect",
    "287": "authentication bypass",
    "434": "unrestricted file upload",
    "502": "insecure deserialization",
}


def _vuln_type_hint(report: dict[str, Any]) -> str:
    cwe = str(report.get("cwe") or "").strip()
    match = re.search(r"(\d+)", cwe)
    if match and match.group(1) in _CWE_VULN_TYPE:
        return _CWE_VULN_TYPE[match.group(1)]
    return cwe or str(report.get("cve") or "").strip()


def _asset_of(report: dict[str, Any]) -> str:
    return str(report.get("endpoint") or report.get("target") or "").strip()


def render_submission_md(
    report: dict[str, Any],
    program: BountyProgram,
    dedupe: dict[str, Any],
) -> str:
    """Render one finding as a program-ready submission with a duplicate check."""
    title = report.get("title") or "Untitled finding"
    lines: list[str] = [
        f"# {title}",
        "",
        f"- **Program:** {program.platform} / {program.handle}"
        + (f" ({program.url})" if program.url else ""),
        f"- **Asset:** {_asset_of(report) or '—'}",
        f"- **Severity:** {str(report.get('severity', 'unknown')).upper()}"
        + (f" · CVSS {report['cvss']}" if report.get("cvss") else ""),
    ]
    weakness = " / ".join(x for x in (report.get("cwe"), report.get("cve")) if x)
    if weakness:
        lines.append(f"- **Weakness:** {weakness}")
    if report.get("method"):
        lines.append(f"- **Method:** {report['method']}")
    lines.append(f"- **Strix finding id:** {report.get('id', 'unknown')}")
    lines.append("")

    lines += ["## Summary", "", str(report.get("description") or "No description provided."), ""]

    if report.get("poc_description") or report.get("poc_script_code"):
        lines += ["## Steps to reproduce", ""]
        if report.get("poc_description"):
            lines += [str(report["poc_description"]), ""]
        if report.get("poc_script_code"):
            lines += ["```", str(report["poc_script_code"]), "```", ""]

    if report.get("impact"):
        lines += ["## Impact", "", str(report["impact"]), ""]
    if report.get("evidence"):
        lines += ["## Evidence", "", str(report["evidence"]), ""]
    if report.get("remediation_steps"):
        lines += ["## Suggested remediation", "", str(report["remediation_steps"]), ""]

    lines += ["## Duplicate check", ""]
    lines.append(
        f"Verdict: **{dedupe.get('verdict', 'unknown')}** "
        f"(best score {dedupe.get('best_score', 0.0)}; "
        f"checked against {dedupe.get('known_report_count', 0)} disclosed report(s))."
    )
    matches = dedupe.get("matches") or []
    if matches:
        lines.append("")
        lines.append("Closest known reports:")
        for m in matches:
            ref = f" — {m['url']}" if m.get("url") else ""
            lines.append(f"- [{m.get('score')}] {m.get('title')} ({m.get('verdict')}){ref}")
    lines += [
        "",
        "> Before submitting, confirm this is not one of the reports above and add a "
        "one-line note on why it is distinct (different asset, root cause, or impact).",
        "",
    ]
    return "\n".join(lines) + "\n"


def _render_readme(program: BountyProgram, gate: RoeGate, finding_count: int) -> str:
    lines = [
        f"# Bug-bounty engagement — {program.name or program.handle}",
        "",
        f"- **Platform:** {program.platform}",
        f"- **Handle:** {program.handle}" + (f" ({program.url})" if program.url else ""),
        f"- **Mode:** {gate.mode} (active tools: {gate.active_tools_allowed})",
        f"- **Validated findings:** {finding_count}",
        "",
        "## Rules of engagement (obeyed this run)",
        "",
    ]
    lines.extend(f"- {c}" for c in gate.constraints)
    lines += [
        "",
        "## Files",
        "",
        "- `program.json` — the compiled program (scope + rules).",
        "- `dedupe.md` — the known/disclosed reports checked against.",
        "- `submissions/` — one submission-ready write-up per validated finding.",
        "",
        "Review each submission (especially its duplicate check) before sending it to "
        "the program. You are the accountable submitter.",
        "",
    ]
    return "\n".join(lines) + "\n"


def write_bounty_artifacts(
    run_dir: Path,
    vulnerability_reports: list[dict[str, Any]],
    *,
    program: BountyProgram | None = None,
    gate: RoeGate | None = None,
    known: KnownReportsStore | None = None,
) -> bool:
    """Write the bounty artifact set for a run. No-op (returns False) outside bounty mode.

    Uses the active run context by default; explicit ``program`` / ``gate`` / ``known``
    override it (used by the standalone entry point).
    """
    context = get_bounty_context()
    program = program or (context.program if context else None)
    if program is None:
        return False
    gate = gate or (context.gate if context else None) or evaluate_roe(program)
    known = known or get_known_reports() or KnownReportsStore([])

    bounty_dir = run_dir / "bounty"
    submissions_dir = bounty_dir / "submissions"
    submissions_dir.mkdir(parents=True, exist_ok=True)

    (bounty_dir / "program.json").write_text(
        program.model_dump_json(indent=2), encoding="utf-8"
    )
    (bounty_dir / "dedupe.md").write_text(render_dedupe_md(known.reports), encoding="utf-8")

    index = ["# Submissions", ""]
    for report in vulnerability_reports:
        dedupe = known.check(
            title=str(report.get("title") or ""),
            asset=_asset_of(report) or None,
            vuln_type=_vuln_type_hint(report) or None,
        )
        report_id = str(report.get("id") or "finding")
        (submissions_dir / f"{report_id}.md").write_text(
            render_submission_md(report, program, dedupe), encoding="utf-8"
        )
        index.append(
            f"- `{report_id}.md` — {report.get('title', 'Untitled')} "
            f"[{dedupe.get('verdict')}]"
        )
    if len(index) == 2:
        index.append("_No validated findings yet._")
    (submissions_dir / "INDEX.md").write_text("\n".join(index) + "\n", encoding="utf-8")

    (bounty_dir / "README.md").write_text(
        _render_readme(program, gate, len(vulnerability_reports)), encoding="utf-8"
    )
    logger.info("Bounty artifacts written to %s", bounty_dir)
    return True


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write bounty submission artifacts for a run.")
    parser.add_argument("run_dir", help="Path to the strix_runs/<run> directory.")
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir).expanduser()
    program_path = run_dir / "bounty" / "program.json"
    if not program_path.is_file():
        parser.error(f"no bounty/program.json in {run_dir}; was this a bounty run?")
    program = load_program_file(program_path)

    known_path = run_dir / "bounty" / "known_reports.json"
    known = (
        KnownReportsStore(load_known_reports_file(known_path)) if known_path.is_file() else None
    )
    if known is not None:
        reset_known_reports(known.reports)
    set_bounty_context(
        BountyContext(
            program=program,
            gate=evaluate_roe(program),
            compiled=compile_to_scope(program),
        )
    )

    vulns_path = run_dir / "vulnerabilities.json"
    reports: list[dict[str, Any]] = []
    if vulns_path.is_file():
        loaded = json.loads(vulns_path.read_text(encoding="utf-8"))
        reports = loaded if isinstance(loaded, list) else loaded.get("vulnerabilities", [])
    write_bounty_artifacts(run_dir, reports, known=known)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
