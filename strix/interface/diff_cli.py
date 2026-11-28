"""``strix diff RUN-A RUN-B`` — compare findings between two completed runs."""

from __future__ import annotations

import argparse
import sys
from typing import cast

from rich.console import Console

from strix.core.paths import RUNS_DIR_NAME, run_record_path, runs_base_dir
from strix.interface.cli_args import FAIL_ON_SEVERITIES, severity_meets_fail_on
from strix.interface.terminal_text import sanitize_terminal_text
from strix.report.diff import (
    DiffError,
    DiffFinding,
    MatchMode,
    RunDiff,
    RunMeta,
    compare_runs,
    dumps_diff,
    resolve_run_spec,
)


def run_diff(argv: list[str]) -> int:
    """Entry point for ``strix diff …``. Returns a process exit code."""
    parser = argparse.ArgumentParser(
        prog="strix diff",
        description=(
            "Compare findings between two Strix runs: what is new, what was fixed, "
            "and what is still present (including severity changes)."
        ),
    )
    parser.add_argument(
        "run_a",
        metavar="RUN-A",
        help=f"Baseline run name under ./{RUNS_DIR_NAME}, or a path to a run directory.",
    )
    parser.add_argument(
        "run_b",
        metavar="RUN-B",
        help=f"Current run name under ./{RUNS_DIR_NAME}, or a path to a run directory.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print a stable JSON document instead of the human summary.",
    )
    parser.add_argument(
        "--fail-on-new",
        dest="fail_on_new",
        type=str.lower,
        choices=FAIL_ON_SEVERITIES,
        default=None,
        metavar="SEVERITY",
        help=(
            "Exit 1 when a new finding is at or above this severity or a still-present "
            "finding escalates to it or higher (critical, high, medium, low, info). "
            "Unrecognized severities always count."
        ),
    )
    parser.add_argument(
        "--match",
        choices=("strict", "class"),
        default="strict",
        help=(
            "Finding identity. 'strict' (default) uses the SARIF primary fingerprint "
            "(location + rule). 'class' uses the file-independent class fingerprint, "
            "so a finding whose file path moved still matches."
        ),
    )
    args = parser.parse_args(argv)
    console = Console()
    err = Console(stderr=True, soft_wrap=True)

    try:
        baseline_dir = resolve_run_spec(args.run_a)
        current_dir = resolve_run_spec(args.run_b)
        diff = compare_runs(
            baseline_dir,
            current_dir,
            match=cast("MatchMode", args.match),
        )
    except DiffError as exc:
        _print_plain(err, f"strix: error: {exc}")
        if str(exc).startswith("No run named"):
            _print_available_runs(err)
        return 1

    if args.json:
        sys.stdout.write(dumps_diff(diff))
    else:
        _print_human(console, diff)

    # A comparison is only complete when both runs completed. An unfinished
    # baseline may be missing findings, so its "new" list cannot gate a job.
    if not (diff.baseline.completed and diff.current.completed):
        return 1
    # A narrower re-test never looked for some baseline findings, so it cannot
    # pass a regression gate.
    if args.fail_on_new and diff.scope_narrowed:
        return 1
    if args.fail_on_new and _new_findings_fail(diff, args.fail_on_new):
        return 1
    return 0


def _new_findings_fail(diff: RunDiff, threshold: str) -> bool:
    return any(severity_meets_fail_on(finding.severity, threshold) for finding in diff.new) or any(
        _escalated_past(finding, threshold) for finding in diff.still_present
    )


def _is_ranked(severity: object) -> bool:
    return str(severity or "").strip().lower() in FAIL_ON_SEVERITIES


def _escalated_past(finding: DiffFinding, threshold: str) -> bool:
    """Whether a still-present finding crossed the threshold since the baseline.

    A change between a ranked and an unrankable label counts as crossing, so
    ``unknown -> critical`` and ``high -> severe`` fail the gate. Two
    unrankable labels stay unchanged.
    """
    if not severity_meets_fail_on(finding.severity_current, threshold):
        return False
    baseline = finding.severity_baseline
    if baseline is None or not severity_meets_fail_on(baseline, threshold):
        return True
    return _is_ranked(baseline) != _is_ranked(finding.severity_current)


def _print_plain(console: Console, text: str) -> None:
    console.print(sanitize_terminal_text(text), markup=False, highlight=False)


def _print_human(console: Console, diff: RunDiff) -> None:
    console.print()
    _print_plain(console, f"Comparing {diff.baseline.name} -> {diff.current.name}")
    _print_run_line(console, diff.baseline)
    _print_run_line(console, diff.current)
    console.print()

    for warning in diff.warnings:
        _print_plain(console, f"Warning: {warning}")
    if diff.warnings:
        console.print()

    _print_section(console, "New", diff.new, kind="new")
    _print_section(console, "Fixed", diff.fixed, kind="fixed")
    _print_section(console, "Still present", diff.still_present, kind="still")
    if diff.not_rechecked:
        _print_section(console, "Not re-checked", diff.not_rechecked, kind="fixed")
    if diff.withdrawn:
        _print_section(console, "Withdrawn as false positive", diff.withdrawn, kind="fixed")

    _print_plain(console, _summary_line(diff))
    console.print()


def _summary_line(diff: RunDiff) -> str:
    parts = [
        f"{len(diff.new)} new",
        f"{len(diff.fixed)} fixed",
        f"{len(diff.still_present)} still present",
    ]
    if diff.not_rechecked:
        parts.append(f"{len(diff.not_rechecked)} not re-checked")
    if diff.withdrawn:
        parts.append(f"{len(diff.withdrawn)} withdrawn")
    return ", ".join(parts)


def _print_run_line(console: Console, meta: RunMeta) -> None:
    started = meta.started_at or "-"
    scan_mode = meta.scan_mode or "-"
    target_text = ", ".join(meta.targets) if meta.targets else "-"
    _print_plain(console, f"  {meta.name}  {started}  {scan_mode}  {target_text}")


def _print_section(
    console: Console,
    title: str,
    findings: list[DiffFinding],
    *,
    kind: str,
) -> None:
    _print_plain(console, f"{title} ({len(findings)})")
    if not findings:
        console.print()
        return
    for finding in findings:
        _print_plain(console, _finding_line(finding, kind=kind))
    console.print()


def _finding_line(finding: DiffFinding, *, kind: str) -> str:
    severity = sanitize_terminal_text(_severity_label(finding, kind=kind))
    location = sanitize_terminal_text(_location_label(finding))
    finding_id = sanitize_terminal_text(_id_label(finding))
    title = sanitize_terminal_text(finding.title)
    return f"  {severity}  {title}  {location}  {finding_id}"


def _severity_label(finding: DiffFinding, *, kind: str) -> str:
    if (
        kind == "still"
        and finding.severity_baseline
        and finding.severity_current
        and finding.severity_baseline != finding.severity_current
    ):
        return f"{finding.severity_baseline} -> {finding.severity_current}"
    return finding.severity


def _location_label(finding: DiffFinding) -> str:
    baseline = finding.location_baseline
    current = finding.location_current
    if baseline and current and baseline != current:
        return f"{baseline} -> {current}"
    return finding.location


def _id_label(finding: DiffFinding) -> str:
    baseline = finding.id_baseline
    current = finding.id_current
    if baseline and current:
        if baseline == current:
            return baseline
        return f"{baseline} -> {current}"
    return current or baseline or "-"


def _print_available_runs(console: Console) -> None:
    base = runs_base_dir()
    available = (
        sorted(
            (child.name for child in base.iterdir() if run_record_path(child).is_file()),
            reverse=True,
        )
        if base.is_dir()
        else []
    )
    if not available:
        return
    _print_plain(console, "Available runs:")
    for name in available[:20]:
        _print_plain(console, f"  {name}")
