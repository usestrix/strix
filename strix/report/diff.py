"""Compare findings between two completed Strix runs."""

from __future__ import annotations

import json
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast
from urllib.parse import urlsplit, urlunsplit

from strix.core.paths import RUNS_DIR_NAME, run_dir_for, run_record_path
from strix.report.sarif import _build_physical_locations, _weakness_id, fingerprints_for_finding
from strix.report.writer import read_run_record


if TYPE_CHECKING:
    from collections.abc import Callable


MatchMode = Literal["strict", "class"]

_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class DiffError(ValueError):
    """A run could not be resolved or its artifacts could not be read."""


@dataclass(frozen=True)
class FindingSnapshot:
    """One finding as loaded from ``vulnerabilities.json`` plus SARIF identity."""

    id: str
    title: str
    severity: str
    location: str
    primary: str | None
    class_hash: str | None
    move_key: str | None = None


@dataclass(frozen=True)
class DiffFinding:
    """A finding as it appears in a diff section (new / fixed / still present)."""

    title: str
    location: str
    severity: str
    id_baseline: str | None
    id_current: str | None
    severity_baseline: str | None
    severity_current: str | None
    location_baseline: str | None
    location_current: str | None

    def to_json(self) -> dict[str, Any]:
        return {
            "id_baseline": self.id_baseline,
            "id_current": self.id_current,
            "location": self.location,
            "location_baseline": self.location_baseline,
            "location_current": self.location_current,
            "severity": self.severity,
            "severity_baseline": self.severity_baseline,
            "severity_current": self.severity_current,
            "title": self.title,
        }


@dataclass(frozen=True)
class RunMeta:
    name: str
    path: str
    started_at: str
    ended_at: str
    scan_mode: str
    targets: list[str]
    status: str
    raw_targets: list[str] = field(compare=False, repr=False)

    @property
    def completed(self) -> bool:
        return self.status.strip().lower() == "completed"

    def to_json(self) -> dict[str, Any]:
        return {
            "ended_at": self.ended_at,
            "name": self.name,
            "path": self.path,
            "scan_mode": self.scan_mode,
            "started_at": self.started_at,
            "status": self.status,
            "targets": list(self.targets),
        }


@dataclass(frozen=True)
class RunDiff:
    baseline: RunMeta
    current: RunMeta
    match: MatchMode
    warnings: list[str]
    new: list[DiffFinding]
    fixed: list[DiffFinding]
    still_present: list[DiffFinding]
    not_rechecked: list[DiffFinding]

    @property
    def severity_changed(self) -> int:
        return sum(
            1
            for finding in self.still_present
            if finding.severity_baseline != finding.severity_current
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "baseline": self.baseline.to_json(),
            "current": self.current.to_json(),
            "fixed": [finding.to_json() for finding in self.fixed],
            "match": self.match,
            "new": [finding.to_json() for finding in self.new],
            "not_rechecked": [finding.to_json() for finding in self.not_rechecked],
            "still_present": [finding.to_json() for finding in self.still_present],
            "summary": {
                "fixed": len(self.fixed),
                "new": len(self.new),
                "not_rechecked": len(self.not_rechecked),
                "severity_changed": self.severity_changed,
                "still_present": len(self.still_present),
            },
            "warnings": list(self.warnings),
        }


def resolve_run_spec(spec: str, *, cwd: Path | None = None) -> Path:
    """Resolve a run name under ``./strix_runs`` or a path to a run directory."""
    base = cwd or Path.cwd()
    expanded = Path(spec).expanduser()
    if _looks_like_path(spec, expanded):
        candidate = expanded if expanded.is_absolute() else (base / expanded)
        if run_record_path(candidate).is_file():
            return candidate
        message = f"No run directory at {spec}."
        raise DiffError(message)

    named = run_dir_for(spec, cwd=base)
    if run_record_path(named).is_file():
        return named

    relative = base / spec
    if run_record_path(relative).is_file():
        return relative

    message = f"No run named '{spec}' under ./{RUNS_DIR_NAME}."
    raise DiffError(message)


def load_run(run_dir: Path) -> tuple[RunMeta, list[FindingSnapshot]]:
    """Load ``run.json`` + ``vulnerabilities.json`` from a run directory.

    A completed scan with no findings does not write ``vulnerabilities.json``;
    that absence is an empty report, not an error.
    """
    if not run_record_path(run_dir).is_file():
        message = f"No run directory at {run_dir}."
        raise DiffError(message)
    try:
        record = read_run_record(run_dir)
    except (RuntimeError, TypeError) as exc:
        raise DiffError(str(exc)) from exc

    findings_path = run_dir / "vulnerabilities.json"
    if not findings_path.is_file():
        return _meta(run_dir, record), []
    try:
        raw = json.loads(findings_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        message = f"vulnerabilities.json at {findings_path} is unreadable: {exc}"
        raise DiffError(message) from exc
    items = _finding_objects(raw, findings_path)

    findings = [_snapshot(item) for item in items]
    return _meta(run_dir, record), findings


def compare_runs(
    baseline_dir: Path,
    current_dir: Path,
    *,
    match: MatchMode = "strict",
) -> RunDiff:
    """Classify findings in *current_dir* relative to *baseline_dir*."""
    baseline_meta, baseline_findings = load_run(baseline_dir)
    current_meta, current_findings = load_run(current_dir)
    new, unmatched_baseline, still_present = match_findings(
        baseline_findings,
        current_findings,
        match=match,
    )
    # A running or interrupted re-test may already have saved one finding
    # while others have not been checked. Those absences are unknown, not fixes.
    if current_meta.completed:
        fixed = unmatched_baseline
        not_rechecked: list[DiffFinding] = []
    else:
        fixed = []
        not_rechecked = unmatched_baseline
    return RunDiff(
        baseline=baseline_meta,
        current=current_meta,
        match=match,
        warnings=_warnings(baseline_meta, current_meta),
        new=_sort_findings(new),
        fixed=_sort_findings(fixed),
        still_present=_sort_findings(still_present),
        not_rechecked=_sort_findings(not_rechecked),
    )


def match_findings(
    baseline: list[FindingSnapshot],
    current: list[FindingSnapshot],
    *,
    match: MatchMode,
) -> tuple[list[DiffFinding], list[DiffFinding], list[DiffFinding]]:
    """Group findings by strict or class identity and pair the best matches.

    Strict mode pairs within each primary fingerprint group by normalized title
    or location, then pairs unique line-only moves by weakness (or normalized
    title) and first code file. Other findings remain unmatched.
    Class mode tries primary fingerprint, normalized title, then location within
    each class group, and pairs a lone remaining finding on each side.
    """
    baseline_groups = _group(baseline, match)
    current_groups = _group(current, match)
    unmatched_baseline: list[FindingSnapshot] = []
    unmatched_current: list[FindingSnapshot] = []
    still_present: list[DiffFinding] = []
    for key in sorted(set(baseline_groups) | set(current_groups)):
        left = baseline_groups.get(key, [])
        right = current_groups.get(key, [])
        pairs, unmatched_left, unmatched_right = _pair_group(left, right, match)
        still_present.extend(_still(before, after) for before, after in pairs)
        unmatched_baseline.extend(unmatched_left)
        unmatched_current.extend(unmatched_right)

    moves: dict[str, FindingSnapshot] = {}
    if match == "strict":
        baseline_counts = Counter(item.move_key for item in unmatched_baseline)
        current_counts = Counter(item.move_key for item in unmatched_current)
        moves = {
            move_key: item
            for item in unmatched_baseline
            if (move_key := item.move_key) is not None
            and baseline_counts[move_key] == current_counts[move_key] == 1
        }
        still_present.extend(
            _still(moves[move_key], item)
            for item in unmatched_current
            if (move_key := item.move_key) is not None and move_key in moves
        )
    new = [_new(item) for item in unmatched_current if item.move_key not in moves]
    fixed = [_fixed(item) for item in unmatched_baseline if item.move_key not in moves]
    return new, fixed, still_present


def _looks_like_path(spec: str, expanded: Path) -> bool:
    if expanded.is_absolute():
        return True
    return spec.startswith(("~", ".", "/", "\\")) or "/" in spec or "\\" in spec


def _snapshot(report: dict[str, Any]) -> FindingSnapshot:
    fingerprints = fingerprints_for_finding(report)
    locations, _ = _build_physical_locations(report.get("code_locations"))
    title = str(report.get("title") or "Untitled")
    move_key = None
    if locations:
        uri = locations[0]["physicalLocation"]["artifactLocation"]["uri"]
        move_key = json.dumps([_weakness_id(report) or _normalized_title(title), uri])
    return FindingSnapshot(
        id=str(report.get("id") or ""),
        title=title,
        severity=str(report.get("severity") or "").strip().lower() or "unknown",
        location=_location(report),
        primary=fingerprints.primary,
        class_hash=fingerprints.vuln_class,
        move_key=move_key,
    )


def _finding_objects(value: object, findings_path: Path) -> list[dict[str, Any]]:
    """Return the top-level findings list, or raise if the document is damaged."""
    if not isinstance(value, list):
        message = f"vulnerabilities.json at {findings_path} is not a list"
        raise DiffError(message)
    findings: list[dict[str, Any]] = []
    for index, item in enumerate(cast("list[object]", value)):
        if not isinstance(item, dict):
            message = (
                f"vulnerabilities.json at {findings_path} contains a non-object "
                f"entry at index {index}"
            )
            raise DiffError(message)
        findings.append(cast("dict[str, Any]", item))
    return findings


def _json_objects(value: object) -> list[dict[str, Any]] | None:
    if not isinstance(value, list):
        return None
    return [
        cast("dict[str, Any]", item)
        for item in cast("list[object]", value)
        if isinstance(item, dict)
    ]


def _location(report: dict[str, Any]) -> str:
    locations = _json_objects(report.get("code_locations"))
    if locations:
        for location in locations:
            file_path = location.get("file")
            if not isinstance(file_path, str) or not file_path:
                continue
            line = location.get("start_line")
            if type(line) is int and line >= 1:
                return f"{file_path}:{line}"
            return file_path
    endpoint = str(report.get("endpoint") or "").strip()
    method = str(report.get("method") or "").strip()
    if endpoint and method:
        return f"{method} {endpoint}"
    if endpoint:
        return endpoint
    target = str(report.get("target") or "").strip()
    return target or "-"


def _meta(run_dir: Path, record: dict[str, Any]) -> RunMeta:
    raw_targets = _target_originals(record)
    return RunMeta(
        name=str(record.get("run_name") or run_dir.name),
        path=str(run_dir),
        started_at=str(record.get("start_time") or ""),
        ended_at=str(record.get("end_time") or ""),
        scan_mode=str(record.get("scan_mode") or "").strip(),
        targets=[_redact_target(target) for target in raw_targets],
        status=str(record.get("status") or ""),
        raw_targets=raw_targets,
    )


def _redact_target(value: str) -> str:
    try:
        parts = urlsplit(value)
        if not parts.scheme or not parts.netloc or parts.password is None:
            return value
        _, _, host = parts.netloc.rpartition("@")
        return urlunsplit(parts._replace(netloc=f"{parts.username}:***@{host}"))
    except ValueError:
        return value


def _target_originals(record: dict[str, Any]) -> list[str]:
    targets = _json_objects(record.get("targets_info"))
    if not targets:
        return []
    return [str(entry["original"]) for entry in targets if entry.get("original")]


def _identity_key(finding: FindingSnapshot, match: MatchMode) -> str:
    if match == "class" and finding.class_hash:
        return f"class:{finding.class_hash}"
    if finding.primary:
        return f"primary:{finding.primary}"
    return "unanchored"


def _group(
    findings: list[FindingSnapshot],
    match: MatchMode,
) -> dict[str, list[FindingSnapshot]]:
    groups: dict[str, list[FindingSnapshot]] = {}
    for finding in findings:
        groups.setdefault(_identity_key(finding, match), []).append(finding)
    return groups


def _normalized_title(title: str) -> str:
    return " ".join(title.split()).casefold()


def _pair_group(
    left: list[FindingSnapshot],
    right: list[FindingSnapshot],
    match: MatchMode,
) -> tuple[
    list[tuple[FindingSnapshot, FindingSnapshot]],
    list[FindingSnapshot],
    list[FindingSnapshot],
]:
    def sort_key(item: FindingSnapshot) -> tuple[str, str, str, str, str]:
        return item.primary or "", item.title, item.location, item.severity, item.id

    left = sorted(left, key=sort_key)
    right = sorted(right, key=sort_key)
    pairs: list[tuple[FindingSnapshot, FindingSnapshot]] = []
    tiers: list[Callable[[FindingSnapshot], str | None]] = [
        lambda item: _normalized_title(item.title),
        lambda item: item.location if item.location != "-" else None,
    ]
    if match == "class":
        tiers.insert(0, lambda item: item.primary)
    for tier_key in tiers:
        candidates: dict[str, deque[int]] = {}
        for index, item in enumerate(right):
            key = tier_key(item)
            if key is not None:
                candidates.setdefault(key, deque()).append(index)

        unmatched_left: list[FindingSnapshot] = []
        matched_right: set[int] = set()
        for item in left:
            key = tier_key(item)
            matches = candidates.get(key) if key is not None else None
            if matches:
                index = matches.popleft()
                pairs.append((item, right[index]))
                matched_right.add(index)
            else:
                unmatched_left.append(item)
        left = unmatched_left
        right = [item for index, item in enumerate(right) if index not in matched_right]

    if match == "class" and len(left) == len(right) == 1:
        pairs.append((left[0], right[0]))
        return pairs, [], []
    return pairs, left, right


def _new(finding: FindingSnapshot) -> DiffFinding:
    return DiffFinding(
        title=finding.title,
        location=finding.location,
        severity=finding.severity,
        id_baseline=None,
        id_current=finding.id,
        severity_baseline=None,
        severity_current=finding.severity,
        location_baseline=None,
        location_current=finding.location,
    )


def _fixed(finding: FindingSnapshot) -> DiffFinding:
    return DiffFinding(
        title=finding.title,
        location=finding.location,
        severity=finding.severity,
        id_baseline=finding.id,
        id_current=None,
        severity_baseline=finding.severity,
        severity_current=None,
        location_baseline=finding.location,
        location_current=None,
    )


def _still(baseline: FindingSnapshot, current: FindingSnapshot) -> DiffFinding:
    return DiffFinding(
        title=current.title,
        location=current.location,
        severity=current.severity,
        id_baseline=baseline.id,
        id_current=current.id,
        severity_baseline=baseline.severity,
        severity_current=current.severity,
        location_baseline=baseline.location,
        location_current=current.location,
    )


def _sort_findings(findings: list[DiffFinding]) -> list[DiffFinding]:
    return sorted(
        findings,
        key=lambda item: (
            _SEVERITY_RANK.get(item.severity, len(_SEVERITY_RANK)),
            item.title.lower(),
            item.location.lower(),
            item.id_current or item.id_baseline or "",
        ),
    )


def _warnings(baseline: RunMeta, current: RunMeta) -> list[str]:
    warnings: list[str] = []
    if not current.completed:
        status = current.status or "unknown"
        warnings.append(
            f"run '{current.name}' is not completed (status: {status}); "
            "findings missing from this run are not re-checked, not fixed"
        )
    if not baseline.completed:
        status = baseline.status or "unknown"
        warnings.append(f"run '{baseline.name}' is not completed (status: {status})")
    if set(baseline.raw_targets) != set(current.raw_targets):
        warnings.append(
            "targets differ "
            f"({_format_targets(baseline.targets)} vs {_format_targets(current.targets)})"
        )
    if baseline.scan_mode != current.scan_mode:
        warnings.append(
            "scan modes differ "
            f"({baseline.scan_mode or 'unknown'} vs {current.scan_mode or 'unknown'})"
        )
    return warnings


def _format_targets(targets: list[str]) -> str:
    if not targets:
        return "none"
    if len(targets) == 1:
        return targets[0]
    return f"{targets[0]} +{len(targets) - 1} more"


def dumps_diff(diff: RunDiff) -> str:
    """Stable JSON document for ``--json``."""
    return json.dumps(diff.to_json(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
