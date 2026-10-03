"""Pure scoring for a Strix run against a ground-truth set.

Ground truth is a list of expected findings, each a dict:
``{"id": "s3-public", "target": "s3://bucket", "title_contains": "public", "cwe": "CWE-284"}``
(``id`` and ``target`` required; ``title_contains``/``cwe``/``domain`` optional match
refiners). A finding/candidate matches an entry when its normalized target equals the
entry's and every supplied refiner is satisfied.

Metrics are intentionally simple and honest: finding-level precision, GT-level
recall, and the two-tier candidate recall (surfaced as a lead even if not validated).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from strix.candidates.schema import normalize_target


def _matches(record: dict[str, Any], gt: dict[str, Any], *, check_cwe: bool = True) -> bool:
    """Whether a finding/candidate record satisfies a ground-truth entry.

    ``check_cwe`` is disabled for candidate (lead) matching: a lead is the low-bar
    tier and carries no CWE, so the CWE refiner only applies to validated findings.
    """
    if normalize_target(str(record.get("target", ""))) != normalize_target(
        str(gt.get("target", ""))
    ):
        return False
    needle = str(gt.get("title_contains", "")).strip().lower()
    if needle:
        haystack = f"{record.get('title', '')} {record.get('description', '')}".lower()
        if needle not in haystack:
            return False
    if check_cwe:
        want_cwe = str(gt.get("cwe", "")).strip().lower()
        if want_cwe and want_cwe not in str(record.get("cwe", "")).strip().lower():
            return False
    return True


def _gt_id(gt: dict[str, Any]) -> str:
    return str(gt.get("id") or gt.get("target") or "")


@dataclass(frozen=True)
class Scorecard:
    """Result of scoring findings/candidates against ground truth."""

    total_expected: int
    findings_count: int
    candidates_count: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    candidate_recall: float
    cost_usd: float
    cost_per_finding: float
    cost_per_true_positive: float
    matched: list[str]
    missed: list[str]
    unexpected: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _ratio(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def score(
    *,
    findings: list[dict[str, Any]],
    ground_truth: list[dict[str, Any]],
    candidates: list[dict[str, Any]] | None = None,
    cost_usd: float = 0.0,
) -> Scorecard:
    """Score validated findings (+ optional candidates) against ground truth."""
    candidates = candidates or []
    total = len(ground_truth)

    matched_gt: list[str] = []
    surfaced_gt: set[str] = set()  # matched by a finding OR a candidate (two-tier recall)
    for gt in ground_truth:
        gid = _gt_id(gt)
        if any(_matches(f, gt) for f in findings):
            matched_gt.append(gid)
            surfaced_gt.add(gid)
        elif any(_matches(c, gt, check_cwe=False) for c in candidates):
            surfaced_gt.add(gid)

    true_finding_ids = {
        str(f.get("id"))
        for f in findings
        if any(_matches(f, gt) for gt in ground_truth)
    }
    unexpected = [str(f.get("id")) for f in findings if str(f.get("id")) not in true_finding_ids]

    findings_count = len(findings)
    tp = len(matched_gt)
    fp = len(unexpected)
    fn = total - tp
    precision = _ratio(len(true_finding_ids), findings_count)
    recall = _ratio(tp, total)
    f1 = _ratio(2 * precision * recall, precision + recall)
    matched_set = set(matched_gt)

    return Scorecard(
        total_expected=total,
        findings_count=findings_count,
        candidates_count=len(candidates),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        candidate_recall=_ratio(len(surfaced_gt), total),
        cost_usd=round(cost_usd, 4),
        cost_per_finding=_ratio(cost_usd, findings_count),
        cost_per_true_positive=_ratio(cost_usd, tp),
        matched=matched_gt,
        missed=[_gt_id(gt) for gt in ground_truth if _gt_id(gt) not in matched_set],
        unexpected=unexpected,
    )


def render_scorecard_markdown(card: Scorecard, *, title: str = "Eval scorecard") -> str:
    """Render a scorecard as a compact markdown report."""
    lines = [
        f"# {title}",
        "",
        f"- **Precision**: {card.precision:.0%} "
        f"({len(card.matched)}/{card.findings_count} findings hit ground truth)",
        f"- **Recall**: {card.recall:.0%} "
        f"({card.true_positives}/{card.total_expected} expected found)",
        f"- **F1**: {card.f1:.0%}",
        f"- **Candidate recall**: {card.candidate_recall:.0%} (surfaced as lead or finding)",
        f"- **TP/FP/FN**: {card.true_positives} / {card.false_positives} / {card.false_negatives}",
        f"- **Cost**: ${card.cost_usd:.2f} total · ${card.cost_per_finding:.2f}/finding · "
        f"${card.cost_per_true_positive:.2f}/TP",
        "",
        f"**Missed**: {', '.join(card.missed) or 'none'}",
        f"**Unexpected**: {', '.join(card.unexpected) or 'none'}",
        "",
    ]
    return "\n".join(lines)
