"""Tests for the Strix 2 Phase 6 eval scoring engine + harness."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from strix.eval.harness import score_run
from strix.eval.metrics import render_scorecard_markdown, score


if TYPE_CHECKING:
    from pathlib import Path


def _finding(fid: str, target: str, title: str = "", cwe: str = "") -> dict[str, Any]:
    return {"id": fid, "target": target, "title": title, "description": "", "cwe": cwe}


_GT = [
    {"id": "s3-public", "target": "s3://bucket/secret", "title_contains": "public"},
    {"id": "idor", "target": "https://api.example.com/v1/orders", "cwe": "CWE-639"},
]


# --- metrics -----------------------------------------------------------------

def test_perfect_score() -> None:
    findings = [
        _finding("v1", "s3://bucket/secret", "Public S3 object readable"),
        _finding("v2", "https://api.example.com/v1/orders", "IDOR", "CWE-639"),
    ]
    card = score(findings=findings, ground_truth=_GT, cost_usd=4.0)
    assert card.true_positives == 2
    assert card.false_positives == 0
    assert card.false_negatives == 0
    assert card.precision == 1.0
    assert card.recall == 1.0
    assert card.f1 == 1.0
    assert card.cost_per_true_positive == 2.0


def test_false_positive_lowers_precision() -> None:
    findings = [
        _finding("v1", "s3://bucket/secret", "Public S3 object"),
        _finding("v2", "https://unrelated.test/x", "Something else"),
    ]
    card = score(findings=findings, ground_truth=_GT, cost_usd=2.0)
    assert card.true_positives == 1
    assert card.false_positives == 1
    assert card.precision == 0.5
    assert card.recall == 0.5
    assert "v2" in card.unexpected
    assert "idor" in card.missed


def test_candidate_recall_credits_surfaced_leads() -> None:
    findings = [_finding("v1", "s3://bucket/secret", "Public S3 object")]
    candidates = [{"id": "cand-1", "target": "https://api.example.com/v1/orders", "title": "IDOR?"}]
    card = score(findings=findings, ground_truth=_GT, candidates=candidates, cost_usd=1.0)
    assert card.recall == 0.5  # only 1 of 2 validated
    assert card.candidate_recall == 1.0  # both surfaced (one as a lead)


def test_cwe_and_title_refiners_must_match() -> None:
    # right target, wrong cwe -> no match
    findings = [_finding("v2", "https://api.example.com/v1/orders", "IDOR", "CWE-79")]
    card = score(findings=findings, ground_truth=_GT)
    assert card.true_positives == 0
    assert "idor" in card.missed


def test_render_markdown_has_key_metrics() -> None:
    card = score(findings=[_finding("v1", "s3://bucket/secret", "public")], ground_truth=_GT)
    out = render_scorecard_markdown(card)
    assert "Precision" in out
    assert "Recall" in out
    assert "Candidate recall" in out


# --- harness -----------------------------------------------------------------

def test_score_run_reads_run_dir(tmp_path: Path) -> None:
    (tmp_path / "vulnerabilities.json").write_text(
        json.dumps([_finding("v1", "s3://bucket/secret", "Public S3 object readable")]),
        encoding="utf-8",
    )
    lead = {"id": "cand-1", "target": "https://api.example.com/v1/orders", "title": "IDOR?"}
    (tmp_path / "candidates.json").write_text(json.dumps([lead]), encoding="utf-8")
    (tmp_path / "run.json").write_text(json.dumps({"llm_usage": {"cost": 3.0}}), encoding="utf-8")
    gt = tmp_path / "ground_truth.yaml"
    gt.write_text(json.dumps({"ground_truth": _GT}), encoding="utf-8")  # JSON is valid YAML

    card = score_run(tmp_path, gt)
    assert card.findings_count == 1
    assert card.candidates_count == 1
    assert card.true_positives == 1
    assert card.recall == 0.5
    assert card.candidate_recall == 1.0
    assert card.cost_usd == 3.0
    assert card.cost_per_finding == 3.0


def test_score_run_missing_files_is_empty(tmp_path: Path) -> None:
    gt = tmp_path / "gt.yaml"
    gt.write_text(json.dumps({"ground_truth": _GT}), encoding="utf-8")
    card = score_run(tmp_path, gt)  # no vulnerabilities.json / run.json
    assert card.findings_count == 0
    assert card.recall == 0.0
    assert card.false_negatives == 2
