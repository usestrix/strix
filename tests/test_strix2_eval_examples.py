"""The committed eval ground-truth templates stay valid + scoreable.

These guard the `eval/ground_truth/*.example.yaml` files against drift from the
scoring schema (``id``/``target`` required; targets must normalize + match so a
real run can actually be scored against them).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.eval.harness import load_ground_truth
from strix.eval.metrics import score


_GT_DIR = Path(__file__).resolve().parent.parent / "eval" / "ground_truth"
_EXAMPLES = sorted(_GT_DIR.glob("*.example.yaml"))


def test_examples_exist() -> None:
    assert _EXAMPLES, f"no ground-truth templates found in {_GT_DIR}"


@pytest.mark.parametrize("path", _EXAMPLES, ids=lambda p: p.name)
def test_example_ground_truth_is_valid_and_scoreable(path: Path) -> None:
    entries = load_ground_truth(path)
    assert entries, f"{path.name} parsed to no entries"

    ids = [str(e.get("id", "")) for e in entries]
    assert all(ids), f"{path.name} has an entry missing an id"
    assert len(set(ids)) == len(ids), f"{path.name} has duplicate ids"
    assert all(str(e.get("target", "")).strip() for e in entries), (
        f"{path.name} has an entry missing a target"
    )

    # A synthetic finding per entry (same target + a title/cwe that satisfies the
    # refiners) must score as a perfect run — proves the targets normalize and the
    # refiners are self-consistent, so a real run can be scored against this file.
    findings = [
        {
            "id": f"f{i}",
            "target": entry["target"],
            "title": entry.get("title_contains", ""),
            "description": "",
            "cwe": entry.get("cwe", ""),
        }
        for i, entry in enumerate(entries)
    ]
    card = score(findings=findings, ground_truth=entries)
    assert card.recall == 1.0, f"{path.name}: {card.missed} did not match their own targets"
    assert card.false_positives == 0
