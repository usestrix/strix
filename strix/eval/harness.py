"""Score a completed run directory against a ground-truth file.

Reads ``vulnerabilities.json`` (findings), ``candidates.json`` (leads, optional) and
``run.json`` (LLM cost) from a run directory, plus a YAML/JSON ground-truth file, and
produces a :class:`~strix.eval.metrics.Scorecard`. Usable as a library
(:func:`score_run`) or a CLI (``python -m strix.eval <run_dir> <ground_truth.yaml>``).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

from strix.eval.metrics import Scorecard, render_scorecard_markdown, score


def _load_structured(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        return yaml.safe_load(text)
    return json.loads(text)


def _as_record_list(data: Any, *keys: str) -> list[dict[str, Any]]:
    """Coerce a loaded document to a list of record dicts.

    Accepts a bare list, or an object wrapping the list under one of ``keys``.
    """
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def load_findings(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "vulnerabilities.json"
    if not path.exists():
        return []
    return _as_record_list(_load_structured(path), "vulnerabilities", "reports", "findings")


def load_candidates(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "candidates.json"
    if not path.exists():
        return []
    return _as_record_list(_load_structured(path), "candidates")


def load_cost(run_dir: Path) -> float:
    path = run_dir / "run.json"
    if not path.exists():
        return 0.0
    data = _load_structured(path)
    if not isinstance(data, dict):
        return 0.0
    usage = data.get("llm_usage")
    if isinstance(usage, dict):
        try:
            return float(usage.get("cost", 0.0) or 0.0)
        except (TypeError, ValueError):
            return 0.0
    return 0.0


def load_ground_truth(path: Path) -> list[dict[str, Any]]:
    return _as_record_list(_load_structured(path), "ground_truth", "expected", "findings")


def score_run(run_dir: Path, ground_truth_path: Path) -> Scorecard:
    """Load a run directory + ground-truth file and return the scorecard."""
    return score(
        findings=load_findings(run_dir),
        candidates=load_candidates(run_dir),
        ground_truth=load_ground_truth(ground_truth_path),
        cost_usd=load_cost(run_dir),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="strix.eval", description="Score a run vs ground truth.")
    parser.add_argument("run_dir", type=Path, help="Run dir (with vulnerabilities.json etc.)")
    parser.add_argument("ground_truth", type=Path, help="Ground-truth YAML/JSON file")
    parser.add_argument("--json", action="store_true", help="Emit the scorecard as JSON")
    args = parser.parse_args(argv)

    if not args.run_dir.is_dir():
        sys.stderr.write(f"run_dir not found: {args.run_dir}\n")
        return 2
    if not args.ground_truth.is_file():
        sys.stderr.write(f"ground_truth not found: {args.ground_truth}\n")
        return 2

    card = score_run(args.run_dir, args.ground_truth)
    if args.json:
        sys.stdout.write(json.dumps(card.to_dict(), indent=2) + "\n")
    else:
        sys.stdout.write(render_scorecard_markdown(card, title=f"Eval: {args.run_dir.name}"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
