"""Strix 2 Phase 6 — honest multi-domain evaluation.

Score a run against a ground-truth set of expected findings: precision, recall,
$-per-finding, and the two-tier **candidate recall** (did we at least surface the
issue as a lead?). Pure metric functions (:mod:`strix.eval.metrics`) plus a thin
harness (:mod:`strix.eval.harness`) that reads a run directory + a ground-truth file
and prints a scorecard. The eval *lab* (target apps + ground-truth files) is
documented in ``docs/strix2/06-eval-lab.md``; this package is the scoring engine.
"""

from strix.eval.metrics import Scorecard, render_scorecard_markdown, score


__all__ = ["Scorecard", "render_scorecard_markdown", "score"]
