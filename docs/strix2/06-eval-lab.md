# Strix 2 — Evaluation lab (Phase 6)

Honest, repeatable measurement of the scanner: **precision, recall, $-per-finding**, and the two-tier
**candidate recall** (did we at least surface the issue as a lead, even if we didn't validate it?). The
scoring engine lives in `strix/eval/`; this doc describes the *lab* it scores.

## What "honest" means here
- **Recall** is measured against a **ground-truth** set of vulnerabilities that a target is known to contain.
- **Precision** is finding-level: what fraction of filed (validated) findings correspond to a real issue.
- **Candidate recall** credits the lead tier: an issue surfaced as a `create_candidate` lead but not validated
  counts toward recall-of-leads, not toward findings. This keeps the no-false-positive discipline honest —
  we do not inflate precision by filing leads as findings, and we do not hide missed coverage.
- **$-per-finding / $-per-TP** uses the run's actual `llm_usage.cost` from `run.json`.

## Lab layout
```
eval/
  targets/<name>/            # a deliberately-vulnerable target (compose file, app, IaC, or a lab account)
  ground_truth/<name>.yaml   # the expected findings for that target
```
Targets are the user's own authorized labs (e.g. a local juice-shop / DVWA container, a test S3 bucket, a
lab AWS account). Only ever run against targets you are authorized to test — the same rule as any Strix run.

**Committed templates.** `eval/ground_truth/*.example.yaml` ship ready-to-copy ground-truth for two
well-known training apps (OWASP Juice Shop, DVWA) and a cloud-lab shape (public S3 / RDS / EBS snapshot /
KMS / IAM, exercising the AWS wrapper's read-only checks). They are *metadata only* — not targets and not
authorization. Copy one to `eval/ground_truth/<name>.yaml`, point the `target:` values at **your** lab, and
prune to what you actually deployed. `tests/test_strix2_eval_examples.py` keeps them valid + self-scoreable
against the schema. See `eval/README.md`.

## Ground-truth format
A YAML (or JSON) file with a list of expected findings. `id` and `target` are required; the rest refine the
match:

```yaml
ground_truth:
  - id: s3-public-object
    target: "s3://acme-lab-bucket/secret.txt"   # matched on normalized target (scheme/trailing-slash-insensitive)
    title_contains: "public"                      # optional: substring of the finding title/description
    domain: cloud                                 # optional, informational
  - id: orders-idor
    target: "https://api.lab.example.com/v1/orders"
    cwe: "CWE-639"                                # optional: required on a *validated* finding (not on a lead)
```

A **finding** matches a ground-truth entry when the normalized target is equal and every supplied refiner
(`title_contains`, `cwe`) holds. A **candidate/lead** matches on target (+ `title_contains`) only — leads carry
no CWE, so the `cwe` refiner is not applied to them.

## Running the scorer
After a run finishes (its dir holds `vulnerabilities.json`, optionally `candidates.json`, and `run.json`):

```bash
python -m strix.eval strix_runs/<run-name> eval/ground_truth/<name>.yaml        # markdown scorecard
python -m strix.eval strix_runs/<run-name> eval/ground_truth/<name>.yaml --json  # machine-readable
```

Or from Python:

```python
from pathlib import Path
from strix.eval.harness import score_run
card = score_run(Path("strix_runs/<run-name>"), Path("eval/ground_truth/<name>.yaml"))
print(card.precision, card.recall, card.candidate_recall, card.cost_per_true_positive)
```

## Reading the scorecard
`precision` / `recall` / `f1`, `candidate_recall`, `true_positives` / `false_positives` / `false_negatives`,
`cost_usd` / `cost_per_finding` / `cost_per_true_positive`, plus `matched` / `missed` / `unexpected` id lists
so a regression is traceable to specific findings. Track these across model/scope/scan-mode changes to see
whether a change actually improved the scanner rather than just changing its output.
