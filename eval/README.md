# Strix 2 — evaluation lab

Targets + ground-truth for measuring the scanner honestly (precision / recall / $-per-finding /
candidate recall). The scoring engine is `strix/eval/`; the methodology is
`docs/strix2/06-eval-lab.md`. This directory holds the lab it scores.

```
eval/
  targets/<name>/            # a deliberately-vulnerable target you host and are authorized to test
  ground_truth/<name>.yaml   # the expected findings for that target
```

## Authorization

**Only ever scan a target you are authorized to test** — the same rule as any Strix run. The
ground-truth files here are metadata (expected-finding lists), not targets and not attack tooling.
Nothing in this repo stands up a target or points a scan at a third party. You bring the target
(a local container, a test bucket, a lab cloud account) and you own the authorization for it.

## Ground-truth files

The `*.example.yaml` files are **templates** for well-known, intentionally-vulnerable training apps
and a cloud lab shape. They are not wired to any live host: copy one to `ground_truth/<name>.yaml`,
set the `target:` values to **your** authorized lab's URLs/ARNs, and prune or extend the entries to
match the build you actually stood up (versions differ in which issues are present).

Format (see the methodology doc for the full contract):

```yaml
ground_truth:
  - id: short-stable-id          # required
    target: "http://host/path"   # required; matched scheme/trailing-slash-insensitive
    title_contains: "substring"  # optional: substring of the finding title/description
    cwe: "CWE-89"                # optional: applied to a *validated* finding, not a lead
    domain: web                  # optional, informational (web|api|network|cloud|infra)
```

## Scoring a run

```bash
python -m strix.eval strix_runs/<run-name> eval/ground_truth/<name>.yaml         # markdown
python -m strix.eval strix_runs/<run-name> eval/ground_truth/<name>.yaml --json  # machine-readable
```

Track precision / recall / candidate-recall / $-per-TP across model, scope, and scan-mode changes to
see whether a change actually improved the scanner rather than just changing its output.
