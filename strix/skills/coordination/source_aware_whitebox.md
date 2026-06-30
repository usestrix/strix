---
name: source-aware-whitebox
description: Coordination playbook for source-aware white-box testing with static triage and dynamic validation
---

# Source-Aware White-Box Coordination

Use this coordination playbook when repository source code is available.

## Objective

Increase white-box coverage by combining source-aware triage with dynamic validation. Source-aware tooling is expected by default when source is available.

## Recommended Workflow

1. Build a quick source map before deep exploitation, including at least one AST-structural pass (`sg` or `tree-sitter`) scoped to relevant paths.
   - For `sg` baseline, derive `sg-targets.txt` from `semgrep.json` scope first (`paths.scanned`, fallback to unique `results[].path`) and run `xargs ... sg run` on that list.
   - Only fall back to path heuristics when semgrep scope is unavailable.
2. Run first-pass static triage to rank high-risk paths.
3. Use triage outputs to prioritize dynamic PoC validation.
4. Keep findings evidence-driven: report on a clear, traceable source-to-sink
   flow with a concrete PoC payload; add dynamic validation when the environment
   allows, but do not gate reporting on it.

## Source-Aware Triage Stack

- `semgrep`: fast security-first triage and custom pattern scans
- `ast-grep` (`sg`): structural pattern hunting and targeted repo mapping
- `tree-sitter`: syntax-aware parsing support for symbol and route extraction
- `gitleaks` + `trufflehog`: complementary secret detection (working tree and history coverage)
- `trivy fs`: dependency, misconfiguration, license, and secret checks

Coverage target per repository:
- one `semgrep` pass
- one AST structural pass (`sg` and/or `tree-sitter`)
- one secrets pass (`gitleaks` and/or `trufflehog`)
- one `trivy fs` pass

## Agent Delegation Guidance

- Keep child agents specialized by vulnerability/component as usual.
- For source-heavy subtasks, prefer creating child agents with `source_aware_sast` skill.
- Use source findings to shape payloads and endpoint selection for dynamic testing.

## Validation Guardrails

- A finding is reportable on strong, traceable source evidence (a clear
  source-to-sink data flow, or a missing/incorrect authorization check) plus a
  concrete PoC payload in the report.
- Dynamic exploitation evidence strengthens a finding and is preferred when the
  environment is available — but do NOT withhold a well-evidenced source-level
  finding solely because dynamic execution was not possible.
- State confidence explicitly: source-confirmed vs dynamically-confirmed.
- Keep scanner output concise, deduplicated, and mapped to concrete code locations.
