---
name: opengrep
description: Exact Opengrep CLI structure, bundled offline rules, scoped rule selection, taint mode, and automation-safe output patterns.
---

# Opengrep CLI Playbook

Official docs:
- https://github.com/opengrep/opengrep
- https://github.com/opengrep/opengrep-rules

Canonical syntax:
`opengrep scan [flags] [targets]`

Bundled rules:
- `/opt/opengrep-rules` holds the full ruleset, one directory per language (`python`, `javascript`, `typescript`, `go`, `java`, `php`, `ruby`, …) plus `generic/secrets`, `dockerfile`, `terraform`, `yaml`, and `strix` (Strix-authored rules, e.g. GitHub-owned actions not pinned to a commit SHA)
- Framework rules sit under the language (`python/django`, `python/flask`, `javascript/express`, …)

High-signal flags:
- `--config <path>` rule file or directory; repeat for several
- `--taint-intrafile` intra-file inter-procedural taint (follows data across functions in one file)
- `--json` / `--sarif` output format
- `--output <file>` write findings to file
- `--severity <level>` filter by severity (`INFO`, `WARNING`, `ERROR`)
- `--error` return non-zero exit when findings exist
- `--quiet` suppress progress noise
- `--jobs <n>` parallel workers
- `--timeout <seconds>` per-rule, per-file timeout
- `--exclude <pattern>` / `--include <pattern>` path filters
- `--exclude-rule <rule_id>` suppress specific rule
- `--baseline-commit <sha>` only report findings introduced after baseline

Agent-safe baseline for automation:
`opengrep scan --config /opt/opengrep-rules --taint-intrafile --json --output opengrep.json --quiet --jobs 4 --timeout 20 /workspace`

Common patterns:
- Full bundled scan:
  `opengrep scan --config /opt/opengrep-rules --json --output opengrep.json --quiet /workspace`
- High-severity focused pass:
  `opengrep scan --config /opt/opengrep-rules --severity ERROR --json --output opengrep_high.json --quiet /workspace`
- SARIF output:
  `opengrep scan --config /opt/opengrep-rules --sarif --output opengrep.sarif --quiet /workspace`
- Language- or framework-specific rules:
  `opengrep scan --config /opt/opengrep-rules/python --config /opt/opengrep-rules/generic/secrets --json --output opengrep_python.json --quiet /workspace`
- Scoped directory scan:
  `opengrep scan --config /opt/opengrep-rules --json --output opengrep_api.json --quiet /workspace/services/api`
- Custom rule:
  `opengrep scan --config ./rules/my-rule.yaml --json --output opengrep_custom.json --quiet /workspace`

Critical correctness rules:
- Always provide an explicit `--config` from `/opt/opengrep-rules` or a local rule file. Registry shorthands (`p/...`, `auto`) fetch rules from the network; do not use them.
- Opengrep has no telemetry; there is no `--metrics` flag, and passing one fails the scan.
- Prefer `--json --output <file>` or `--sarif --output <file>` for machine-readable downstream processing. JSON keeps `paths.scanned` and `results[].path`.
- Keep the target path explicit; use an absolute or clearly scoped workspace path instead of `.` when possible.

Usage rules:
- Start with the full `/opt/opengrep-rules` set unless the task clearly calls for a narrower language or framework directory.
- Add `--taint-intrafile` for injection-class hunting (SQLi, command injection, SSRF, path traversal) in supported languages.
- Use `--quiet` in automation to reduce noisy logs.
- Use `--jobs` and `--timeout` explicitly for reproducible runtime behavior.
- `PartialParsing` errors on templates are normal; they do not invalidate the run.

Failure recovery:
- If scans are too slow, narrow the target path and the rule directories before changing engine settings.
- If scans time out, increase `--timeout` modestly or lower `--jobs`.
- If output is too broad, scope `--config`, add `--severity`, or exclude known irrelevant paths.

If uncertain, query web_search with:
`site:github.com/opengrep/opengrep <flag>`
