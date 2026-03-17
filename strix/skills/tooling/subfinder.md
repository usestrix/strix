---
name: subfinder
description: Subfinder passive subdomain enumeration syntax, source controls, and pipeline-ready output patterns.
---

# Subfinder CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/subfinder/usage
- https://docs.projectdiscovery.io/opensource/subfinder/running
- https://github.com/projectdiscovery/subfinder

Canonical syntax:
`subfinder [flags]`

High-signal flags:
- `-d <domain>` single domain
- `-dL <file>` domain list
- `-all` include all sources
- `-recursive` use recursive-capable sources
- `-s <sources>` include specific sources
- `-es <sources>` exclude specific sources
- `-rl <n>` global rate limit
- `-rls <source=n/s,...>` per-source rate limits
- `-proxy <http://host:port>` proxy outbound source requests
- `-silent` compact output
- `-o <file>` output file
- `-oJ, -json` JSONL output
- `-cs, -collect-sources` include source metadata (`-oJ` output)
- `-nW, -active` show only active subdomains
- `-timeout <seconds>` request timeout
- `-max-time <minutes>` overall enumeration cap

Agent-safe baseline for automation:
`subfinder -d example.com -all -recursive -rl 20 -timeout 30 -silent -oJ -o subfinder.jsonl`

Common patterns:
- Standard passive enum:
  `subfinder -d example.com -silent -o subs.txt`
- Broad-source passive enum:
  `subfinder -d example.com -all -recursive -silent -o subs_all.txt`
- Multi-domain run:
  `subfinder -dL domains.txt -all -recursive -rl 20 -silent -o subfinder_out.txt`
- Source-attributed JSONL output:
  `subfinder -d example.com -all -oJ -cs -o subfinder_sources.jsonl`
- Passive enum via explicit proxy:
  `subfinder -d example.com -all -recursive -proxy http://127.0.0.1:48080 -silent -oJ -o subfinder_proxy.jsonl`

Critical correctness rules:
- `-cs` is useful only with JSON output (`-oJ`).
- Many sources require API keys in provider config; low results can be config-related, not target-related.
- `-nW` performs active resolution/filtering and can drop passive-only hits.
- Keep passive enum first, then validate with `httpx`.

Usage rules:
- Keep output files explicit when chaining to `httpx`/`nuclei`.
- Use `-rl/-rls` when providers throttle aggressively.
- Do not use `-h`/`--help` for routine tasks unless absolutely necessary.

Failure recovery:
- If results are unexpectedly low, rerun with `-all` and verify provider config/API keys.
- If provider errors appear, lower `-rl` and apply `-rls` per source.
- If runs take too long, lower scope or split domain batches.

If uncertain, query web_search with:
`site:docs.projectdiscovery.io subfinder <flag> usage`
