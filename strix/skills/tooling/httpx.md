---
name: httpx
description: ProjectDiscovery httpx probing syntax, exact probe flags, and automation-safe output patterns.
---

# httpx CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/httpx/usage
- https://docs.projectdiscovery.io/opensource/httpx/running
- https://github.com/projectdiscovery/httpx

Canonical syntax:
`httpx [flags]`

High-signal flags:
- `-u, -target <url>` single target
- `-l, -list <file>` target list
- `-sc` status code
- `-title` page title
- `-server, -web-server` server header
- `-td, -tech-detect` technology detection
- `-fr, -follow-redirects` follow redirects
- `-mc <codes>` / `-fc <codes>` match or filter status codes
- `-path <path_or_file>` probe specific paths
- `-p, -ports <ports>` probe custom ports
- `-j, -json` JSONL output
- `-silent` compact output
- `-rl <n>` requests/second cap
- `-t <n>` threads
- `-timeout <seconds>` request timeout
- `-retries <n>` retry attempts
- `-o <file>` output file

Agent-safe baseline for automation:
`httpx -l hosts.txt -sc -title -server -td -fr -timeout 10 -retries 1 -rl 50 -t 25 -silent -j -o httpx.jsonl`

Common patterns:
- Quick live+fingerprint check:
  `httpx -l hosts.txt -sc -title -server -td -silent -o httpx.txt`
- Probe known admin paths:
  `httpx -l hosts.txt -path /,/login,/admin -sc -title -silent -j -o httpx_paths.jsonl`
- Probe both schemes explicitly:
  `httpx -l hosts.txt -nf -sc -title -silent`
- Vhost detection pass:
  `httpx -l hosts.txt -vhost -sc -title -silent -j -o httpx_vhost.jsonl`

Critical correctness rules:
- For machine parsing, prefer `-j -o <file>`.
- Keep `-rl` and `-t` explicit for reproducible throughput.
- When using `-path` or `-ports`, keep scope tight to avoid accidental scan inflation.

Usage rules:
- Use `-silent` for pipeline-friendly output.
- Use `-mc/-fc` when downstream steps depend on specific response classes.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- If too many timeouts occur, reduce `-rl/-t` and/or increase `-timeout`.
- If output is noisy, add `-fc` filters or `-fd` duplicate filtering.
- If HTTPS-only probing misses HTTP services, rerun with `-nf`.

If uncertain, query web_search with:
`site:docs.projectdiscovery.io httpx <flag> usage`
