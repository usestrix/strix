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
- `-nf, -no-fallback` probe both HTTP and HTTPS
- `-nfs, -no-fallback-scheme` do not auto-switch schemes
- `-sc` status code
- `-title` page title
- `-server, -web-server` server header
- `-td, -tech-detect` technology detection
- `-fr, -follow-redirects` follow redirects
- `-mc <codes>` / `-fc <codes>` match or filter status codes
- `-path <path_or_file>` probe specific paths
- `-p, -ports <ports>` probe custom ports
- `-proxy, -http-proxy <url>` proxy target requests
- `-tlsi, -tls-impersonate` experimental TLS impersonation
- `-j, -json` JSONL output
- `-sr, -store-response` store request/response artifacts
- `-srd, -store-response-dir <dir>` custom directory for stored artifacts
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
- Proxy-instrumented probing:
  `httpx -l hosts.txt -sc -title -proxy http://127.0.0.1:48080 -silent -j -o httpx_proxy.jsonl`
- Response-storage pass for downstream content parsing:
  `httpx -l hosts.txt -fr -sr -srd recon/httpx_store -sc -title -server -cl -ct -location -probe -silent`

Critical correctness rules:
- For machine parsing, prefer `-j -o <file>`.
- Keep `-rl` and `-t` explicit for reproducible throughput.
- Use `-nf` when you need dual-scheme probing from host-only input.
- When using `-path` or `-ports`, keep scope tight to avoid accidental scan inflation.
- Use `-sr -srd <dir>` when later steps need raw response artifacts (JS/route extraction, grepping, replay).

Usage rules:
- Use `-silent` for pipeline-friendly output.
- Use `-mc/-fc` when downstream steps depend on specific response classes.
- Prefer `-proxy` flag over global proxy env vars when only httpx traffic should be proxied.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- If too many timeouts occur, reduce `-rl/-t` and/or increase `-timeout`.
- If output is noisy, add `-fc` filters or `-fd` duplicate filtering.
- If HTTPS-only probing misses HTTP services, rerun with `-nf` (and avoid `-nfs`).

If uncertain, query web_search with:
`site:docs.projectdiscovery.io httpx <flag> usage`
