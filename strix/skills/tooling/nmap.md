---
name: nmap
description: Canonical Nmap CLI syntax, two-pass scanning workflow, and sandbox-safe bounded scan patterns.
---

# Nmap CLI Playbook

Official docs:
- https://nmap.org/book/man-briefoptions.html
- https://nmap.org/book/man.html
- https://nmap.org/book/man-performance.html

Canonical syntax:
`nmap [Scan Type(s)] [Options] {target specification}`

High-signal flags:
- `-n` skip DNS resolution
- `-Pn` skip host discovery when ICMP/ping is filtered
- `-sS` SYN scan (root/privileged)
- `-sT` TCP connect scan (no raw-socket privilege)
- `-sV` detect service versions
- `-sC` run default NSE scripts
- `-p <ports>` explicit ports (`-p-` for all TCP ports)
- `--top-ports <n>` quick common-port sweep
- `--open` show only hosts with open ports
- `-T<0-5>` timing template (`-T4` common)
- `--max-retries <n>` cap retransmissions
- `--host-timeout <time>` give up on very slow hosts
- `--script-timeout <time>` bound NSE script runtime
- `-oA <prefix>` output in normal/XML/grepable formats

Agent-safe baseline for automation:
`nmap -n -Pn --open --top-ports 100 -T4 --max-retries 1 --host-timeout 90s -oA nmap_quick <host>`

Common patterns:
- Fast first pass:
  `nmap -n -Pn --top-ports 100 --open -T4 --max-retries 1 --host-timeout 90s <host>`
- Very small important-port pass:
  `nmap -n -Pn -p 22,80,443,8080,8443 --open -T4 --max-retries 1 --host-timeout 90s <host>`
- Service/script enrichment on discovered ports:
  `nmap -n -Pn -sV -sC -p <comma_ports> --script-timeout 30s --host-timeout 3m -oA nmap_services <host>`
- No-root fallback:
  `nmap -n -Pn -sT --top-ports 100 --open --host-timeout 90s <host>`

Critical correctness rules:
- Always set target scope explicitly.
- Prefer two-pass scanning: discovery pass, then enrichment pass.
- Always set a timeout boundary with `--host-timeout`; add `--script-timeout` whenever NSE scripts are involved.
- Keep discovery scans tight: use explicit important ports or a small `--top-ports` profile unless broader coverage is explicitly required.
- In sandboxed runs, avoid exhaustive sweeps (`-p-`, very high `--top-ports`, or wide host ranges) unless explicitly required.
- Do not spam traffic; start with the smallest port set that can answer the question.
- Prefer `naabu` for broad port discovery; use `nmap` for scoped verification/enrichment.

Usage rules:
- Add `-n` by default in automation to avoid DNS delays.
- Use `-oA` for reusable artifacts.
- Prefer `-p 22,80,443,8080,8443` or `--top-ports 100` before considering larger sweeps.
- Do not use `-h`/`--help` for routine usage unless absolutely necessary.

Failure recovery:
- If host appears down unexpectedly, rerun with `-Pn`.
- If scan stalls, tighten scope (`-p` or smaller `--top-ports`) and lower retries.
- If scripts run too long, add `--script-timeout`.

If uncertain, query web_search with:
`site:nmap.org/book nmap <flag>`
