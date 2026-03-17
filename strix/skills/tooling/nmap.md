---
name: nmap
description: Canonical Nmap CLI syntax, two-pass scanning workflow, and runtime-bound performance flags.
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
`nmap -n -Pn -sV -sC --open --top-ports 1000 --max-retries 2 --host-timeout 2m -oA nmap_scan <host>`

Common patterns:
- Fast first pass:
  `nmap -n -Pn --top-ports 1000 --open -T4 --max-retries 2 --host-timeout 2m <host>`
- Full TCP port discovery (bounded):
  `nmap -n -Pn -p- -T4 --min-rate 1000 --max-retries 1 --host-timeout 15m <host>`
- Service/script enrichment on discovered ports:
  `nmap -n -Pn -sV -sC -p <comma_ports> --script-timeout 60s -oA nmap_services <host>`
- No-root fallback:
  `nmap -n -Pn -sT --top-ports 1000 --open <host>`

Critical correctness rules:
- Always set target scope explicitly.
- Prefer two-pass scanning: discovery pass, then enrichment pass.
- Bound long scans with `--host-timeout` and sensible retry settings.

Usage rules:
- Add `-n` by default in automation to avoid DNS delays.
- Use `-oA` for reusable artifacts.
- Do not use `-h`/`--help` for routine usage unless absolutely necessary.

Failure recovery:
- If host appears down unexpectedly, rerun with `-Pn`.
- If scan stalls, tighten scope (`--top-ports`) and lower retries.
- If scripts run too long, add `--script-timeout`.

If uncertain, query web_search with:
`site:nmap.org/book nmap <flag>`
