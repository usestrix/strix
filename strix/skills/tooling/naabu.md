---
name: naabu
description: Naabu port-scanning syntax with host input, scan-type, verification, and rate controls.
---

# Naabu CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/naabu/usage
- https://docs.projectdiscovery.io/opensource/naabu/running
- https://github.com/projectdiscovery/naabu

Canonical syntax:
`naabu [flags]`

High-signal flags:
- `-host <host>` single host
- `-list, -l <file>` hosts list
- `-p <ports>` explicit ports (supports ranges)
- `-top-ports <n|full>` top ports profile
- `-exclude-ports <ports>` exclusions
- `-scan-type <s|c|syn|connect>` SYN or CONNECT scan
- `-Pn` skip host discovery
- `-rate <n>` packets per second
- `-c <n>` worker count
- `-timeout <ms>` per-probe timeout in milliseconds
- `-retries <n>` retry attempts
- `-proxy <socks5://host:port>` SOCKS5 proxy
- `-verify` verify discovered open ports
- `-j, -json` JSONL output
- `-silent` compact output
- `-o <file>` output file

Agent-safe baseline for automation:
`naabu -list hosts.txt -top-ports 100 -scan-type c -Pn -rate 300 -c 25 -timeout 1000 -retries 1 -verify -silent -j -o naabu.jsonl`

Common patterns:
- Top ports with controlled rate:
  `naabu -list hosts.txt -top-ports 100 -scan-type c -rate 300 -c 25 -timeout 1000 -retries 1 -verify -silent -o naabu.txt`
- Focused web-ports sweep:
  `naabu -list hosts.txt -p 80,443,8080,8443 -scan-type c -rate 300 -c 25 -timeout 1000 -retries 1 -verify -silent`
- Single-host quick check:
  `naabu -host target.tld -p 22,80,443 -scan-type c -rate 300 -c 25 -timeout 1000 -retries 1 -verify`
- Root SYN mode (if available):
  `sudo naabu -list hosts.txt -top-ports 100 -scan-type syn -rate 500 -c 25 -timeout 1000 -retries 1 -verify -silent`

Critical correctness rules:
- Use `-scan-type connect` when running without root/privileged raw socket access.
- Always set `-timeout` explicitly; it is in milliseconds.
- Set `-rate` explicitly to avoid unstable or noisy scans.
- `-timeout` is in milliseconds, not seconds.
- Keep port scope tight: prefer explicit important ports or a small `-top-ports` value unless broader coverage is explicitly required.
- Do not spam traffic; start with the smallest useful port set and conservative rate/worker settings.
- Prefer `-verify` before handing ports to follow-up scanners.

Usage rules:
- Keep host discovery behavior explicit (`-Pn` or default discovery).
- Use `-j -o <file>` for automation pipelines.
- Prefer `-p 22,80,443,8080,8443` or `-top-ports 100` before considering larger sweeps.
- Do not use `-h`/`--help` for normal flow unless absolutely necessary.

Failure recovery:
- If privileged socket errors occur, switch to `-scan-type c`.
- If scans are slow or lossy, lower `-rate`, lower `-c`, and tighten `-p`/`-top-ports`.
- If many hosts appear down, compare runs with and without `-Pn`.

If uncertain, query web_search with:
`site:docs.projectdiscovery.io naabu <flag> usage`
