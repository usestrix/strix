---
name: dirsearch
description: Dirsearch content-discovery CLI structure, wordlist/extension selection, rate controls, and automation-safe output patterns
---

# Dirsearch CLI Playbook

Official docs:
- https://github.com/maurosoria/dirsearch

Dirsearch is a threaded HTTP content-discovery scanner: it brute-forces directories and files on a target with a wordlist and reports status-code-differentiated results. It is pre-installed in the sandbox via pipx.

Canonical syntax:
`dirsearch [flags]`

High-signal flags:
- `-u, --url <url>` single target (or `-l <file>` for a list of targets)
- `-w <wordlist>` custom wordlist (default `db/dicc.txt`; use Seclists/dirb lists for depth)
- `-e <extensions>` comma-separated extensions to append (`php,html,txt,bak,old,env`)
- `-t <threads>` thread count
- `--max-rate <n>` global request rate cap
- `-r` recursive brute force into discovered directories
- `-R <depth>` max recursion depth
- `-x <status>` exclude status codes (e.g. `-x 404,403`)
- `-i <status>` include only specific status codes
- `-q` quiet mode (results only)
- `--format=json -o <file>` structured output for automation
- `--header <h>` / `--cookie <c>` auth or custom headers
- `--random-agent` rotate user agents
- `--timeout <s>` request timeout
- `--proxy <url>` route through a proxy (or caido)
- `-H, --header` alternative header syntax; `--user-agent` fixed UA

Agent-safe baseline:
```
dirsearch -u https://target -e php,html,txt,bak,old,env,json -t 20 --max-rate 50 \
  -x 404,403 -q --format=json -o dirsearch.json
```

Common patterns:
- Shallow quick sweep:
  `dirsearch -u https://target -e php,txt -t 20 --max-rate 50 -x 404 -q --format=json -o quick.json`
- Recursive deep discovery:
  `dirsearch -u https://target -e php,bak,old,env -r -R 3 -t 30 --max-rate 100 -x 404 -q --format=json -o deep.json`
- Authenticated scan:
  `dirsearch -u https://target -e json -t 10 --max-rate 30 --cookie "session=..." -x 404 -q`
- Extension-focused backup hunt:
  `dirsearch -u https://target -e bak,old,swp,sav,orig,dist,env,sql -t 20 -x 404 -q`

These examples intentionally use dirsearch's bundled `db/dicc.txt` default so they
run in the shipped sandbox. If a larger API or raft wordlist has been provisioned,
pass its verified absolute path with `-w`; do not assume that a named wordlist is
installed.

Critical correctness rules:
- Always exclude the baseline noise (`-x 404`, and consider `403` unless you intend to test bypasses)
- Keep `-t` and `--max-rate` explicit and moderate (20 threads / 50-100 rps is a sane ceiling for most targets)
- Use JSON output (`--format=json -o <file>`) for automation and reporting
- Use `-r/-R` deliberately: recursion multiplies requests exponentially
- For APIs/JS-heavy apps, prefer `api`/`raft` wordlists over generic dirb lists

Usage rules:
- Run passive recon (robots, sitemap, JS mining) before brute force so the wordlist targets real paths
- Verify results by fetching each hit; filter soft-200s (SPAs return 200 for everything) by body size/content
- Do not run unbounded recursion or default thread counts on production targets

Failure recovery:
- All 403/429: you are being rate-limited or WAF-blocked - lower `--max-rate`, add `--random-agent`, or route through the proxy
- Soft-200 flood: filter with `-x` or by content-length at the parsing stage
- Slow scans: reduce wordlist size, disable recursion, raise threads only if the target tolerates it

If uncertain, query web_search with:
`dirsearch flags documentation recursive extensions`

## Pairing

- Results feed `content_discovery` methodology
- 403 hits -> access-control bypass testing (see `content_discovery`)
- Config/backup hits -> `information_disclosure`, `source_aware_sast`, `dependency_cve_scanning`
