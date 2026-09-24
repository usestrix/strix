---
name: dirsearch
description: dirsearch path/content enumeration syntax with status/size filtering, recursion, and non-interactive structured output.
---

# dirsearch CLI Playbook

Official docs:
- https://github.com/maurosoria/dirsearch

dirsearch is a mature path/content brute-forcer that ships with curated
wordlists, sane defaults, extension tagging, and built-in recursion. Reach
for it first for a broad directory/file sweep with no setup; reach for
`ffuf` when you need surgical fuzzing of a specific input position (header,
body, vhost) or precise matcher/filter control.

Canonical syntax:
`dirsearch -u <url> -e <extensions> [flags]`

High-signal flags:
- `-u <url>` / `-l <file>` single target URL / list of targets
- `-e <ext,ext>` extensions to append (e.g. `php,html,js,json,txt,bak`); `-f` force extensions on every word
- `-w <wordlist>` custom wordlist (defaults to the bundled `db/dicts.txt`)
- `-x <codes>` / `--exclude-status <codes>` exclude status codes (e.g. `404,500-599`)
- `-i <codes>` / `--include-status <codes>` include only these status codes
- `--exclude-sizes <sizes>` drop responses of a given size (e.g. `0B,123B`)
- `--exclude-text <str>` / `--exclude-regex <re>` drop soft-404 bodies
- `-r` recursive discovery; `-R <n>` / `--max-recursion-depth <n>` cap depth; `--recursion-status <codes>`
- `-t <n>` threads; `--max-rate <n>` requests/sec cap; `-s <sec>` / `--delay <sec>` per-request delay
- `--timeout <sec>` request timeout; `--retries <n>`
- `-H <header>` custom header (repeatable); `--cookie <c>`; `--user-agent <ua>`; `--random-agent`
- `-m <METHOD>` HTTP method; `-d <data>` request body
- `--proxy <url>` upstream proxy (HTTP/SOCKS); `--proxy-auth`
- `--full-url` print absolute URLs in output
- `-q` / `--quiet-mode` suppress the banner/progress noise
- `-o <file>` output path; `--output-formats <simple|plain|json|xml|md|csv|html|sqlite>` structured report
- `--crawl` parse discovered pages for more paths

Agent-safe baseline for automation:
`dirsearch -u https://target.tld/ -e php,html,js,json,txt --exclude-status 404 --max-rate 50 -t 20 --timeout 10 -q --output-formats json -o dirsearch.json`

Common patterns:
- Basic content discovery:
  `dirsearch -u https://target.tld/ -e php,html,js,json,txt,bak,old --exclude-status 404 -t 30 -q`
- Recursive sweep with bounded depth:
  `dirsearch -u https://target.tld/ -e php,json -r -R 2 --recursion-status 200-399 --exclude-status 404 -t 20 -q`
- Include-only interesting codes (auth-gated / redirects):
  `dirsearch -u https://target.tld/ -e php,json -i 200,204,301,302,401,403 -t 20 -q`
- Strip soft-404 noise by size:
  `dirsearch -u https://target.tld/ -e html --exclude-status 404 --exclude-sizes 0B,1256B -t 20 -q`
- Authenticated enumeration:
  `dirsearch -u https://target.tld/ -e php,json -H 'Authorization: Bearer <token>' --cookie 'session=<v>' --exclude-status 404 -t 15 -q`
- Proxy-instrumented run (route through the Strix proxy):
  `dirsearch -u https://target.tld/ -e php,json --proxy http://127.0.0.1:48080 --exclude-status 404 -t 10 -q`
- Multiple targets from a file:
  `dirsearch -l targets.txt -e php,json --exclude-status 404 -t 20 -q --output-formats json -o dirsearch.json`

Critical correctness rules:
- Always constrain results with `--exclude-status 404` (or `-i` allow-list) — the default output is noisy and soft-404 sites need `--exclude-sizes`/`--exclude-text` on top.
- Save structured output with `--output-formats json -o <file>` for deterministic parsing; parse that file rather than scraping stdout.
- Bound every run: keep `-t`/`--max-rate` conservative to start, cap `-R` recursion depth, and set `--timeout` so a slow target cannot stall the sandbox.
- `-e` only *appends* extensions; use `-f` to force them onto every wordlist entry when the server hides real names behind extensions.

Usage rules:
- Prefer a targeted `-e` extension set matched to the detected tech stack over a kitchen-sink list.
- Start with the bundled wordlist; switch to a focused custom `-w` (e.g. tech-specific list) only when the default under-covers.
- Feed confirmed paths into `create_note` (endpoint inventory) and `record_coverage` (surface + outcome) so other agents build on the map instead of re-enumerating.

Failure recovery:
- If output is dominated by soft-404s, add `--exclude-sizes`/`--exclude-text`/`--exclude-regex` instead of raising thread count.
- If the run is too slow, lower `-t`/`--max-rate`, tighten `-e`, and cap `-R` recursion depth.
- If the target rate-limits or blocks, add `-s <delay>`, `--random-agent`, and route through `--proxy`.

If uncertain, query web_search with:
`site:github.com/maurosoria/dirsearch <flag> README`

Alternate tool for surgical fuzzing: `ffuf -w <wordlist> -u https://target.tld/FUZZ`.
Reach for `ffuf` when you need to mutate a precise input position (header,
body, vhost) or want fine-grained `-mc/-fc/-fs` matcher control; reach for
`dirsearch` for a fast, low-setup broad path/content sweep.
