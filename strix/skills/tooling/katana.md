---
name: katana
description: Katana crawler syntax, depth/js/known-files behavior, and stable concurrency controls.
---

# Katana CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/katana/usage
- https://docs.projectdiscovery.io/opensource/katana/running
- https://github.com/projectdiscovery/katana

Canonical syntax:
`katana [flags]`

High-signal flags:
- `-u, -list <url|file>` target URL(s)
- `-d, -depth <n>` crawl depth
- `-jc, -js-crawl` parse JavaScript-discovered endpoints
- `-jsl, -jsluice` deeper JS parsing (memory intensive)
- `-kf, -known-files <all|robotstxt|sitemapxml>` known-file crawling mode
- `-c, -concurrency <n>` concurrent fetchers
- `-p, -parallelism <n>` concurrent input targets
- `-rl, -rate-limit <n>` request rate limit
- `-timeout <seconds>` request timeout
- `-retry <n>` retry count
- `-ef, -extension-filter <list>` extension exclusions
- `-silent`, `-j, -jsonl`, `-o <file>` output controls

Agent-safe baseline for automation:
`katana -u https://target.tld -d 3 -jc -kf robotstxt -c 10 -p 10 -rl 50 -timeout 10 -retry 1 -ef png,jpg,jpeg,gif,svg,css,woff,woff2,ttf,eot,map -silent -j -o katana.jsonl`

Common patterns:
- Fast crawl baseline:
  `katana -u https://target.tld -d 3 -jc -silent`
- Deeper JS-aware crawl:
  `katana -u https://target.tld -d 5 -jc -jsl -kf all -c 10 -p 10 -rl 50 -o katana_urls.txt`
- Multi-target run with JSONL output:
  `katana -list urls.txt -d 3 -jc -silent -j -o katana.jsonl`

Critical correctness rules:
- `-kf` must be followed by one of `all`, `robotstxt`, or `sitemapxml`.
- Never pass another flag as the value for `-kf` (for example `-kf -c` is invalid).

Usage rules:
- Keep `-d`, `-c`, `-p`, and `-rl` explicit for reproducible runs.
- Use `-ef` early to reduce static-file noise before fuzzing.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- If crawl runs too long, lower `-d` and optionally add `-ct`.
- If memory spikes, disable `-jsl` and lower `-c/-p`.
- If output is noisy, tighten scope and add `-ef` filters.

If uncertain, query web_search with:
`site:docs.projectdiscovery.io katana <flag> usage`
