---
name: subfinder
description: subfinder passive subdomain enumeration, source configuration, API key setup, output filtering, and pipeline integration
---

# subfinder

subfinder is a passive subdomain discovery tool that aggregates results from 50+ sources (certificate transparency logs, DNS datasets, search engines, passive DNS databases, and threat intelligence APIs). It discovers subdomains without sending probes to the target -- all queries go to third-party data sources. Run it first in a recon pipeline before httpx and nuclei to build a complete attack surface inventory. Only use against authorized targets within the defined scope.

## Core Usage

### Basic enumeration

```bash
subfinder -d example.com
```

### Multiple domains

```bash
subfinder -d example.com -d api.example.com
```

### From a file

```bash
subfinder -dL domains.txt -o subdomains.txt
```

### Silent output (subdomains only, no banner)

```bash
subfinder -d example.com -silent
```

## Key Flags Reference

| Flag | Purpose |
|------|---------|
| `-d <domain>` | Target domain (repeatable for multiple) |
| `-dL <file>` | File containing domains (one per line) |
| `-s <sources>` | Use specific sources only (e.g. `-s crtsh,github`) |
| `-es <sources>` | Exclude specific sources |
| `-ls` / `-list-sources` | List all available sources |
| `-all` | Use all sources including slow ones |
| `-recursive` | Use only recursively-capable sources |
| `-active` / `-nW` | Show only verified live subdomains |
| `-ip` / `-oI` | Resolve and include IP addresses (active mode) |
| `-m <pattern>` | Include only matching subdomains |
| `-f <pattern>` | Exclude matching subdomains |
| `-o <file>` | Output to file |
| `-oJ` / `-json` | JSONL output format |
| `-cs` / `-collect-sources` | Include source attribution in JSON |
| `-r <resolvers>` | Custom DNS resolvers (comma-separated) |
| `-rL <file>` | File containing resolver IPs |
| `-rl <n>` | HTTP requests per second rate limit |
| `-t <n>` | Concurrent goroutines (default: 10, active mode only) |
| `-timeout <n>` | Request timeout in seconds (default: 30) |
| `-max-time <n>` | Total enumeration time limit in minutes (default: 10) |
| `-proxy <url>` | HTTP proxy (e.g. `http://127.0.0.1:8080`) |
| `-silent` | Subdomains-only output (no banner/stats) |
| `-v` | Verbose mode |
| `-nc` / `-no-color` | Disable colored output |
| `-duc` | Disable update check |

## Sources

### List available sources

```bash
subfinder -ls
```

Key free sources (no API key required):
- `crtsh` -- Certificate Transparency logs (most reliable, always use)
- `hackertarget` -- DNS lookup API
- `dnsdumpster` -- DNS map data
- `waybackarchive` -- Wayback Machine subdomains
- `threatminer` -- Threat intelligence

Sources requiring API keys (significantly expand coverage):
- `github` -- GitHub code search (often reveals internal subdomains)
- `shodan` -- Shodan host data
- `censys` -- Censys certificate data
- `virustotal` -- VirusTotal passive DNS
- `binaryedge` -- BinaryEdge scans
- `securitytrails` -- SecurityTrails DNS history

### API key configuration

API keys are stored in `~/.config/subfinder/provider-config.yaml`:

```yaml
github:
  - ghp_your_github_token
shodan:
  - your_shodan_api_key
virustotal:
  - your_vt_api_key
censys:
  - your_censys_api_id:your_censys_api_secret
```

```bash
# Verify which sources are active
subfinder -ls -v

# Use only high-quality sources with keys
subfinder -d example.com -s crtsh,github,shodan,virustotal
```

## Output Formats

### Plain text (default)

```
api.example.com
mail.example.com
dev.example.com
```

### JSONL output

```bash
subfinder -d example.com -oJ -o results.jsonl
```

```json
{"host":"api.example.com","input":"example.com","source":"crtsh"}
{"host":"mail.example.com","input":"example.com","source":"hackertarget"}
```

### JSONL with source attribution

```bash
subfinder -d example.com -oJ -cs -o results.jsonl
```

### Parse JSONL output

```python
import json

with open("results.jsonl") as f:
    for line in f:
        entry = json.loads(line)
        print(f"{entry['host']} (source: {entry.get('source', 'unknown')})")
```

## Recommended Scan Sequences

### Standard passive enumeration

```bash
subfinder -d example.com \
  -silent \
  -o subdomains.txt
```

### All sources (thorough, slower)

```bash
subfinder -d example.com \
  -all \
  -silent \
  -o subdomains_full.txt
```

### Active validation (confirm live subdomains)

```bash
# Discover then immediately filter to live hosts
subfinder -d example.com -silent | \
  httpx -silent -mc 200,301,302,401,403 -o live_subdomains.txt
```

### JSONL with IP resolution

```bash
subfinder -d example.com \
  -active \
  -ip \
  -oJ \
  -o subdomains_with_ips.jsonl \
  -silent
```

## Chaining with Other Tools

```bash
# Full recon pipeline: subfinder -> httpx -> nuclei
subfinder -d example.com -silent | \
  httpx -silent -status-code -title -tech-detect -follow-redirects | \
  tee httpx_results.txt | \
  awk '{print $1}' | \
  nuclei -tags exposure,misconfig -severity medium,high,critical

# subfinder -> nmap: port scan all discovered subdomains
subfinder -d example.com -silent -o subdomains.txt
nmap -iL subdomains.txt -sV --top-ports 1000 -T4 -oA subdomain_scan

# subfinder -> ffuf: directory scan all live hosts
subfinder -d example.com -silent | \
  httpx -silent -mc 200 | \
  while read url; do
    ffuf -u "$url/FUZZ" \
      -w /usr/share/wordlists/dirb/common.txt \
      -mc 200,301,302 -ac -s
  done

# Collect all subdomains from multiple tools, deduplicate
subfinder -d example.com -silent > all_subs.txt
cat all_subs.txt | sort -u > unique_subs.txt
```

## Scope Management

```bash
# Filter to specific subdomain patterns
subfinder -d example.com -silent | grep -E "^(api|dev|staging|admin)\."

# Exclude out-of-scope subdomains
subfinder -d example.com -silent | grep -v "\.cdn\.\|\.static\."

# Using built-in match/filter flags
subfinder -d example.com -m "api,admin,dev" -silent
subfinder -d example.com -f "cdn,static,assets" -silent
```

## Validation

1. Cross-reference results with manual certificate transparency search: `https://crt.sh/?q=%.example.com`
2. Verify subdomains resolve with `dig <subdomain> +short` before passing to active tools
3. For wildcard domains (`*.example.com`), confirm each subdomain is individually hosted: `dig A <subdomain>` returning a unique IP means it's a real host
4. Check for subdomain takeover candidates: subdomains pointing to deprovisioned cloud services (AWS S3, Azure, GitHub Pages, Heroku)
5. Run httpx with `-probe` flag to confirm HTTP responses before vulnerability scanning

## False Positives

- **Wildcard DNS** -- some domains resolve all subdomains to a single IP/page; filter these out by checking if many subdomains share an identical response
- **Historical subdomains** -- passive sources include decommissioned subdomains; always validate with httpx before scanning
- **CDN subdomains** -- `cdn.example.com`, `assets.example.com` are usually low-value for vulnerability scanning; filter unless explicitly in scope
- **Third-party hosted** -- some discovered subdomains point to SaaS platforms (Zendesk, Salesforce, Hubspot); confirm ownership before testing
- **Duplicate entries from multiple sources** -- use `sort -u` to deduplicate

## Pro Tips

1. Always pipe through `httpx` to confirm live hosts before running any active tools -- passive data includes stale entries
2. `crtsh` alone covers 60-70% of subdomains for most targets without API keys -- start with it before adding sources
3. Use `-oJ -cs` (JSONL + source attribution) to track which sources contributed each subdomain -- helps diagnose missing coverage
4. For bug bounty targets, `github` source often reveals internal or development subdomains from leaked code
5. `-max-time 10` (default) may be too short for large enterprises -- increase to `-max-time 30` for thorough coverage
6. Combine with `naabu` for port discovery across all subdomains: `subfinder -d example.com -silent | naabu -silent`
7. Store API keys once in `~/.config/subfinder/provider-config.yaml` -- they persist across all runs without re-configuration
