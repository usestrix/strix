---
name: httpx
description: httpx HTTP probing, technology detection, status filtering, and response analysis for web reconnaissance
---

# httpx

httpx is a fast multi-purpose HTTP toolkit for probing web servers. It confirms which hosts are alive on HTTP/HTTPS, extracts titles, status codes, response sizes, server banners, and technology fingerprints. Run it after port discovery (nmap) and before vulnerability scanning (nuclei) to filter down to live targets. Only use against authorized targets within the defined scope.

## Core Usage

### Basic probe

```bash
httpx -u https://example.com
```

### Probe a list of hosts

```bash
httpx -l hosts.txt
httpx -l hosts.txt -ports 80,443,8080,8443
```

### Pipe from stdin

```bash
cat hosts.txt | httpx -silent -status-code -title
echo "https://example.com" | httpx -tech-detect
```

## Key Flags Reference

| Flag | Purpose |
|------|---------|
| `-u` / `-target` | Single target URL |
| `-l` / `-list` | File with targets (one per line) |
| `-ports <list>` | Comma-separated ports to probe (e.g. `80,443,8080`) |
| `-sc` / `-status-code` | Show HTTP status code in output |
| `-title` | Extract and show page title |
| `-server` | Show `Server` response header |
| `-tech-detect` | Fingerprint technologies (Wappalyzer-based) |
| `-td` | Alias for `-tech-detect` |
| `-cl` / `-content-length` | Show response content length |
| `-ct` / `-content-type` | Show `Content-Type` header |
| `-location` | Show redirect `Location` header |
| `-follow-redirects` | Follow HTTP redirects |
| `-fr` | Alias for `-follow-redirects` |
| `-mc <codes>` | Match specific status codes (e.g. `-mc 200,301`) |
| `-fc <codes>` | Filter out status codes (e.g. `-fc 404,403`) |
| `-ms <size>` | Match response size (bytes) |
| `-fs <size>` | Filter by response size |
| `-ml <lines>` | Match response line count |
| `-fl <lines>` | Filter by response line count |
| `-tls-probe` | Show TLS certificate info |
| `-tls-grab` | Extract TLS details (expiry, issuer, SANs) |
| `-cname` | Resolve and show CNAME records |
| `-cdn` | Detect CDN provider |
| `-probe` | Show probe result (true/false) |
| `-path <path>` | Append path to each target |
| `-threads <n>` | Concurrent threads (default: 50) |
| `-rate-limit <n>` | Max requests per second |
| `-timeout <n>` | Request timeout in seconds (default: 10) |
| `-retries <n>` | Retry count for failed requests |
| `-o <file>` | Output to file |
| `-json` / `-j` | JSON output |
| `-silent` | Only print results (no banner) |
| `-nc` / `-no-color` | Disable colored output |
| `-v` | Verbose mode |

## Standard Output Flags (Recommended Combination)

```bash
httpx -l hosts.txt \
  -status-code -title -server -tech-detect \
  -follow-redirects \
  -silent
```

This gives: `URL [status] [title] [server] [technologies]`

## Technology Detection

```bash
# Detect tech stack on single target
httpx -u https://example.com -tech-detect -silent

# Detect across many hosts, output JSON for parsing
httpx -l hosts.txt -tech-detect -json -o tech_results.jsonl -silent

# Filter to targets running specific tech
httpx -l hosts.txt -tech-detect -silent | grep -i "wordpress"
httpx -l hosts.txt -tech-detect -silent | grep -i "nginx\|apache"
httpx -l hosts.txt -tech-detect -silent | grep -i "jenkins\|gitlab\|jira"
```

Detection covers: CMS (WordPress, Drupal, Joomla), frameworks (React, Angular, Django, Laravel), web servers (Nginx, Apache, IIS, Caddy), CDNs (Cloudflare, Fastly, Akamai), and 1500+ other technologies.

## Status Code Filtering

```bash
# Only live hosts (200 OK)
httpx -l hosts.txt -mc 200 -silent

# All successful responses
httpx -l hosts.txt -mc 200,201,204 -silent

# Find login panels (redirects + 200)
httpx -l hosts.txt -mc 200,301,302 -title -silent | grep -i "login\|signin\|admin"

# Exclude not-found and forbidden
httpx -l hosts.txt -fc 404,403 -silent
```

## TLS Certificate Probing

```bash
# Basic TLS info
httpx -l hosts.txt -tls-probe -silent

# Detailed certificate extraction (SANs reveal related domains)
httpx -l hosts.txt -tls-grab -json -o tls.jsonl -silent

# Parse SANs from JSON output
python3 -c "
import json
with open('tls.jsonl') as f:
    for line in f:
        d = json.loads(line)
        tls = d.get('tls-grab', {})
        sans = tls.get('subject_an', [])
        print(d['url'], '->', sans)
"
```

## Output Formats

### Plain text (default)

```
https://example.com [200] [Example Domain] [nginx/1.18.0]
```

### JSON output (for automation)

```bash
httpx -l hosts.txt -status-code -title -tech-detect -json -o results.jsonl
```

### Key JSON fields

Field names may use hyphens or underscores depending on httpx version. Use fallback access (`r.get('status_code', r.get('status-code'))`) when parsing programmatically.

- `url` -- final URL after redirects
- `status_code` / `status-code` -- HTTP response code
- `title` -- extracted page title
- `webserver` -- `Server` header value
- `tech` -- detected technology list
- `content_length` / `content-length` -- response size in bytes
- `content_type` / `content-type` -- response MIME type
- `tls-grab` / `tls` -- TLS certificate details
- `host` -- resolved IP address
- `cname` -- CNAME chain

### Parse JSON output

```python
import json

def get(r, *keys):
    """Version-safe field access for httpx JSON output."""
    for k in keys:
        if k in r:
            return r[k]
    return None

with open("results.jsonl") as f:
    for line in f:
        r = json.loads(line)
        status = get(r, 'status_code', 'status-code')
        tech = r.get('tech', [])
        print(f"[{status}] {r['url']} | {r.get('title','')} | {', '.join(tech)}")
```

## Recommended Scan Sequences

### Full web recon (standard)

```bash
httpx -l subdomains.txt \
  -status-code -title -server -tech-detect \
  -follow-redirects \
  -fc 404 \
  -threads 50 \
  -json -o httpx_results.jsonl \
  -silent
```

### Quick alive check (fast)

```bash
httpx -l hosts.txt -mc 200,301,302 -silent -threads 100
```

### Admin panel hunting

```bash
httpx -l hosts.txt \
  -path /admin \
  -mc 200,301,302 \
  -title -silent
```

### Port sweep with httpx

```bash
# Probe a single host on common web ports
httpx -u http://10.0.0.1 -ports 80,443,8000,8080,8443,8888,9000,9090,3000,5000 \
  -status-code -title -silent
```

## Chaining with Other Tools

```bash
# subfinder -> httpx -> nuclei (full recon pipeline)
subfinder -d example.com -silent | \
  httpx -status-code -title -tech-detect -follow-redirects -silent | \
  tee httpx_results.txt | \
  awk '{print $1}' | \
  nuclei -tags exposure,misconfig -severity medium,high,critical

# nmap -> httpx (probe discovered HTTP ports)
TARGET="10.0.0.1"
nmap -p- --open -oG - $TARGET | \
  awk '/Ports:/{for(i=1;i<=NF;i++) if($i ~ /\/open\//) {split($i,p,"/"); print p[1]}}' | \
  xargs -I{} echo "http://$TARGET:{}" | httpx -status-code -title -silent

# httpx tech detection -> targeted nuclei scan
httpx -l subdomains.txt -tech-detect -json -o tech.jsonl -silent
# Then run technology-specific nuclei templates based on detected stack
cat tech.jsonl | python3 -c "
import json, sys
for line in sys.stdin:
    r = json.loads(line)
    tech = [t.lower() for t in r.get('tech', [])]
    if any('wordpress' in t for t in tech):
        print(r['url'])
" | nuclei -tags wordpress -severity low,medium,high,critical
```

## Validation

1. Confirm URLs are reachable: `curl -I -L <url>` and compare status codes with httpx output
2. Verify tech detection against page source: `curl -s <url> | grep -i "wp-content\|generator"` for WordPress
3. Cross-check TLS SANs with manual `openssl s_client -connect <host>:443 </dev/null | openssl x509 -noout -text`
4. For unexpected redirects, trace manually with `curl -v -L <url>` to see full redirect chain

## False Positives

- **Technology detection** relies on response headers and body patterns -- may miss custom installations or flag incorrectly on shared components
- **CDN detection** may report false positives when behind reverse proxies that add CDN-like headers
- **Content-length filtering** varies by encoding (gzip vs plain) -- use with caution for precise filtering
- **Status codes behind WAFs** -- 403 may mean both "forbidden" and "WAF blocked scan" -- manual verification required

## Pro Tips

1. Always use `-follow-redirects` -- many targets serve `http://` but redirect to `https://`
2. `-tech-detect` is the most valuable flag for prioritizing nuclei templates -- run it on every web target
3. Use `-json` output format for all scripted pipelines -- plain text is harder to parse reliably
4. Combine `-path /admin,/wp-admin,/manager` to quickly hunt login panels across many hosts
5. For large subdomain lists (1000+), set `-threads 100` and `-rate-limit 300` to balance speed and reliability
6. TLS SANs from `-tls-grab` often reveal additional subdomains not found by subfinder
7. Filter results with `-fc 404,400` before passing to nuclei to avoid scanning dead hosts
