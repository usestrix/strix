---
name: ffuf
description: ffuf web fuzzing for directory/file discovery, parameter fuzzing, vhost enumeration, and response filtering
---

# ffuf

ffuf (Fuzz Faster U Fool) is a fast web fuzzer for directory and file discovery, parameter enumeration, virtual host brute-forcing, and any HTTP-based fuzzing task. The `FUZZ` keyword marks the injection point in the request -- it can appear in the URL path, query string, headers, or POST body. Only use against authorized targets within the defined scope.

## Core Usage

### Directory and file discovery

```bash
ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt
```

### Extension fuzzing

```bash
ffuf -u https://example.com/FUZZ -w wordlist.txt -e .php,.txt,.html,.bak,.zip
```

### File in a specific directory

```bash
ffuf -u https://example.com/admin/FUZZ -w /usr/share/wordlists/dirb/common.txt
```

## Key Flags Reference

| Flag | Purpose |
|------|---------|
| `-u <url>` | Target URL (use `FUZZ` as placeholder) |
| `-w <wordlist>` | Wordlist file path (use `WORDLIST:KEYWORD` for named keywords) |
| `-e <exts>` | File extensions to append (e.g. `.php,.html`) |
| `-mc <codes>` | Match HTTP status codes (default: 200,204,301,302,307,401,403,405,500) |
| `-fc <codes>` | Filter out status codes (e.g. `-fc 404,400`) |
| `-ms <size>` | Match response size in bytes |
| `-fs <size>` | Filter by response size (exclude specific sizes) |
| `-fw <words>` | Filter by word count in response |
| `-fl <lines>` | Filter by line count in response |
| `-mr <regex>` | Match responses containing regex pattern |
| `-fr <regex>` | Filter responses matching regex |
| `-H <header>` | Add/override request header (e.g. `-H "Cookie: session=abc"`) |
| `-X <method>` | HTTP method (default: GET) |
| `-d <data>` | POST request body |
| `-b <cookies>` | Cookie string |
| `-t <n>` | Concurrent threads (default: 40) |
| `-rate <n>` | Max requests per second |
| `-p <delay>` | Delay between requests (e.g. `0.1` seconds) |
| `-timeout <n>` | Request timeout in seconds (default: 10) |
| `-recursion` | Enable recursive fuzzing |
| `-recursion-depth <n>` | Max recursion depth |
| `-of <format>` | Output format: `json`, `ejson`, `html`, `md`, `csv`, `all` |
| `-o <file>` | Output file |
| `-v` | Verbose (show full URL + redirect location) |
| `-s` | Silent mode (no banner, only results) |
| `-c` | Colorize output |
| `-ac` | Auto-calibrate response filtering (recommended) |
| `-ic` | Ignore wordlist comments |
| `-r` | Follow redirects |
| `-x <proxy>` | Route traffic through proxy (e.g. `-x http://127.0.0.1:8080`) |
| `-k` | Skip TLS certificate verification |

## Wordlists Available in Sandbox

```
/usr/share/wordlists/dirb/common.txt          # 4614 entries, general purpose
/usr/share/wordlists/dirb/big.txt             # 20469 entries, more thorough
/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt
/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

## Response Filtering (Critical)

Unfiltered results are noisy. Always filter with one or more of these approaches:

### Auto-calibration (recommended)

```bash
# Let ffuf detect the baseline response size automatically
ffuf -u https://example.com/FUZZ -w wordlist.txt -ac
```

### Manual size filtering

```bash
# First, probe a known-missing path to get the 404 response size
curl -s -o /dev/null -w "%{size_download}" https://example.com/nonexistent123
# Then filter that size
ffuf -u https://example.com/FUZZ -w wordlist.txt -fs 1234
```

### Status code filtering

```bash
# Show only interesting responses
ffuf -u https://example.com/FUZZ -w wordlist.txt -mc 200,204,301,302,401,403

# Exclude common noise
ffuf -u https://example.com/FUZZ -w wordlist.txt -fc 404,400,500
```

## Common Scenarios

### Standard directory discovery

```bash
ffuf -u https://example.com/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -mc 200,301,302,401,403 \
  -ac \
  -c -v
```

### Deep discovery with extensions

```bash
ffuf -u https://example.com/FUZZ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -e .php,.html,.txt,.bak,.zip,.conf,.log \
  -mc 200,301,302 \
  -ac \
  -t 50 \
  -o ffuf_results.json -of json
```

### Recursive scan

```bash
ffuf -u https://example.com/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -recursion -recursion-depth 2 \
  -mc 200,301,302 \
  -ac \
  -t 30
```

### API endpoint discovery

```bash
ffuf -u https://api.example.com/FUZZ \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,400,401,403,405 \
  -H "Content-Type: application/json" \
  -ac -c -v
```

### Backup and config file hunting

```bash
ffuf -u https://example.com/FUZZ \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  -e .bak,.backup,.old,.orig,.swp,.zip,.tar.gz,.conf,.config,.env,.yaml,.yml \
  -mc 200 \
  -ac
```

## Parameter Fuzzing

### GET parameter discovery

```bash
# Find hidden GET parameters
ffuf -u https://example.com/page?FUZZ=value \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 \
  -fs $(curl -s -o /dev/null -w "%{size_download}" "https://example.com/page")
```

### POST parameter fuzzing

```bash
ffuf -u https://example.com/login \
  -X POST \
  -d "FUZZ=value&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 -ac
```

### Value fuzzing (brute force a parameter)

```bash
ffuf -u https://example.com/page?id=FUZZ \
  -w /usr/share/wordlists/seclists/Fuzzing/Integers/Integers.txt \
  -mc 200 \
  -ac
```

## Virtual Host Enumeration

```bash
# Enumerate vhosts via Host header fuzzing
ffuf -u https://example.com/ \
  -H "Host: FUZZ.example.com" \
  -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -mc 200,301,302 \
  -ac \
  -c -v
```

## Multiple Wordlists (W1/W2 keywords)

```bash
# Fuzz both directory and extension simultaneously
ffuf -u https://example.com/W1.W2 \
  -w /usr/share/wordlists/dirb/common.txt:W1 \
  -w /usr/share/wordlists/seclists/Fuzzing/extensions.txt:W2 \
  -mc 200 -ac
```

## Authenticated Scanning

```bash
# Cookie-based auth
ffuf -u https://example.com/FUZZ \
  -w wordlist.txt \
  -b "session=abc123; csrf_token=xyz" \
  -mc 200,301,302,403 -ac

# Bearer token auth
ffuf -u https://api.example.com/FUZZ \
  -w api-endpoints.txt \
  -H "Authorization: Bearer <token>" \
  -mc 200,201,401,403,405 -ac
```

## Rate Control for WAF Evasion

```bash
# Slow scan to avoid rate limiting/blocking
ffuf -u https://example.com/FUZZ \
  -w wordlist.txt \
  -rate 10 \
  -p 0.1 \
  -mc 200,301,302 -ac

# Route through proxy for traffic inspection
ffuf -u https://example.com/FUZZ \
  -w wordlist.txt \
  -x http://127.0.0.1:8080 \
  -mc 200,301 -ac
```

## Output and Parsing

### JSON output

```bash
ffuf -u https://example.com/FUZZ \
  -w wordlist.txt \
  -o results.json -of json \
  -ac -s
```

### Parse JSON results

```python
import json

with open("results.json") as f:
    data = json.load(f)

for result in data.get("results", []):
    print(f"[{result['status']}] {result['url']} "
          f"(size: {result['length']}, words: {result['words']}, lines: {result['lines']})")
```

### Key JSON fields

- `url` -- full URL of the finding
- `status` -- HTTP response code
- `length` -- response body size in bytes
- `words` -- word count in response
- `lines` -- line count in response
- `duration` -- request duration in nanoseconds
- `redirectlocation` -- redirect target (if applicable)

## Validation

1. Visit each discovered path in the browser or with `curl -I <url>` to confirm the finding
2. For 403 responses, check if content is actually accessible -- some 403s expose directory listings
3. For redirects (301/302), follow manually to see the final destination
4. Verify backup files contain sensitive data before reporting: `curl -s <url> | head -50`
5. Cross-check discovered endpoints against robots.txt and sitemap.xml for missed paths

## False Positives

- **Wildcard responses** -- some servers return 200 for all paths; use `-ac` or `-fs` to filter these out
- **WAF soft-blocks** -- WAF may return 200 with an error page for blocked requests; filter by response size
- **CDN caching** -- cached responses may return 200 for removed content; verify with `curl -H "Cache-Control: no-cache"`
- **Redirect chains** -- a 301 to a 404 still shows as 301 in ffuf; use `-r` to follow and `-mc 200` to confirm
- **Rate-limit pages** -- if rate limited, server may return consistent 429 or 503 for all requests; pause and retry with `-rate 5`

## Chaining with Other Tools

```bash
# httpx -> ffuf: run directory scan only on live hosts
httpx -l subdomains.txt -mc 200,301,302 -silent | \
  awk '{print $1}' | \
  while read url; do
    ffuf -u "$url/FUZZ" -w /usr/share/wordlists/dirb/common.txt \
      -mc 200,301,302 -ac -s -o - -of json
  done

# ffuf discovery -> nuclei: scan discovered endpoints
ffuf -u https://example.com/FUZZ \
  -w wordlist.txt -mc 200 -ac -s \
  -o ffuf.json -of json
python3 -c "
import json
d = json.load(open('ffuf.json'))
for r in d.get('results', []):
    print(r['url'])
" | nuclei -tags exposure,xss,sqli -severity medium,high,critical
```

## Pro Tips

1. Always use `-ac` (auto-calibration) as a first pass -- manually tune with `-fs` if results are still noisy
2. Start with a small wordlist (`common.txt`) then escalate to larger ones (`directory-list-2.3-medium.txt`) for confirmed targets
3. The `-e` flag multiplies requests by the number of extensions -- keep extension lists short
4. Use `-v` to see redirect chains -- a 301 to `/admin/` often means the directory exists
5. For APIs, include `-mc 400,401,405` -- these responses often confirm a valid endpoint exists even when authentication is required
6. Combine `-recursion -recursion-depth 2` only on confirmed interesting directories -- unlimited recursion creates enormous request volumes
7. Save results with `-of json -o` on every scan -- plain text output loses filtering metadata
