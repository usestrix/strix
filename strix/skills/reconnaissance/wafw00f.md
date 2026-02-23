---
name: wafw00f
description: wafw00f WAF detection and fingerprinting to identify web application firewalls before active scanning
---

# wafw00f

wafw00f fingerprints Web Application Firewalls (WAFs) by analyzing HTTP responses to normal and crafted requests. Identifying the WAF before scanning is critical -- it determines whether nuclei, ffuf, and sqlmap payloads need to be rate-limited, obfuscated, or adjusted to avoid triggering blocks. Run wafw00f immediately after httpx tech detection and before any active vulnerability scanning.

## Core Usage

### Basic detection

```bash
wafw00f https://example.com
```

### Multiple targets from file

```bash
wafw00f -i targets.txt
```

### Pipe from stdin

```bash
cat live_hosts.txt | xargs -I{} wafw00f {}
```

## Key Flags Reference

| Flag | Purpose |
|------|---------|
| (positional) | Target URL |
| `-i <file>` | Input file with URLs (one per line) |
| `-o <file>` | Output file (default: stdout) |
| `-f <format>` | Output format: `text`, `json`, `csv` (default: text) |
| `-a` | Fingerprint all WAFs, do not stop at first match |
| `-r` | Follow HTTP redirects |
| `-t <n>` | Number of concurrent threads (default: 1) |
| `-p <proxy>` | Proxy URL (e.g. `http://127.0.0.1:8080`) |
| `-v` | Verbose mode (show request/response details) |
| `-l` | List all WAFs wafw00f can detect |
| `--version` | Show version |

## WAF Detection Logic

wafw00f uses a three-phase detection approach:

1. **Baseline request** -- sends a normal HTTP GET and records headers, cookies, response codes
2. **Malicious probes** -- sends requests with known attack patterns (SQLi, XSS, path traversal) in parameters
3. **Differential analysis** -- compares normal vs. malicious responses to identify WAF signatures

Signatures are matched against 180+ known WAF products based on:
- Response headers (`X-Sucuri-ID`, `X-CDN`, `Server`, `X-Powered-By`)
- Cookie names (`incap_ses`, `__cfduid`, `citrix_ns_id`)
- Response body content (error page text, redirect URLs)
- HTTP status codes and timing patterns

## Output Formats

### Text (default)

```
[*] Checking https://example.com
[+] The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF.
[~] Number of requests: 2
```

### No WAF detected

```
[*] Checking https://example.com
[~] The site https://example.com does not seem to be behind a WAF
[~] Number of requests: 7
```

### JSON output

```bash
wafw00f https://example.com -f json -o waf_result.json
```

```json
[
  {
    "url": "https://example.com",
    "detected": true,
    "firewall": "Cloudflare",
    "manufacturer": "Cloudflare Inc."
  }
]
```

### CSV output

```bash
wafw00f -i targets.txt -f csv -o waf_results.csv
```

```
url,detected,firewall,manufacturer
https://example.com,true,Cloudflare,Cloudflare Inc.
https://api.example.com,false,,
```

## Common WAF Families and Scan Implications

| WAF | Detection | Scanning Strategy |
|-----|-----------|-------------------|
| **Cloudflare** | `cf-ray` header, `__cf_bm` cookie | Low rate (`-rl 10`), avoid generic XSS/SQLi in URLs |
| **AWS WAF / ALB** | `x-amzn-requestid`, `x-amz-cf-id` | Standard rate, watch for 403 on payload parameters |
| **Imperva (Incapsula)** | `incap_ses_*` cookie, `visid_incap_*` | Rotate User-Agent, slow rate |
| **Akamai** | `akamai-grn` header, `ak_bmsc` cookie | Behavioral analysis -- slow down significantly |
| **F5 BIG-IP ASM** | `TS` cookie prefix, `X-Cnection` header | Use `-rl 5`, fragment payloads |
| **Sucuri** | `x-sucuri-id` header | Standard rate, most checks are signature-based |
| **Fortinet FortiWeb** | `FORTIWAFSID` cookie | Low rate, payload encoding helps |
| **ModSecurity** | Generic 403 + `Mod_Security` in body | Tune payloads; many rules are bypassable |

## Recommended Scan Sequences

### Pre-scan WAF check (standard workflow)

```bash
# 1. Get live hosts
httpx -l subdomains.txt -silent -mc 200,301,302 -o live.txt

# 2. Detect WAFs across all live hosts
wafw00f -i live.txt -f json -o waf_results.json

# 3. Parse WAF results and adjust scanning strategy
python3 -c "
import json
results = json.load(open('waf_results.json'))
waf_protected = [r['url'] for r in results if r['detected']]
no_waf = [r['url'] for r in results if not r['detected']]
print('WAF-protected:', len(waf_protected))
print('No WAF:', len(no_waf))
for r in results:
    if r['detected']:
        print(f\"  {r['url']} -> {r['firewall']}\")
"
```

### Single target deep fingerprint

```bash
# Use -a to check all WAF signatures (not just first match)
wafw00f https://example.com -a -v
```

### Batch scan with threading

```bash
wafw00f -i targets.txt -t 5 -f json -o waf_results.json
```

## Adjusting Scan Strategy Based on WAF

### No WAF detected

```bash
# Scan at normal rate
nuclei -target https://example.com \
  -tags exposure,misconfig,xss,sqli \
  -severity medium,high,critical \
  -c 25 -rl 150

ffuf -u https://example.com/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -ac -t 40
```

### WAF detected (generic -- applies to most WAFs)

```bash
# Reduce rate, follow redirects, avoid noisy patterns
nuclei -target https://example.com \
  -tags exposure,misconfig \
  -severity high,critical \
  -c 5 -rl 10 -timeout 15

ffuf -u https://example.com/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -ac -rate 10 -p 0.2
```

### Cloudflare specifically

```bash
# Very conservative -- Cloudflare uses behavioral analysis
nuclei -target https://example.com \
  -tags ssl,exposure \
  -severity high,critical \
  -rl 5 -c 3 -timeout 20 -retries 1

# Route through proxy to inspect what triggers blocks
nuclei -target https://example.com \
  -proxy http://127.0.0.1:8080 \
  -tags http -rl 5
```

## Chaining with Other Tools

```bash
# Full pipeline with WAF-aware rate adjustment
TARGET="https://example.com"

# Step 1: Detect WAF
WAF=$(wafw00f $TARGET -f json | python3 -c "
import json, sys
r = json.load(sys.stdin)
print(r[0]['firewall'] if r[0]['detected'] else 'none')
")
echo "WAF: $WAF"

# Step 2: Set rate limit based on WAF
if [ "$WAF" = "none" ]; then
  RATE=150; CONCURRENCY=25
elif echo "$WAF" | grep -qi "cloudflare\|akamai"; then
  RATE=5; CONCURRENCY=3
else
  RATE=20; CONCURRENCY=10
fi

# Step 3: Run nuclei with adjusted rate
nuclei -target $TARGET \
  -tags exposure,misconfig \
  -severity medium,high,critical \
  -rl $RATE -c $CONCURRENCY

# subfinder -> httpx -> wafw00f -> nuclei pipeline
subfinder -d example.com -silent | \
  httpx -silent -mc 200,301,302 | \
  tee live_hosts.txt | \
  xargs -I{} wafw00f {} -f json >> all_waf.json
```

## Listing All Detectable WAFs

```bash
# See full list of 180+ supported WAF signatures
wafw00f -l
```

Notable detectable WAFs: 360 WangZhan Bao, Airlock, Alert Logic, Alibaba Cloud WAF, Amazon Web Services WAF, Akamai, AnquanBao, Approach, Armor, Baidu Yunjiasu, Barracuda, BIG-IP ASM, Cloudbric, Cloudflare, CloudFront, Comodo cWatch, CrawlProtect, DenyAll, Distil, DDoS-GUARD, Edgecast, F5, FortiWeb, Imperva, Incapsula, Janusec, Jiasule, KnownSec, ModSecurity, NAXSI, Nemesida, Nginx-WAF, NSFocus, Palo Alto, PerimeterX, PointIPSec, Profense, Qcloud, Radware, Reblaze, RSFirewall, Safedog, Sansetsu, SecuPress, Shieldon, SiteGround, Sitelock, Sucuri, Tencent, Trustwave, URLScan, Varnish, Wangsu, WebARX, WebKnight, Wordfence, XLabs, Yundun, Yunsuo, ZenEdge, and many more.

## Validation

1. Confirm WAF detection by manually sending a known-bad request: `curl -s -o /dev/null -w "%{http_code}" "https://example.com/?q=<script>alert(1)</script>"` -- WAF typically returns 403 or 406
2. Check response headers manually: `curl -I https://example.com` and look for WAF-specific headers
3. Use `-a` flag to check all signatures when WAF type is uncertain -- the first match may not be the primary WAF
4. For proxy deployments (CDN in front of WAF), wafw00f detects the outermost layer -- the origin may have a different WAF
5. Re-run after bypass attempts to confirm WAF is still responding

## False Positives

- **CDN without WAF** -- Cloudflare CDN (proxy only) may trigger WAF signatures even without WAF rules enabled; test actual blocking behavior with a simple `<script>` payload
- **Custom error pages** -- applications with custom 403/406 pages that happen to contain WAF-like text can cause false matches
- **Load balancers** -- F5 BIG-IP load balancers without ASM enabled may be detected as "BIG-IP" WAF
- **"No WAF detected" is not a green light** -- some WAFs (especially custom/enterprise) may not match known signatures; aggressive scans may still be blocked
- **Timing-based detection only** -- some behavioral WAFs (Akamai Bot Manager, PerimeterX) may not be detected because they require browser fingerprinting, not just HTTP analysis

## Pro Tips

1. Always run wafw00f before nuclei, ffuf, or sqlmap -- a single 429/block from Cloudflare can IP-ban the sandbox for hours
2. Use `-a` on targets with uncertain results -- some hosts run multiple WAF layers (e.g., Cloudflare in front of ModSecurity)
3. JSON output is the only format that works reliably in pipelines -- avoid parsing text output
4. "No WAF detected" on port 443 does not mean port 8080/8443 is unprotected -- check all HTTP-speaking ports individually
5. When WAF is detected, start with non-intrusive nuclei tags (`ssl`, `exposure`, `technologies`) before escalating to `xss`, `sqli`
6. Document the WAF in findings -- a target behind Cloudflare Business/Enterprise has different remediation implications than one behind ModSecurity
7. Proxy the wafw00f traffic through Caido/Burp (`-p http://127.0.0.1:8080`) to see exactly which requests trigger WAF responses
