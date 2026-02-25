---
name: nuclei
description: Nuclei template-based vulnerability scanning, tag and severity filtering, rate control, and result interpretation
---

# Nuclei

Nuclei is a fast, template-based vulnerability scanner. Each template encodes a specific check -- CVE, misconfiguration, exposure, or default credential -- and runs against one or more targets. Templates are updated automatically in the Strix sandbox (`nuclei -update-templates` runs at container build time). Only use against authorized targets within the defined scope.

## Core Usage

### Basic scan against a target

```bash
nuclei -target https://example.com
```

### Multiple targets

```bash
# From a file
nuclei -list targets.txt

# From stdin (pipe from other tools)
echo "https://example.com" | nuclei -id exposed-panels
cat hosts.txt | nuclei -tags login,exposure -severity medium,high,critical
```

### Targeted scan by tag

```bash
# Web application tags
nuclei -target https://example.com -tags xss,sqli,ssrf,lfi,rce

# Exposure and misconfiguration checks
nuclei -target https://example.com -tags exposure,misconfig

# Login panels and default credentials
nuclei -target https://example.com -tags login,default-login

# CVE checks only
nuclei -target https://example.com -tags cve

# Technology-specific
nuclei -target https://example.com -tags wordpress,drupal,jenkins,gitlab
```

### Severity filtering

```bash
# Only high and critical
nuclei -target https://example.com -severity high,critical

# Exclude informational (reduce noise)
nuclei -target https://example.com -es info
```

## Key Flags Reference

| Flag | Purpose |
|------|---------|
| `-target` / `-u` | Single target URL |
| `-list` / `-l` | File containing targets (one per line) |
| `-id <id>` | Run specific template by ID |
| `-t <path>` | Template file or directory path |
| `-tags <tags>` | Filter by comma-separated tags |
| `-etags <tags>` | Exclude templates with these tags |
| `-severity <s>` | Filter: info,low,medium,high,critical |
| `-es <s>` | Exclude severity levels |
| `-stats` | Show scan statistics |
| `-c <n>` | Parallel template execution (default: 25) |
| `-rate-limit <n>` | Max requests per second (default: 150) |
| `-rl <n>` | Alias for -rate-limit |
| `-timeout <n>` | Request timeout in seconds (default: 5) |
| `-retries <n>` | Retry count for failed requests (default: 1) |
| `-o <file>` | Output file (text) |
| `-json` / `-j` | JSON output |
| `-json-export <file>` | Save JSON results to file |
| `-no-color` | Disable colored output |
| `-silent` | Only print findings (no banner/stats) |
| `-v` | Verbose (show requests/responses) |
| `-debug` | Debug mode (full request/response dump) |
| `-duc` | Disable update check |
| `-fhr` | Follow HTTP redirects |
| `-proxy <url>` | Route through proxy (e.g. Caido) |

## Template Categories

Templates are organized under `~/.local/nuclei-templates/`:

```
cves/          # CVE-specific checks by year
exposures/     # Sensitive file/data exposure
misconfigs/    # Security misconfiguration checks
default-logins/ # Default credentials for common services
technologies/  # Technology fingerprinting
vulnerabilities/ # General vulnerability checks
network/       # Port-level checks (non-HTTP)
dns/           # DNS-related checks
ssl/           # TLS/SSL issues
```

### List available templates by tag

```bash
nuclei -tl | grep -i "wordpress"
nuclei -tl -tags cve | head -20
```

## Recommended Scan Sequences

### Quick coverage scan (fast)

```bash
nuclei -target https://example.com \
  -tags exposure,misconfig,default-login \
  -severity medium,high,critical \
  -c 50 -rl 100 -silent
```

### Full web application scan (thorough)

```bash
nuclei -target https://example.com \
  -tags http,ssl,exposure,misconfig,xss,sqli,ssrf,lfi,rce,cve \
  -es info \
  -c 25 -rl 50 \
  -json-export nuclei_results.json
```

### CVE-focused scan

```bash
nuclei -target https://example.com \
  -tags cve \
  -severity high,critical \
  -stats
```

### Technology-specific (after tech detection via httpx)

```bash
# After httpx reveals WordPress
nuclei -target https://example.com \
  -tags wordpress \
  -severity low,medium,high,critical

# Jenkins
nuclei -target https://jenkins.example.com \
  -tags jenkins -severity medium,high,critical
```

## Output Interpretation

### Finding format

```
[timestamp] [template-id] [type] [severity] [target] [extra]
[2024-01-15 10:23:41] [CVE-2021-44228] [http] [critical] [http://example.com] ["X-Api-Version: ${jndi:ldap://x.x.x.x/x}"]
```

### Parse JSON output for specific fields

```python
import json

with open("nuclei_results.json") as f:
    for line in f:
        finding = json.loads(line)
        severity = finding.get('info', {}).get('severity', 'unknown').upper()
        template = finding.get('template-id', 'unknown')
        matched = finding.get('matched-at', '')
        print(f"[{severity}] {template}: {matched}")
```

### Key JSON fields

- `template-id` -- unique template identifier
- `info.severity` -- severity level
- `info.tags` -- template tags
- `matched-at` -- URL/endpoint where finding was triggered
- `extracted-results` -- captured data (e.g. version strings, credentials)
- `request` / `response` -- raw HTTP exchange (with `-v`)

## Rate Limiting and Stealth

```bash
# Conservative scan (WAF-aware, low rate)
nuclei -target https://example.com -rl 10 -c 5 -timeout 10 -retries 2

# Route through Caido proxy for traffic inspection
nuclei -target https://example.com -proxy http://127.0.0.1:8080 -tags http
```

## Chaining with Other Tools

```bash
# subfinder -> httpx -> nuclei (full pipeline)
subfinder -d example.com -silent | \
  httpx -silent -status-code -follow-redirects | \
  grep "200" | awk '{print $1}' | \
  nuclei -tags exposure,misconfig -severity medium,high,critical

# nmap open ports -> nuclei network templates
TARGET="10.0.0.1"
nmap -p- --open $TARGET -oG - | \
  awk '/Ports:/{for(i=1;i<=NF;i++) if($i ~ /\/open\//) {split($i,p,"/"); print p[1]}}' | \
  xargs -I{} nuclei -target "tcp://$TARGET:{}" -tags network
```

## Validation

1. Verify each finding by replaying the request manually using `curl` or the browser
2. Check `extracted-results` -- version matches confirm CVE applicability
3. For authentication-related findings, attempt the default credential shown
4. Use `-debug` to inspect the exact request/response that triggered a match
5. Cross-reference CVE findings against the confirmed service version from nmap `-sV`

## False Positives

- **Technology detection templates** often trigger on partial string matches -- verify version
- **Exposure templates** may match on benign backup files -- confirm file content is sensitive
- **Default login templates** may report success even when auth is only partially correct
- **Informational findings** are often not vulnerabilities -- use `-es info` to filter out noise
- Network timeouts cause false negatives -- use `-retries 2` and `-timeout 10` on slow targets

## Pro Tips

1. Always filter by `-severity medium,high,critical` for initial scans -- info findings create noise
2. Use `-json-export` to save results for structured follow-up, not plain `-o`
3. Run technology-specific templates after httpx tech detection rather than scanning everything
4. `nuclei -tl -tags <tag>` lists templates before running -- check coverage before scanning
5. For scope-limited engagements, use `-id <specific-template>` to avoid unintended checks
6. Combine with interactsh for blind vulnerability detection (SSRF, blind XSS, log4shell)
7. Low `-rl` values (10-20) dramatically reduce false negatives on rate-limited targets
