---
name: nikto
description: Operator-assisted Nikto workflows for web server vulnerability scanning and misconfiguration detection
category: tools
tags: [scanning, web, misconfiguration, operator-assisted]
---

# Nikto

Web server scanner that checks for dangerous files, outdated software, server misconfigurations, and known vulnerabilities. Complements Strix's application-level testing with server-level checks.

## When to Request

- Early web assessment phase to identify low-hanging server misconfigs
- When checking for default files, backup files, and admin panels
- To verify HTTP header security (HSTS, X-Frame-Options, CSP)
- Against each unique web server in scope

## Operator-Assisted Workflow

1. Agent identifies web servers from recon (Nmap, DNS enumeration)
2. Agent provides Nikto command targeting specific host and port
3. Operator runs scan and provides output
4. Agent triages findings: confirm exploitable issues vs informational noise
5. Agent chains confirmed findings into deeper application testing

## Key Commands

### Standard Scan
```
nikto -h https://TARGET -o nikto_output.json -Format json
```

### With Authentication
```
nikto -h https://TARGET -id admin:password -o output.json -Format json
```

### Specific Port and SSL
```
nikto -h TARGET -p 8443 -ssl -o output.json -Format json
```

### Tuning (Focus Areas)
```
# 1=Files, 2=Misconfig, 3=Info, 4=XSS, 5=RFI, 6=Command exec, 7=SQLi, 8=File upload, 9=DoS
nikto -h TARGET -Tuning 1234567 -o output.json -Format json
```

### Multiple Hosts
```
nikto -h hosts.txt -o output.json -Format json
```

### Evasion Techniques
```
# IDS evasion: 1=Random URI encoding, 2=Self-reference, 3=Premature end, 4=Long URL
nikto -h TARGET -evasion 1234 -o output.json -Format json
```

## Output Analysis

- **OSVDB/CVE references** -- cross-reference with exploit databases for confirmed vulnerabilities
- **Default files found** -- admin panels, phpinfo, server-status, backup files worth investigating
- **Missing headers** -- note for reporting but prioritize exploitable findings
- **Outdated software** -- version-specific CVE lookup; feed into Metasploit or manual exploitation
- **Directory listings** -- immediate information disclosure; enumerate for sensitive files
- **HTTP methods** -- PUT/DELETE enabled may allow file upload or resource manipulation

## Integration with Strix

- Feed discovered paths and admin panels into Strix proxy for targeted testing
- Use found technology versions to load appropriate framework skills
- Chain default credentials findings with authentication testing
- Discovered backup files and config files feed into information disclosure analysis
