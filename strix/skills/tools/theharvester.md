---
name: theharvester
description: Operator-assisted theHarvester workflows for OSINT gathering of emails, subdomains, IPs, and URLs from public sources
category: tools
tags: [osint, recon, enumeration, operator-assisted]
---

# theHarvester

OSINT tool for gathering emails, subdomains, hosts, employee names, open ports, and banners from public sources (search engines, certificate transparency, DNS).

## When to Request

- Early reconnaissance to map the target organization's external footprint
- Email harvesting for phishing scope or credential stuffing targets
- Subdomain discovery from passive sources (no direct target interaction)
- When active scanning is not yet authorized

## Operator-Assisted Workflow

1. Agent determines target domain and desired intelligence type
2. Agent specifies data sources and output format
3. Operator runs theHarvester and provides results
4. Agent correlates findings: emails map to user accounts, subdomains expand scope, IPs feed into port scanning
5. Agent directs follow-up recon or active testing on discovered assets

## Key Commands

### Full Passive Recon
```
theHarvester -d TARGET_DOMAIN -b all -l 500 -f output.json
```

### Specific Sources
```
# Search engines and certificate transparency
theHarvester -d TARGET_DOMAIN -b google,bing,crtsh,dnsdumpster,certspotter -l 200 -f output.json

# Shodan for exposed services
theHarvester -d TARGET_DOMAIN -b shodan -f output.json
```

### Email Focused
```
theHarvester -d TARGET_DOMAIN -b google,bing,linkedin,yahoo -l 500 -f emails.json
```

### DNS Brute Force (Active)
```
theHarvester -d TARGET_DOMAIN -b all -c -f output.json
```

## Output Analysis

- **Email addresses** -- identify naming patterns (first.last, flast); use for credential attacks, social engineering scope
- **Subdomains** -- expand attack surface; cross-reference with DNS resolution and port scanning
- **IP addresses and ranges** -- identify hosting providers, shared infrastructure, cloud services
- **Employee names** -- useful for username enumeration, social engineering, LinkedIn correlation
- **Exposed services (Shodan)** -- pre-identified open ports and banners without active scanning

## Integration with Strix

- Discovered subdomains feed into Nmap scanning and web application testing
- Email patterns inform username enumeration against login endpoints
- IP ranges define scope for network-level assessment
- Employee names help build custom wordlists for credential testing

## Operator Help

To provide tool output for this request, save the full command output to the
HIL inbox file indicated by the agent:

```
strix/hil/inbox/resp_<TASK_ID>.txt
```

You can also pipe output directly:

```
theharvester [OPTIONS] TARGET > strix/hil/inbox/resp_<TASK_ID>.txt
```

The agent will automatically detect and parse the response.  See the
`HIL_INBOX_PATH` environment variable to customise the inbox location.
