---
name: nmap
description: Operator-assisted Nmap workflows for host discovery, port scanning, service enumeration, and NSE vulnerability detection
category: tools
tags: [recon, scanning, enumeration, operator-assisted]
---

# Nmap

Network mapper for host discovery, port scanning, service/version detection, and OS fingerprinting. The agent cannot run Nmap directly -- request the operator to execute scans and provide output for analysis.

## When to Request

- Beginning of any engagement for attack surface mapping
- After discovering new hosts, subdomains, or IP ranges
- When service versions are needed to identify exploitable software
- To run NSE scripts against specific services (HTTP, SMB, SSH, DNS)

## Operator-Assisted Workflow

1. Agent determines scan scope and objectives based on current assessment phase
2. Agent provides the operator with the exact Nmap command to run
3. Operator executes on their machine and pastes output (prefer XML with `-oX`)
4. Agent parses results: open ports, service versions, OS detection, script output
5. Agent uses findings to direct next steps (targeted vuln testing, service-specific agents)

## Key Commands

### Host Discovery
```
nmap -sn -PE -PP -PS80,443 -PA3389 -oX discovery.xml TARGET_RANGE
```

### Standard Service Scan
```
nmap -sV -sC -O -T4 -oX scan.xml TARGET
```

### Full TCP Port Scan
```
nmap -sS -p- -T4 --min-rate 1000 -oX full_tcp.xml TARGET
```

### UDP Top Ports
```
nmap -sU --top-ports 100 -sV -oX udp.xml TARGET
```

### Vulnerability Detection
```
nmap --script vuln -sV -p PORTS -oX vuln.xml TARGET
```

### Specific Service Scripts
```
# HTTP
nmap --script http-enum,http-headers,http-methods,http-title -p 80,443,8080 TARGET

# SMB
nmap --script smb-enum-shares,smb-enum-users,smb-vuln-* -p 445 TARGET

# DNS
nmap --script dns-zone-transfer,dns-brute -p 53 TARGET

# SSL/TLS
nmap --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed -p 443 TARGET
```

### Aggressive Full Assessment
```
nmap -A -T4 -p- --script "default or vuln" -oX aggressive.xml TARGET
```

## Output Formats

- **XML (`-oX`)** -- preferred; structured and parseable, includes all details
- **Greppable (`-oG`)** -- quick filtering with grep/awk
- **Normal (`-oN`)** -- human-readable text
- **All formats (`-oA basename`)** -- generates all three simultaneously

## Output Analysis

When the operator provides Nmap output, extract and act on:

- **Open ports and services** -- map the full attack surface; prioritize uncommon ports and services
- **Version strings** -- match against known CVEs (e.g., Apache 2.4.49 = CVE-2021-41773)
- **OS detection** -- informs exploit selection and payload compatibility
- **NSE script results** -- direct findings (vulns, misconfigs, info disclosure)
- **Filtered/closed distinction** -- filtered ports suggest firewall rules worth probing further
- **Service banners** -- technology stack identification, custom application fingerprinting

## Integration with Strix

- Feed discovered HTTP/HTTPS services into Strix proxy for web application testing
- Use version info to select appropriate vulnerability skills (e.g., load `nextjs` skill if Next.js detected)
- Spawn targeted sub-agents for each discovered service type
- Cross-reference open ports with known default service ports for technology identification

## Operator Help

To provide tool output for this request, save the full command output to the
HIL inbox file indicated by the agent:

```
strix/hil/inbox/resp_<TASK_ID>.txt
```

You can also pipe output directly:

```
nmap [OPTIONS] TARGET > strix/hil/inbox/resp_<TASK_ID>.txt
```

The agent will automatically detect and parse the response.  See the
`HIL_INBOX_PATH` environment variable to customise the inbox location.
