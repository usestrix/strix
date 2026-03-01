---
name: nuclei
description: Operator-assisted Nuclei workflows for template-based vulnerability scanning across web applications, networks, and cloud services
category: tools
tags: [scanning, vulnerability, templates, operator-assisted]
---

# Nuclei

Template-based vulnerability scanner with a massive community template library. Covers CVEs, misconfigurations, exposed panels, default credentials, and technology detection. Fast and highly configurable.

## When to Request

- After recon to scan all discovered hosts for known vulnerabilities at scale
- Technology-specific CVE checks when service versions are identified
- Exposed panel and default credential sweeps
- Cloud misconfiguration checks
- Custom template scanning for application-specific patterns

## Operator-Assisted Workflow

1. Agent identifies targets and selects template categories based on recon findings
2. Agent provides Nuclei command with appropriate tags, severity filters, and output format
3. Operator runs scan (may take time for large template sets) and provides output
4. Agent triages results by severity and exploitability
5. Agent prioritizes confirmed vulnerabilities for manual exploitation and chains

## Key Commands

### General Vulnerability Scan
```
nuclei -u https://TARGET -as -o nuclei_output.json -jsonl
```

### By Severity
```
nuclei -u https://TARGET -s critical,high -o critical_high.json -jsonl
```

### By Tags
```
# Specific technology
nuclei -u https://TARGET -tags cve,sqli,xss,rce,lfi -o tagged.json -jsonl

# Exposed panels and default logins
nuclei -u https://TARGET -tags panel,default-login -o panels.json -jsonl
```

### Multiple Targets
```
nuclei -l targets.txt -s critical,high,medium -o results.json -jsonl -c 50 -rl 150
```

### Specific CVE Check
```
nuclei -u https://TARGET -id CVE-2021-44228,CVE-2023-34362 -o cve_check.json -jsonl
```

### Technology Detection
```
nuclei -u https://TARGET -tags tech -o tech_detect.json -jsonl
```

### Custom Templates
```
nuclei -u https://TARGET -t /path/to/custom-templates/ -o custom.json -jsonl
```

### Network Scan
```
nuclei -l hosts.txt -t network/ -p 21,22,80,443,445,3306,3389,5432,8080 -o network.json -jsonl
```

## Template Categories

- **cves/** -- known CVE exploits and checks
- **vulnerabilities/** -- generic vulnerability patterns
- **misconfiguration/** -- server and service misconfigs
- **exposures/** -- sensitive file and data exposure
- **default-logins/** -- default credential checks
- **technologies/** -- technology fingerprinting
- **network/** -- network service vulnerabilities

## Output Analysis

- **Critical/High findings** -- immediate exploitation targets; verify manually and chain
- **CVE matches** -- cross-reference with Metasploit modules or public exploits
- **Exposed panels** -- admin interfaces for credential testing or direct exploitation
- **Default credentials** -- immediate access if valid; test for privilege escalation
- **Technology detection** -- informs skill selection and targeted testing approach
- **Misconfigurations** -- may enable further attacks (open redirects, CORS, debug endpoints)

## Integration with Strix

- Confirmed vulnerabilities trigger specialized Strix agents for exploitation
- Technology detection results inform which skills to load for sub-agents
- Exposed panels feed into Strix proxy for authenticated testing
- CVE findings guide Metasploit module selection for the operator

## Operator Help

To provide tool output for this request, save the full command output to the
HIL inbox file indicated by the agent:

```
strix/hil/inbox/resp_<TASK_ID>.txt
```

You can also pipe output directly:

```
nuclei [OPTIONS] TARGET > strix/hil/inbox/resp_<TASK_ID>.txt
```

The agent will automatically detect and parse the response.  See the
`HIL_INBOX_PATH` environment variable to customise the inbox location.
