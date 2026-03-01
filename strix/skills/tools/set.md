---
name: set
description: Operator-assisted Social Engineering Toolkit workflows for phishing, credential harvesting, and client-side attack delivery
category: tools
tags: [social-engineering, phishing, exploitation, operator-assisted]
---

# SET (Social Engineering Toolkit)

Social engineering attack platform for phishing, credential harvesting, payload delivery, and website cloning. Use when the assessment scope includes social engineering or client-side attacks.

## When to Request

- When social engineering is in scope for the assessment
- To create credential harvesting pages that clone target login portals
- For payload delivery via crafted documents or USB attacks
- When phishing campaigns need to be set up for authorized testing

## Operator-Assisted Workflow

1. Agent identifies social engineering opportunities (target login pages, email patterns, employee info)
2. Agent specifies the attack type and provides configuration details
3. Operator runs SET and configures the attack (clone site, generate payload, set up listener)
4. Operator reports captured credentials or successful payload execution
5. Agent uses harvested credentials or access for further assessment

## Key Commands

### Launch SET
```
setoolkit
```

### Credential Harvester (Website Clone)
```
# Menu path: 1) Social-Engineering Attacks > 2) Website Attack Vectors > 3) Credential Harvester Attack Method > 2) Site Cloner
# Enter attacker IP and target URL to clone
```

### Spear Phishing
```
# Menu path: 1) Social-Engineering Attacks > 1) Spear-Phishing Attack Vectors
# Options: email template, payload, target list
```

### HTA Attack
```
# Menu path: 1) Social-Engineering Attacks > 2) Website Attack Vectors > 8) HTA Attack Method
```

### PowerShell Attack
```
# Menu path: 1) Social-Engineering Attacks > 10) PowerShell Attack Vectors > 1) PowerShell Alphanumeric Shellcode Injector
```

## Attack Types

- **Credential Harvester** -- clone login page, capture submitted credentials
- **Spear Phishing** -- craft targeted emails with malicious attachments
- **Website Attack** -- serve exploits via cloned or crafted web pages
- **Infectious Media** -- USB autorun payloads
- **PowerShell** -- fileless attack delivery via PowerShell

## Output Analysis

- **Captured credentials** -- test against all target services for reuse
- **Payload execution** -- confirms client-side attack viability; proceed to post-exploitation
- **Phishing metrics** -- click rates, credential submission rates for reporting
- **Shell access** -- from successful payload delivery; pivot to internal assessment

## Integration with Strix

- Agent provides target login URLs and email patterns discovered during recon
- Harvested credentials feed into authenticated web application testing via Strix
- Employee information from theHarvester/OSINT informs phishing target selection
- Successful phishing demonstrates risk for security awareness reporting
