---
name: burp-suite
description: Operator-assisted Burp Suite workflows for intercepting proxy analysis, active scanning, and manual web application testing
category: tools
tags: [proxy, web, scanning, operator-assisted]
---

# Burp Suite

Web application security testing proxy with interception, scanning, and manual testing tools. Use alongside Strix's Caido proxy when Burp-specific features are needed (active scanner, Intruder, Collaborator).

## When to Request

- When Burp's active scanner is needed for comprehensive automated vulnerability detection
- For Intruder attacks (credential stuffing, parameter fuzzing, race conditions)
- When Collaborator payloads are needed for out-of-band vulnerability detection (blind SSRF, XXE, SQLi)
- To capture and replay complex multi-step authentication flows

## Operator-Assisted Workflow

1. Agent identifies targets requiring Burp-specific testing capabilities
2. Agent specifies what to test: active scan scope, Intruder positions, Collaborator payloads
3. Operator configures Burp, runs scans/attacks, and reports findings
4. Agent analyzes results and directs follow-up exploitation
5. Agent incorporates Burp findings into the overall assessment via Strix reporting

## Key Workflows

### Active Scanning
```
1. Configure scope in Target > Scope
2. Crawl the application via embedded browser
3. Right-click > Scan from site map or specific requests
4. Review Scanner > Issue activity for findings
5. Export results as XML or HTML report
```

### Intruder Attack
```
1. Send request to Intruder (Ctrl+I)
2. Mark payload positions with section signs
3. Select attack type: Sniper, Battering Ram, Pitchfork, Cluster Bomb
4. Load payload list
5. Start attack and analyze results by status code, length, response time
```

### Collaborator (Out-of-Band)
```
1. Generate Collaborator payload: burpcollaborator.net subdomain
2. Inject into SSRF, XXE, SQLi, email header, DNS parameters
3. Monitor Collaborator for HTTP, DNS, SMTP callbacks
4. Confirm blind vulnerabilities via out-of-band interaction
```

### Repeater Testing
```
1. Send request to Repeater (Ctrl+R)
2. Modify parameters, headers, methods manually
3. Compare responses side-by-side
4. Iterate on injection payloads
```

### Extensions
```
- Autorize: automated authorization testing
- Logger++: advanced request logging
- Turbo Intruder: high-speed fuzzing with Python scripting
- JWT Editor: JWT manipulation and attack
- Param Miner: hidden parameter discovery
```

## Output Analysis

- **Active scan findings** -- severity-ranked vulnerabilities with request/response evidence
- **Intruder results** -- sort by response length/status to identify anomalies; different length = different behavior
- **Collaborator interactions** -- type (HTTP/DNS/SMTP), timing, and payload that triggered it
- **Repeater responses** -- manual comparison for injection confirmation

## Integration with Strix

- Strix identifies targets and attack vectors; Burp provides deep automated scanning
- Collaborator findings confirm blind vulnerabilities that Strix's proxy cannot detect
- Intruder results for credential testing complement Strix's authentication analysis
- Burp scan reports feed into Strix's vulnerability documentation
