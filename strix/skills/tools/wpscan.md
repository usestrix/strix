---
name: wpscan
description: Operator-assisted WPScan workflows for WordPress vulnerability scanning, plugin/theme enumeration, and user discovery
category: tools
tags: [scanning, wordpress, web, operator-assisted]
---

# WPScan

WordPress-specific security scanner for core, plugin, and theme vulnerability detection, user enumeration, and configuration analysis. Essential when a target runs WordPress.

## When to Request

- When WordPress is identified on any target (via headers, meta tags, wp-login, /wp-content/)
- To enumerate installed plugins and themes with known vulnerabilities
- For WordPress user enumeration
- To check WordPress core version against known CVEs

## Operator-Assisted Workflow

1. Agent identifies WordPress installation from recon or technology fingerprinting
2. Agent requests WPScan with appropriate enumeration flags
3. Operator runs scan (API token recommended for vulnerability data) and provides output
4. Agent maps vulnerabilities to plugins/themes/core versions
5. Agent directs exploitation of confirmed vulnerabilities

## Key Commands

### Full Enumeration
```
wpscan --url https://TARGET -e ap,at,u --api-token API_TOKEN -o wpscan.json -f json
```

### Plugin Enumeration (Aggressive)
```
wpscan --url https://TARGET -e ap --plugins-detection aggressive --api-token API_TOKEN -o plugins.json -f json
```

### User Enumeration
```
wpscan --url https://TARGET -e u1-100 -o users.json -f json
```

### Password Brute Force
```
wpscan --url https://TARGET -U users.txt -P passwords.txt --max-threads 10
```

### Specific Plugin Check
```
wpscan --url https://TARGET --plugins-detection aggressive -e ap --api-token API_TOKEN -o output.json -f json
```

### Stealthy Scan
```
wpscan --url https://TARGET -e ap,u --plugins-detection passive --random-user-agent --throttle 500 -o output.json -f json
```

## Output Analysis

- **Vulnerable plugins/themes** -- highest priority; check exploit availability in WPVulnDB, ExploitDB
- **Outdated WordPress core** -- version-specific CVEs; check for unauthenticated RCE/SQLi/XSS
- **Discovered users** -- feed into brute force or credential stuffing attacks
- **XML-RPC enabled** -- potential for brute force amplification, SSRF, pingback DDoS
- **Debug mode** -- information disclosure; may expose database credentials or paths
- **Directory listing** -- enumerate wp-content/uploads for sensitive files
- **Backup files** -- wp-config.php.bak, .sql dumps containing credentials

## Integration with Strix

- Vulnerable plugins with known RCE/SQLi feed directly into exploitation via Strix agents
- Discovered usernames used for authentication testing against wp-login and XML-RPC
- Plugin and theme info informs custom payload crafting for XSS and injection testing
- wp-config exposure feeds into credential reuse testing against databases and other services

## Operator Help

To provide tool output for this request, save the full command output to the
HIL inbox file indicated by the agent:

```
strix/hil/inbox/resp_<TASK_ID>.txt
```

You can also pipe output directly:

```
wpscan [OPTIONS] TARGET > strix/hil/inbox/resp_<TASK_ID>.txt
```

The agent will automatically detect and parse the response.  See the
`HIL_INBOX_PATH` environment variable to customise the inbox location.
