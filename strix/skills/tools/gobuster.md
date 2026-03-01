---
name: gobuster
description: Operator-assisted Gobuster workflows for directory brute-forcing, DNS subdomain enumeration, and vhost discovery
category: tools
tags: [recon, enumeration, brute-force, operator-assisted]
---

# Gobuster

Fast directory/file, DNS subdomain, and virtual host brute-forcer written in Go. Use when Strix's built-in crawling misses hidden paths, subdomains, or virtual hosts.

## When to Request

- After initial crawling to discover paths not linked in the application
- For subdomain enumeration alongside DNS recon
- To find hidden API endpoints, admin panels, backup files
- Virtual host discovery on shared hosting

## Operator-Assisted Workflow

1. Agent identifies target domains and web servers from recon
2. Agent specifies mode (dir/dns/vhost), wordlist, and extensions based on technology stack
3. Operator runs Gobuster and provides output
4. Agent analyzes discovered paths, subdomains, or vhosts
5. Agent prioritizes findings for further testing (admin panels, API routes, dev environments)

## Key Commands

### Directory Brute-Force
```
gobuster dir -u https://TARGET -w /usr/share/wordlists/dirb/common.txt -x php,asp,aspx,jsp,html,js,json -t 50 -o gobuster_dir.txt
```

### With Authentication Cookie
```
gobuster dir -u https://TARGET -w wordlist.txt -c "session=TOKEN" -H "Authorization: Bearer TOKEN" -o output.txt
```

### DNS Subdomain Enumeration
```
gobuster dns -d TARGET_DOMAIN -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 -o gobuster_dns.txt
```

### Virtual Host Discovery
```
gobuster vhost -u https://TARGET -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain -t 50 -o gobuster_vhost.txt
```

### API Endpoint Discovery
```
gobuster dir -u https://TARGET/api -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt -t 50 -o api_endpoints.txt
```

### Status Code Filtering
```
# Hide 404s, show everything else
gobuster dir -u https://TARGET -w wordlist.txt -b 404,403 -o output.txt

# Only show specific codes
gobuster dir -u https://TARGET -w wordlist.txt -s 200,301,302 -o output.txt
```

## Wordlist Selection

- **General**: `dirb/common.txt`, `dirbuster/directory-list-2.3-medium.txt`
- **Technology-specific**: `seclists/Discovery/Web-Content/` (raft, IIS, Apache, Tomcat, etc.)
- **API**: `seclists/Discovery/Web-Content/api/` endpoints and objects
- **DNS**: `seclists/Discovery/DNS/subdomains-top1million-*.txt`
- **Backup/sensitive**: `seclists/Discovery/Web-Content/common-and-sensitive.txt`

## Output Analysis

- **200 responses** -- accessible content; prioritize admin panels, config files, API docs
- **301/302 redirects** -- follow to find actual content location; auth redirects reveal protected paths
- **403 Forbidden** -- exists but restricted; try bypass techniques (path traversal, method switching, header manipulation)
- **500 errors** -- server errors may indicate injectable parameters or debug information
- **New subdomains** -- expand attack surface; scan each for services
- **Virtual hosts** -- may expose dev/staging environments with weaker security

## Integration with Strix

- Discovered paths feed directly into Strix proxy scope for application testing
- New subdomains trigger additional Nmap scans and web assessments
- Admin panels and API docs discovered here inform targeted agent creation
- 403 paths become targets for access control bypass testing
