---
name: nmap
description: Nmap port scanning, service detection, OS fingerprinting, and NSE script guidance for network reconnaissance
---

# Nmap

Nmap is the primary network discovery and port scanning tool in the Strix sandbox. Use it to map open ports, identify running services and versions, fingerprint operating systems, and run targeted NSE scripts against discovered services.

## Core Scan Types

### TCP SYN Scan (default, recommended)

```bash
nmap -sS -p- --open -T4 <target>
```

Fast, stealthy half-open scan. Requires root (already available in sandbox). Use `--open` to suppress closed/filtered ports.

### Service and Version Detection

```bash
nmap -sV -sC -p <ports> <target>
```

`-sV` probes open ports for service/version. `-sC` runs default NSE scripts (safe category). Always run after initial port discovery -- do NOT combine full port scan with version detection on all 65535 ports.

### Recommended Two-Phase Workflow

```bash
# Phase 1: fast port discovery (all ports, no version)
nmap -sS -p- --open -T4 -oN ports.txt <target>

# Phase 2: deep scan on discovered ports only
nmap -sV -sC -O -p 22,80,443,8080 --script=vuln -oA deep_scan <target>
```

### UDP Scan (slow -- use sparingly)

```bash
nmap -sU --top-ports 100 -T4 <target>
```

UDP scanning is slow. Limit to top ports or specific services (DNS/53, SNMP/161, TFTP/69).

### OS Detection

```bash
nmap -O --osscan-guess <target>
```

Requires at least one open and one closed TCP port. Use `--osscan-guess` for imprecise matches.

## Key Flags Reference

| Flag | Purpose |
|------|---------|
| `-sS` | TCP SYN scan (stealth, default with root) |
| `-sT` | TCP connect scan (no root needed) |
| `-sV` | Service/version detection |
| `-sC` | Default NSE scripts |
| `-O` | OS detection |
| `-A` | Aggressive: -sV -sC -O --traceroute combined |
| `-p-` | All 65535 ports |
| `-p <list>` | Specific ports: `-p 22,80,443` or `-p 1-1000` |
| `--open` | Show only open ports |
| `-T1` to `-T5` | Timing: T1=sneaky, T3=default, T4=fast, T5=insane |
| `--min-rate <n>` | Force minimum packet rate (e.g. `--min-rate 1000`) |
| `--script <name>` | Run specific NSE script or category |
| `-oN <file>` | Normal output to file |
| `-oX <file>` | XML output (parseable) |
| `-oA <base>` | All formats: .nmap, .xml, .gnmap |
| `-v` / `-vv` | Verbosity (show ports as found) |
| `--reason` | Show why port is classified open/closed |
| `-6` | IPv6 scanning |

## NSE Scripts

### Categories

```bash
# Safe default scripts (run always)
nmap -sC <target>

# Vulnerability detection (may be intrusive)
nmap --script=vuln <target>

# Specific service scripts
nmap --script=http-* -p 80,443 <target>
nmap --script=ftp-* -p 21 <target>
nmap --script=smb-* -p 445 <target>
nmap --script=ssl-* -p 443,8443 <target>
```

### High-Value Scripts by Service

```bash
# HTTP
nmap --script=http-title,http-server-header,http-methods,http-auth-finder -p 80,443,8080,8443 <target>

# HTTPS certificate info
nmap --script=ssl-cert,ssl-enum-ciphers -p 443 <target>

# SMB (Windows environments)
nmap --script=smb-vuln-ms17-010,smb-security-mode,smb-enum-shares -p 445 <target>

# SSH
nmap --script=ssh-auth-methods,ssh-hostkey -p 22 <target>

# FTP
nmap --script=ftp-anon,ftp-bounce -p 21 <target>

# DNS
nmap --script=dns-zone-transfer,dns-recursion -p 53 <target>

# MySQL / PostgreSQL
nmap --script=mysql-info,mysql-empty-password -p 3306 <target>
nmap --script=pgsql-brute -p 5432 <target>
```

## Output Parsing

### Extract open ports for follow-up tools

```bash
# Get comma-separated open ports from nmap output
grep "^[0-9]" ports.txt | awk -F/ '{print $1}' | tr '\n' ',' | sed 's/,$//'

# Use with httpx for HTTP probing
nmap -sS -p- --open -T4 <target> -oG - | grep "open" | awk '{print $2}' | xargs -I{} httpx -u {}
```

### Read XML output programmatically

```bash
# Parse XML for service data
python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('deep_scan.xml')
for host in tree.findall('.//host'):
    for port in host.findall('.//port'):
        state = port.find('state').get('state')
        if state == 'open':
            portid = port.get('portid')
            service = port.find('service')
            print(f'{portid}: {service.get(\"name\",\"unknown\")} {service.get(\"version\",\"\")}')
"
```

## Common Scenarios

### Web application target

```bash
# Find all HTTP/HTTPS ports
nmap -sV -p 80,443,8000,8080,8443,8888,9000,9090,3000,5000 --open <target>
```

### Internal network sweep

```bash
# Discover live hosts first, then scan
nmap -sn 192.168.1.0/24 -oG hosts.txt
grep "Up" hosts.txt | awk '{print $2}' > live_hosts.txt
nmap -iL live_hosts.txt -sV --top-ports 1000 -T4 -oA network_scan
```

### API and microservices target

```bash
# Common API and service ports
nmap -sV -p 80,443,3000,4000,5000,8000,8080,8443,8888,9000,9090,10080 <target>
```

## Timing and Performance

- **T4** is the standard choice for most scans. Fast enough without triggering basic rate limiting.
- **T3** (default) is slower but less likely to miss results on unstable networks.
- Use `--min-rate 500` to guarantee throughput regardless of timing template.
- Avoid **T5** on production targets -- causes packet loss and missed ports.
- For IDS evasion, use **T1** or **T2** with `-f` (packet fragmentation).

## Validation

1. Confirm open ports by connecting directly: `nc -zv <target> <port>` or `curl -I http://<target>:<port>`
2. Cross-check version info with banner grabbing: `nc <target> <port>` and observe response
3. For `filtered` ports, try from different source IPs or use `--scan-delay` to bypass rate limits
4. Verify NSE findings with manual requests before reporting as confirmed vulnerabilities

## False Positives

- **Filtered does not mean closed** -- firewall may be dropping packets; retry with `--scan-delay 1s`
- **Version detection can be wrong** -- services may report misleading banners; validate manually
- **vuln scripts produce false positives** -- always verify script findings with targeted manual testing
- **OS detection is unreliable** behind load balancers, NAT, or containers

## Chaining with Other Tools

```bash
# Nmap -> httpx: probe discovered HTTP ports
nmap -p- --open -oG - <target> | grep open | awk -F/ '{print $1}' | \
  xargs -I{} echo "http://<target>:{}" | httpx -status-code -title

# Nmap -> nuclei: scan discovered services
nmap -sV -p 80,443 -oX scan.xml <target>
nuclei -target <target> -tags http,ssl -severity medium,high,critical
```

## Pro Tips

1. Always run a fast all-port scan first, then deep-scan only the open ports
2. Use `-oA` to save all output formats -- XML is machine-readable for later parsing
3. `--script=vuln` is slow and noisy -- reserve for confirmed interesting services
4. For web targets, nmap port discovery + httpx tech detection beats `nmap -A` alone
5. Containers and cloud instances often have only 1-3 open ports -- skip `--top-ports` and scan `-p-`
6. Use `--reason` when debugging unexpected `filtered` results to understand firewall behavior
