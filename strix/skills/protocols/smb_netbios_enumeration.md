---
name: smb-netbios-enumeration
description: SMB/NetBIOS enumeration covering null sessions, share discovery, user enumeration, and known protocol vulnerabilities (e.g., EternalBlue, SMBGhost)
---

# SMB/NetBIOS Enumeration

Server Message Block (SMB) and NetBIOS are critical attack surfaces on Windows networks (and Samba on *nix). Misconfigured SMB can expose file shares, user lists, password policies, and domain information. Vulnerable SMB versions (SMBv1) or unpatched SMBv3 implementations can lead to unauthenticated remote code execution.

## Attack Surface

**Scope**
- TCP 445 (Direct SMB over TCP)
- TCP 139 (SMB over NetBIOS)
- UDP 137 (NetBIOS Name Service)
- UDP 138 (NetBIOS Datagram Service)

**What to Test**
- Authentication requirements (Null session, Guest access)
- Share permissions (Read/Write access on IPC$, C$, ADMIN$, custom shares)
- Information disclosure (Users, groups, domain info, password policies)
- Vulnerability to known RCE/DoS flaws (MS17-010, CVE-2020-0796)
- Message signing configuration (SMB relay susceptibility)

## Key Vulnerabilities

### Null Sessions and Guest Access

**Anonymous Enumeration**
Historically, Windows allowed "Null Sessions" (anonymous access without credentials) to IPC$. This permits enumeration of users, groups, shares, and password policies. While restricted in modern Windows versions by default, misconfigurations or legacy systems still exhibit this.

**Guest Access**
The built-in Guest account might be enabled and have access to shares, leading to sensitive data exposure.

### Protocol Vulnerabilities

| Vuln | CVE | Description | Test |
|------|-----|-------------|------|
| EternalBlue | MS17-010 / CVE-2017-0144 | RCE in SMBv1. Exploited widely (WannaCry). | `nmap --script smb-vuln-ms17-010 -p 445 <host>` |
| SMBGhost / CoronaBlue | CVE-2020-0796 | RCE/DoS in SMBv3.1.1 compression. | `nmap --script smb-vuln-cve-2020-0796 -p 445 <host>` |
| SMBleed | CVE-2020-1206 | Information disclosure in SMBv3.1.1 decompression. | Often tested alongside SMBGhost. |

### SMB Message Signing

**SMB Relay Attacks**
If SMB signing is not required (`Message signing enabled but not required`), the server is vulnerable to SMB relay attacks. An attacker can intercept NTLM authentication traffic and relay it to the server to gain unauthorized access.

## Testing Methodology

### 1. Protocol and Configuration Check

```bash
# General SMB discovery and signing check
nmap -n -Pn -p 139,445 --script smb-os-discovery,smb-security-mode <host>
```

### 2. Null Session and Share Enumeration

```bash
# Using smbclient (anonymous)
smbclient -N -L //<host>

# Using enum4linux (comprehensive enumeration)
enum4linux -a <host>

# Using nmap for shares
nmap -n -Pn -p 445 --script smb-enum-shares <host>
```

### 3. Vulnerability Scanning

```bash
# Check for known SMB vulnerabilities
nmap -n -Pn -p 445 --script "smb-vuln-*" <host>
```

## Validation

1. **Demonstrate Access** — Show the output of an anonymous/guest connection listing shares or reading a file.
2. **Prove Enumeration** — Extract valid usernames or password policy details using a null session.
3. **Confirm Vulnerabilities** — Run specific vulnerability checks (e.g., MS17-010) and verify the output indicates vulnerability.

## False Positives

- **Firewall Filtering** — Ports appear open, but deep inspection or scripts fail due to intermediate firewalls.
- **SMB Signing "Enabled"** — The service might support signing, but if it's not *required*, it's still vulnerable to relay. Pay attention to the exact wording.
- **Honeypots** — Deliberately vulnerable-looking SMB services that trap scanners.

## CVSS Context

| Finding | Typical CVSS | Rationale |
|---------|-------------|-----------|
| EternalBlue (MS17-010) | 9.3 (Critical) | Remote Code Execution |
| SMBGhost (CVE-2020-0796) | 10.0 (Critical) | Remote Code Execution |
| Anonymous Share Access (Read/Write) | 7.5 - 9.0 (High/Critical) | Data exposure or modification depending on share content |
| Null Session User Enumeration | 5.3 (Medium) | Information disclosure aiding further attacks |
| SMB Signing Not Required | 5.3 (Medium) | Enables relay attacks, requiring adjacent network position |

## Pro Tips

1. When testing shares, look for configuration files, backups, and scripts that might contain hardcoded credentials.
2. `IPC$` is for inter-process communication; you can't typically browse files on it, but it's used for enumeration.
3. If anonymous access fails, always test with any valid credentials you've obtained, no matter how low-privileged.

## Tooling

- **nmap** — Essential for discovery and vulnerability checks (`smb-os-discovery`, `smb-enum-shares`, `smb-vuln-*`).
- **smbclient** — Command-line SMB client, excellent for testing connectivity and manual browsing.
- **enum4linux** — Comprehensive tool for extracting information from Windows and Samba hosts.
- **CrackMapExec / NetExec** — Advanced post-exploitation and enumeration tools (if available in the environment).
