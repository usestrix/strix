---
name: azure
description: Azure cloud security testing covering Entra ID, managed identity and IMDS abuse, anonymous storage, Key Vault, App Service, and privilege escalation paths
---

# Azure Cloud Security

Azure misconfigurations expose the same classes of findings as other clouds - anonymous storage, over-permissioned identities, and metadata/token abuse - with Azure-specific surfaces: Entra ID (Azure AD) tenants and app registrations, Managed Identities via IMDS, blob storage with SAS tokens, and App Service settings. For SSRF-mediated metadata access, combine with the `ssrf` skill.

## Attack Surface

**Identity**
- Entra ID (Azure AD): tenants, users, app registrations, service principals, conditional access, MFA gaps
- Managed identities (system/user-assigned) with tokens fetched from IMDS
- Azure AD tokens in apps (see `authentication_jwt`), OAuth flows, consent grants

**Storage & Data**
- Blob containers and files shares with anonymous access or leaked SAS tokens
- `$web` static hosting containers, backup containers, VM disk exports
- Key Vaults with over-permissive access policies; databases (SQL, Cosmos DB) with public endpoints

**Compute & Apps**
- VMs (IMDS at `169.254.169.254`), scale sets, App Service (env vars, slots, SSH), Functions, Logic Apps
- ARM templates and deployment scripts containing credentials
- Azure DevOps: pipelines, service connections, PATs, variable groups

**Management**
- Azure CLI/Graph API access from any compromised credential; subscription-level roles
- Public endpoints: App Service default domains, blob endpoints, Key Vault endpoints

## Reconnaissance

**Credential discovery**
- Environment variables: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_SUBSCRIPTION_ID`, `ARM_*`
- `.env`, CI variable groups, Key Vault references, ARM templates, App Service app settings
- Source code, mobile apps, JS bundles (Azure AD client IDs + redirect URIs)

**Tenant/user enumeration (unauthenticated)**
- `login.microsoftonline.com/{tenant}/.well-known/openid-configuration` confirms tenant
- User enumeration via login errors (existing vs nonexistent user) on apps using Entra ID
- `https://login.microsoftonline.com/getuserrealm?user=<email>` reveals tenant state

**Authenticated (any credential)**
```
az login --identity                                        # managed identity context
az account show
az ad signed-in-user show
az account list --query '[].{name:name,id:id}'
az role assignment list --include-inherited --include-groups
```

## Key Vulnerabilities

### IMDS and Managed Identity Abuse

IMDS requires the `Metadata: true` header (no token, unlike AWS IMDSv2):

```
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01"
```

**Managed identity token** (the crown jewel):

```
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com"
```

The returned `access_token` can call Azure Management, Graph (`https://graph.microsoft.com`), or Key Vault (`https://vault.azure.net`) depending on the identity's role assignments. From a compromised VM/App Service with SSRF or RCE, this is direct cloud access:

```
curl -s -H "Authorization: Bearer <token>" "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

### Anonymous Blob Storage

Container-level public access (blob or container level) enables anonymous reads:

```
curl -s "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list"
curl -s "https://<account>.blob.core.windows.net/<container>/<blob>"
```

Container names are often guessable from app patterns (`backups`, `logs`, `uploads`, `$web`, `<app>-data`); enumerate candidates. `$web` hosting containers expose the app's static assets (and sometimes source maps/`.env`).

### Leaked SAS Tokens

Shared Access Signature tokens appear in URLs (Azure Storage URLs, exports, emails, logs):

```
https://<account>.blob.core.windows.net/<container>/<blob>?sv=...&st=...&se=...&sp=rw&sig=...
```

Inspect `sp` (permissions: r/w/d/l), `se` (expiry), and `sr` (resource scope). A token found in a log/email with `sp=rwdl` and long expiry is a finding; service SAS tokens with account-level keys grant broader scope. Test the token against the container listing and adjacent resources.

### Entra ID App Misconfiguration

- App registrations with `redirect_uris` allowing attacker origins (see `oauth`, `keycloak`)
- Public client (mobile/desktop) apps with client secrets in bundles
- `user_impersonation`/delegated permission grants too broad; consent phishing via apps requesting high-impact scopes
- Service principals with Contributor/Owner over subscriptions or high-value resource groups
- Conditional Access gaps: legacy auth enabled, MFA not enforced for admins

### Key Vault Exposure

- Access policies granting read to low-priv identities (or `az keyvault` from a compromised MSI)
- Secrets in Key Vault referenced by App Service/Function settings - the vault is the credential store
- Soft-delete/purge-protection gaps allowing secret recovery after deletion

```
az keyvault secret list --vault-name <vault> --query '[].name'
az keyvault secret show --vault-name <vault> --name <secret>
```

### App Service / Functions

- App settings (`APPSETTING_*`) leak connection strings, keys, Key Vault references
- Public source control/deployment slots exposing env configs
- SSH/console access (`https://<app>.scm.azurewebsites.net`) when enabled
- Function app keys (`_master`) in configs or client bundles -> invoke admin functions
- Outdated runtimes with known CVEs

### Privilege Escalation

Common Azure escalation paths:

| Permission | Escalation |
|------------|------------|
| `Microsoft.Authorization/roleAssignments/write` | Grant yourself Owner/Contributor |
| `Microsoft.KeyVault/vaults/write` + access policy | Read all secrets |
| `Microsoft.Compute/virtualMachines/write` | Modify VM extensions to run commands |
| `Microsoft.Web/sites/config/write` | Change App Service app settings/connection strings |
| `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` | Assign an MSI to a resource you control |
| `Microsoft.Automation/automationAccounts/...` | Runbook execution |
| `Microsoft.ContainerService/managedClusters/...` | AKS admin credentials |

## Advanced Techniques

- **MSI token -> Graph**: request a token for `https://graph.microsoft.com` and enumerate users/groups/apps with the identity's grants
- **VM extension abuse**: with VM write access, run a custom script extension that dumps env/IMDS tokens
- **App Service env dump**: `https://<app>.scm.azurewebsites.net/api/settings` (needs auth) or source-controlled appsettings files
- **Storage account key recovery**: with Contributor over the storage account, list account keys and mint service SAS tokens at will
- **Disk export**: export a VM's OS disk to a storage account and mount/parse it for credentials
- **Azure DevOps**: leaked PATs -> pipelines, service connections (cloud creds), variable groups

## Testing Methodology

1. Discover credentials (env, source, configs, MSI) and confirm the principal (`az account show`/Graph)
2. Enumerate role assignments and effective permissions
3. Test anonymous blob access and hunt leaked SAS tokens
4. Probe IMDS (with header) for instance metadata and MSI tokens
5. Enumerate Key Vaults, App Services, and their settings
6. Map escalation paths from the role assignments
7. Validate with minimal, reversible access proofs (list, not exfiltrate)

## Validation

1. IMDS/MSI: show the metadata response and the token's scopes/resource; list subscriptions/vaults the identity can reach
2. Blob: show an anonymous container listing and a sample of sensitive objects (redacted)
3. SAS: demonstrate the token's permissions against the target container
4. Key Vault: show the vault's secret names and read one benign/test secret (or document the access)
5. Escalation: show the exact API call and the resulting permission change (reversible where possible)

## False Positives

- Metadata endpoint unreachable (no SSRF/RCE, or IMDS blocked by hop limits/firewall)
- Anonymous blob read on a container of public static assets (intended public content)
- MSI token valid but identity has no interesting role assignments (limited impact)
- SAS token expired or scoped read-only to a non-sensitive blob
- App Service settings visible only to authenticated admins (not exposed)
- 403 vs 404 on blob endpoints: 403 means the container exists but denies anonymous access - a recon note, not a breach

## Impact

- Cloud account compromise via managed identity/credential theft
- Mass data exposure from anonymous storage and leaked SAS tokens
- Secret theft from Key Vault with downstream lateral movement
- Subscription-wide takeover via role-assignment escalation

## Pro Tips

1. IMDS is one header away: always try `Metadata: true` with the token endpoint from any SSRF/RCE in Azure
2. Managed identity tokens are scoped to a `resource` - request tokens for `management.azure.com`, `graph.microsoft.com`, and `vault.azure.net` to map what the identity can do
3. Blob 403 vs 404 tells you container existence; enumerate container names from app patterns when you can't list
4. Hunt SAS tokens in logs/URLs/emails - `sp=rwdl` with long `se` is a real finding
5. `az` CLI and Graph API (`curl -H "Authorization: Bearer <token>" https://graph.microsoft.com/v1.0/me`) cover most enumeration; MicroBurst/Stormspotter automate the escalation mapping when installed
6. Pair with `ssrf`, `authentication_jwt`, `oauth`, and `exposed_databases` skills

## Summary

Azure attacks start from a credential or a metadata endpoint: identify the principal, map role assignments, then exploit anonymous storage, SAS leaks, Key Vault access, and MSI tokens. IMDS + managed identity is the highest-yield path - prove token scopes and stop at listing-level evidence.
