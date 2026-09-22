---
name: sharepoint
description: SharePoint (on-prem and Online) security testing covering ViewState-chain RCE patterns, REST/API over-exposure, and sharing-link/OAuth app-token abuse
---

# SharePoint

SharePoint on-prem inherits ASP.NET's full deserialization risk surface (see `aspnet`) plus its own history of unauthenticated pre-auth RCE chains through `_layouts` administrative pages. SharePoint Online trades that for a different problem: REST/API over-exposure and OAuth app-only tokens with broader Graph/SharePoint permissions than the app actually needs. Establish which flavor you're facing before choosing an attack path.

## Attack Surface

**On-premises**
- `_layouts/15/` (or `/16/`) administrative and utility pages, `_vti_bin/` web services (SOAP/REST)
- ASP.NET Web Forms underneath — full ViewState surface applies (see `aspnet` skill)
- `_api/` REST endpoint (SharePoint's OData-flavored API), Central Administration site

**SharePoint Online (Microsoft 365)**
- `_api/` REST + Microsoft Graph (`sites.read.all`/`sites.readwrite.all` app permissions)
- Sharing links (anyone/organization/specific-people), site-collection/list-item permission inheritance
- SharePoint Framework (SPFx) web parts, Power Automate flows triggered from SharePoint events
- App-only OAuth (Azure AD app registrations granted SharePoint API permissions)

## Reconnaissance

**Version/flavor fingerprint**
```
GET /_layouts/15/start.aspx
GET /_vti_bin/sites.asmx
GET /_api/web
```
`X-SharePointHealthScore`, `MicrosoftSharePointTeamServices` header, and the exact `_layouts/15` vs `_layouts/16` path reveal on-prem version generation; SharePoint Online responds from `*.sharepoint.com` with different header fingerprints (`SPRequestGuid`, `X-MSEdge-Ref`).

**Endpoint enumeration**
```
GET /_api/web/lists
GET /_api/web/siteusers
GET /_api/web/webinfos
GET /_layouts/15/viewlsts.aspx   # list of all lists/libraries, on-prem admin-facing but sometimes reachable
```

**Site-collection/permission mapping**
- `GET /_api/web/roleassignments` — enumerate who has what permission at the site level
- Sharing-link enumeration via `_api/web/GetFileByServerRelativeUrl(...)/ListItemAllFields` and associated sharing metadata

## Key Vulnerabilities

### On-prem unauthenticated RCE chain pattern

SharePoint's historical high-severity CVEs share a common shape: an unauthenticated (or low-privilege) request to a `_layouts` administrative page (a well-known example class is the ToolPane/webpart-property-deserialization pattern) reaches an ASP.NET Web Forms control that deserializes a crafted property value, chaining into the same `ObjectStateFormatter`/`LosFormatter` gadget primitives covered in `aspnet`. **Do not attempt to reproduce a specific weaponized public exploit blind** — instead:
1. Fingerprint the exact SharePoint build/patch level (`_layouts/15/config.aspx` or `/_vti_pvt/aspx.aspx` version strings, or authenticated `Central Administration` → Servers in Farm).
2. Cross-reference against SharePoint's published Security Update Guide / CVE advisories for that exact build.
3. Confirm the specific patch is genuinely missing before treating the chain as live — these are high-impact, well-known CVEs and patch cadence varies widely across enterprise on-prem farms.

### `_api`/REST endpoint enumeration and over-exposure

- Anonymous access enabled at the web-application level (a legacy on-prem config) exposing `_api/web/lists` and list contents without authentication.
- REST endpoints returning more fields than the UI displays — `_api/web/lists/getbytitle('Users')/items` on a list intended for internal HR data, reachable by any authenticated user regardless of intended list-level permissions if inheritance was broken incorrectly.
- `$select`/`$expand` OData query parameters traversing relationships beyond what the endpoint author intended — SharePoint's REST API is OData-based, so the same over-fetch patterns from `graphql`/OData skills apply.

### Sharing-link and permission-inheritance bugs

- "Anyone" sharing links (no auth required, just possession of the link) created for a document and never revoked — check for such links leaked via search-engine indexing, browser history, or shared chat logs.
- Permission-inheritance breaks: a list item given unique (non-inherited) permissions that are *broader* than the parent list — common misconfiguration when "share with specific people" is used carelessly, granting access company-wide instead.
- Site-collection admin escalation via a misconfigured "Owners" group that inherited membership from an overly broad AD/Entra group.

### SharePoint Online OAuth app-only token abuse

- Azure AD app registrations granted `Sites.FullControl.All` or `Sites.ReadWrite.All` at the tenant level when the app only needs access to one site collection — a compromised app secret grants far more than intended.
- App-only tokens (client-credentials flow) don't carry user context — actions taken with them bypass any per-user conditional-access or sharing restriction, making a leaked app secret a bigger win than a compromised individual user account in many tenants.
- Legacy ACS (Azure ACS)-based SharePoint add-in model, if still enabled, has its own weaker token-validation history — check whether the tenant still has "SharePoint Add-ins" / ACS principals registered (`_layouts/15/appinv.aspx` on-prem, or Microsoft's ACS deprecation-migration status for Online).

### `_layouts/15/` admin-page enumeration

Even without a working exploit chain, enumerate `_layouts/15/*.aspx` for pages that should require Central Admin/site-collection-admin rights but respond (even with a redirect-to-login) differently than a genuinely nonexistent page — this fingerprints exact functionality present on the farm and narrows which CVE classes are worth checking.

## Testing Methodology

1. **Fingerprint flavor and exact build** — on-prem vs Online, precise version/patch level via config/version-string pages.
2. **If on-prem** — cross-reference build against published SharePoint CVE advisories before attempting any deserialization chain; treat `aspnet`'s ViewState methodology as directly applicable to any Web-Forms-backed page found.
3. **REST/API sweep** — enumerate `_api/web/lists`, `siteusers`, `roleassignments`; test anonymous access and cross-list-permission consistency.
4. **Sharing-link audit** — search for indexed/leaked "Anyone" links; check permission-inheritance breaks on sensitive lists/libraries.
5. **OAuth app registration review (Online, white-box/tenant-admin context)** — enumerate app permissions granted vs actually used; flag tenant-wide grants for single-site-scoped apps.

## Validation

1. RCE chain: only after confirming the exact unpatched build via version fingerprint — demonstrate with command output or an out-of-band callback, referencing the specific CVE advisory matched.
2. REST over-exposure: show the actual data returned to an under-privileged/anonymous principal that the intended permission model should have blocked.
3. Sharing-link/OAuth abuse: demonstrate access to content via the leaked link or app token that the legitimate permission model (UI-visible sharing state) does not show as intended.

## False Positives

- Farm is fully patched to the latest cumulative update — treat any deserialization-chain finding as informational/patch-verification only, not exploitable.
- REST endpoint requires authentication and correctly enforces list-level permissions per authenticated principal tested.
- "Anyone" links found are already expired/revoked (test link liveness, not just discovery).
- App-only OAuth grant, while broad in scope, is confirmed to be intentional per the tenant's documented app inventory (verify with the engagement point of contact rather than assuming).

## Impact

- Unauthenticated RCE and full farm compromise via unpatched on-prem deserialization chains.
- Company-wide document/data exposure via anonymous REST access or permission-inheritance misconfiguration.
- Tenant-wide SharePoint/Graph data access via compromised over-scoped app-only OAuth credentials.
- Persistent unauthorized access via un-revoked "Anyone" sharing links.

## Pro Tips

1. Always confirm exact patch level before attempting any RCE chain — SharePoint's public CVEs are well-documented and patch-dependent; an unpatched claim without version evidence isn't credible.
2. `_api` REST responses often leak more fields than the SharePoint UI ever displays — always diff API response fields against UI-visible fields.
3. App-only OAuth tokens matter more than they look in Online tenants — no per-user conditional access applies to them.
4. Pair with `aspnet` for the on-prem deserialization/ViewState methodology and `oauth`/`azure` for the Online app-registration and Graph-permission layer.

## Summary

SharePoint splits cleanly into two risk profiles: on-prem inherits ASP.NET's deserialization RCE surface and lives or dies on patch cadence, while Online shifts risk to REST/API over-exposure, sharing-link hygiene, and OAuth app-only permission scope. Fingerprint the flavor and exact version first — it determines whether you're chasing a known CVE chain or an access-control/OAuth-scope review.
