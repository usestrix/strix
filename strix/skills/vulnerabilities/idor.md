---
name: idor
description: IDOR/BOLA testing for object-level authorization failures and cross-account data access
---

# IDOR

Object-level authorization failures (BOLA/IDOR) lead to cross-account data exposure and unauthorized state changes across APIs, web, mobile, and microservices. Treat every object reference as untrusted until proven bound to the caller.

## Attack Surface

**Scope**
- Horizontal access: access another subject's objects of the same type
- Vertical access: access privileged objects/actions (admin-only, staff-only)
- Cross-tenant access: break isolation boundaries in multi-tenant systems
- Cross-service access: token or context accepted by the wrong service

**Reference Locations**
- Paths, query params, JSON bodies, form-data, headers, cookies
- JWT claims, GraphQL arguments, WebSocket messages, gRPC messages

**Identifier Forms**
- Integers, UUID/ULID/CUID, Snowflake, slugs
- Composite keys (e.g., `{orgId}:{userId}`)
- Opaque tokens, base64/hex-encoded blobs

**Relationship References**
- parentId, ownerId, accountId, tenantId, organization, teamId, projectId, subscriptionId

**Expansion/Projection Knobs**
- `fields`, `include`, `expand`, `projection`, `with`, `select`, `populate`
- Often bypass authorization in resolvers or serializers

## High-Value Targets

- Exports/backups/reporting endpoints (CSV/PDF/ZIP)
- Messaging/mailbox/notifications, audit logs, activity feeds
- Billing: invoices, payment methods, transactions, credits
- Healthcare/education records, HR documents, PII/PHI/PCI
- Admin/staff tools, impersonation/session management
- File/object storage keys (S3/GCS signed URLs, share links)
- Background jobs: import/export job IDs, task results
- Multi-tenant resources: organizations, workspaces, projects

## Reconnaissance

**Parameter Analysis**
- Pagination/cursors: `page[offset]`, `page[limit]`, `cursor`, `nextPageToken` (often reveal or accept cross-tenant/state)
- Directory/list endpoints as seeders: search/list/suggest/export often leak object IDs for secondary exploitation
- Find undocumented params with `arjun -u <url>` (GET) or `arjun -u <url> -m POST` —
  surfaces hidden filters like `?include_deleted=1`, `?as_user=…`, `?owner_id=…`
  that frequently widen the IDOR surface.

**Enumeration Techniques**
- Alternate types: `{"id":123}` vs `{"id":"123"}`, arrays vs scalars, objects vs scalars
- Edge values: null/empty/0/-1/MAX_INT, scientific notation, overflows
- Duplicate keys/parameter pollution: `id=1&id=2`, JSON duplicate keys `{"id":1,"id":2}` (parser precedence)
- Case/aliasing: userId vs userid vs USER_ID; alt names like resourceId, targetId, account
- Path traversal-like in virtual file systems: `/files/user_123/../../user_456/report.csv`

**UUID/Opaque ID Sources**
- Logs, exports, JS bundles, analytics endpoints, emails, public activity
- Time-based IDs (UUIDv1, ULID) may be guessable within a window

## Key Vulnerabilities

### Horizontal & Vertical Access

- Swap object IDs between principals using the same token to probe horizontal access
- Repeat with lower-privilege tokens to probe vertical access
- Target partial updates (PATCH, JSON Patch/JSON Merge Patch) for silent unauthorized modifications

### Bulk & Batch Operations

- Batch endpoints (bulk update/delete) often validate only the first element; include cross-tenant IDs mid-array
- CSV/JSON imports referencing foreign object IDs (ownerId, orgId) may bypass create-time checks

### Secondary IDOR

- Use list/search endpoints, notifications, emails, webhooks, and client logs to collect valid IDs
- Fetch or mutate those objects directly
- Pagination/cursor manipulation to skip filters and pull other users' pages

### Job/Task Objects

- Access job/task IDs from one user to retrieve results for another (`export/{jobId}/download`, `reports/{taskId}`)
- Cancel/approve someone else's jobs by referencing their task IDs

### File/Object Storage

- Direct object paths or weakly scoped signed URLs
- Attempt key prefix changes, content-disposition tricks, or stale signatures reused across tenants
- Replace share tokens with tokens from other tenants; try case/URL-encoding variations

### GraphQL

- Enforce resolver-level checks: do not rely on a top-level gate
- Verify field and edge resolvers bind the resource to the caller on every hop
- Abuse batching/aliases to retrieve multiple users' nodes in one request
- Global node patterns (Relay): decode base64 IDs and swap raw IDs
- Overfetching via fragments on privileged types

```graphql
query IDOR {
  me { id }
  u1: user(id: "VXNlcjo0NTY=") { email billing { last4 } }
  u2: node(id: "VXNlcjo0NTc=") { ... on User { email } }
}
```

### Microservices & Gateways

- Token confusion: token scoped for Service A accepted by Service B due to shared JWT verification but missing audience/claims checks
- Trust on headers: reverse proxies or API gateways injecting/trusting headers like `X-User-Id`, `X-Organization-Id`; try overriding or removing them
- Context loss: async consumers (queues, workers) re-process requests without re-checking authorization

### Multi-Tenant

- Probe tenant scoping through headers, subdomains, and path params (`X-Tenant-ID`, org slug)
- Try mixing org of token with resource from another org
- Test cross-tenant reports/analytics rollups and admin views which aggregate multiple tenants

### WebSocket

- Authorization per-subscription: ensure channel/topic names cannot be guessed (`user_{id}`, `org_{id}`)
- Subscribe/publish checks must run server-side, not only at handshake
- Try sending messages with target user IDs after subscribing to own channels

### gRPC

- Direct protobuf fields (`owner_id`, `tenant_id`) often bypass HTTP-layer middleware
- Validate references via grpcurl with tokens from different principals

### Integrations

- Webhooks/callbacks referencing foreign objects (e.g., `invoice_id`) processed without verifying ownership
- Third-party importers syncing data into wrong tenant due to missing tenant binding

## Bypass Techniques

**Parser & Transport**
- Content-type switching: `application/json` ↔ `application/x-www-form-urlencoded` ↔ `multipart/form-data`
- Method tunneling: `X-HTTP-Method-Override`, `_method=PATCH`; or using GET on endpoints incorrectly accepting state changes
- JSON duplicate keys/array injection to bypass naive validators

**Parameter Pollution**
- Duplicate parameters in query/body to influence server-side precedence (`id=123&id=456`); try both orderings
- Mix case/alias param names so gateway and backend disagree (userId vs userid)

**Cache & Gateway**
- CDN/proxy key confusion: responses keyed without Authorization or tenant headers expose cached objects to other users
- Manipulate Vary and Accept headers
- Redirect chains and 304/206 behaviors can leak content across tenants

**Race Windows**
- Time-of-check vs time-of-use: change the referenced ID between validation and execution using parallel requests

**Blind Channels**
- Use differential responses (status, size, ETag, timing) to detect existence
- Error shape often differs for owned vs foreign objects
- HEAD/OPTIONS, conditional requests (`If-None-Match`/`If-Modified-Since`) can confirm existence without full content

## Chaining Attacks

- IDOR + CSRF: force victims to trigger unauthorized changes on objects you discovered
- IDOR + Stored XSS: pivot into other users' sessions through data you gained access to
- IDOR + SSRF: exfiltrate internal IDs, then access their corresponding resources
- IDOR + Race: bypass spot checks with simultaneous requests

## Testing Methodology

1. **Build matrix** - Subject × Object × Action matrix (who can do what to which resource)
2. **Obtain principals** - At least two: owner and non-owner (plus admin/staff if applicable)
3. **Collect IDs** - Capture at least one valid object ID per principal from list/search/export endpoints
4. **Cross-channel testing** - Exercise every action (R/W/D/Export) while swapping IDs, tokens, tenants
5. **Transport variation** - Test across web, mobile, API, GraphQL, WebSocket, gRPC
6. **Consistency check** - Same rule must hold regardless of transport, content-type, serialization, or gateway

## Validation

1. Demonstrate access to an object not owned by the caller (content or metadata)
2. Show the same request fails with appropriately enforced authorization when corrected
3. Prove cross-channel consistency: same unauthorized access via at least two transports (e.g., REST and GraphQL)
4. Document tenant boundary violations (if applicable)
5. Provide reproducible steps and evidence (requests/responses for owner vs non-owner)

## False Positives

- Public/anonymous resources by design
- Soft-privatized data where content is already public
- Idempotent metadata lookups that do not reveal sensitive content
- Correct row-level checks enforced across all channels
- Empty array / null returned for another user's resource — silent enforcement, not exposure; compare against the owner's view to confirm the data is actually missing rather than just hidden from the response shape

## Impact

- Cross-account data exposure (PII/PHI/PCI)
- Unauthorized state changes (transfers, role changes, cancellations)
- Cross-tenant data leaks violating contractual and regulatory boundaries
- Regulatory risk (GDPR/HIPAA/PCI), fraud, reputational damage

## Pro Tips

1. Always test list/search/export endpoints first; they are rich ID seeders
2. Build a reusable ID corpus from logs, notifications, emails, and client bundles
3. Toggle content-types and transports; authorization middleware often differs per stack
4. In GraphQL, validate at resolver boundaries; never trust parent auth to cover children
5. In multi-tenant apps, vary org headers, subdomains, and path params independently
6. Check batch/bulk operations and background job endpoints; they frequently skip per-item checks
7. Inspect gateways for header trust and cache key configuration
8. Treat UUIDs as untrusted; obtain them via OSINT/leaks and test binding
9. Use timing/size/ETag differentials for blind confirmation when content is masked
10. Prove impact with precise before/after diffs and role-separated evidence

## Harvesting Unguessable IDs

When an object reference is a UUID/GUID or opaque token that can't be enumerated, the attack becomes *find the value*, then swap it. Leak-then-reuse beats brute force. Sources:

- **Archives / passive URL sets** — Wayback CDX (`web.archive.org/cdx/search/cdx?url=*.target.com/*&fl=original&collapse=urlkey`), AlienVault OTX url_list, URLScan search API, Common Crawl, VirusTotal domain report; aggregate with `waymore`/`waybackurls`/`gau`, then regex out UUIDs
- **Code / search** — GitHub (hardcoded IDs in requests/scripts), Google-indexed and cached pages
- **Request-side leaks** — `Referer` header forwarding an ID to third parties, browser history, HTTP/proxy/VPN/ISP logs
- **Predictability flaws** — "random" IDs built from `timestamp + machineID` (UUIDv1/ULID guessable within a window); leak an old UUID via archives, then brute sequentially around it
- **Fixed/default UUIDs** — admin/system rows on `00000000-0000-0000-0000-000000000000`, `11111111-...`
- **Other primitives** — clickjacking to lift an ID from the victim's context; a read-only/low-priv user who can *view* IDs they can't act on

## 403 / 401 Bypass

A `403`/`401` is often the only thing between you and the IDOR — treat it as a filter to defeat, not a dead end. And never trust the status: a `403` response can still perform the action (blind IDOR / side effect) — re-check state.

**Path/endpoint rediscovery** — the blocked path may be reachable by another route: fuzz siblings (`dirsearch`/content discovery), and pull historical paths from Wayback that may bypass a newer ACL.

**Auth-bypass headers** — many gateways/reverse proxies trust a forwarded header for source IP or the internal URL. Add one (value `127.0.0.1`, or the internal path) to spoof a trusted origin:
```
X-Original-URL: /admin        X-Rewrite-URL: /admin      X-Forwarded-For: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1   X-Forwarded-Host / X-Host / X-Real-IP / X-Originating-IP
X-Client-IP · X-Remote-IP · X-Remote-Addr · Client-IP · True-Client-IP · Base-Url · Referer
```
(`X-Original-URL`/`X-Rewrite-URL` against IIS/ASP.NET is especially high-yield — the app routes on the header *after* the front-end ACL matched the original path.)

**URL-mutation payloads** — front-end and back-end normalize the path differently; mutate it so the proxy sees an allowed path and the app sees the forbidden one. Technique classes (apply to `/admin`):
- Trailing tricks: `/admin/`, `/admin/.`, `/admin//`, `/admin/./`, `/./admin/..`, `/admin%20`, `/admin%09`, `/admin?`, `/admin#`, `/admin%00`
- Semicolon/param-path: `/admin;/`, `/admin/;/`, `/admin/;foo=bar`
- Encoded traversal & separators: `/%2e/admin`, `/admin%2f`, `%2f%2f`, `/admin/..;/`, `/..%2f..%2fadmin`, double-encoding (`%252e`, `%252f`)
- Case & extension: `/ADMIN`, `/Admin`, append `.json`/`.html`/`;.css` to hit a cache/route differential
- Method/version swaps: `GET`→`POST`/`PUT`/`HEAD`, `X-HTTP-Method-Override`, older API versions of the same endpoint

Automate the sweep with `bypass-403` / `4-ZERO-3` / `B1pass3r`, then confirm the winning mutation by hand.

## Summary

Authorization must bind subject, action, and specific object on every request, regardless of identifier opacity or transport. If the binding is missing anywhere, the system is vulnerable.
