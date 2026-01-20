# INSECURE DIRECT OBJECT REFERENCE (IDOR)

## Critical

Object- and function-level authorization failures (BOLA/IDOR) routinely lead to cross-account data exposure and unauthorized state changes across APIs, web, mobile, and microservices. Treat every object reference as untrusted until proven bound to the caller.

## Scope

- Horizontal access: access another subject's objects of the same type
- Vertical access: access privileged objects/actions (admin-only, staff-only)
- Cross-tenant access: break isolation boundaries in multi-tenant systems
- Cross-service access: token or context accepted by the wrong service

## Methodology

1. Build a Subject × Object × Action matrix (who can do what to which resource).
2. For each resource type, obtain at least two principals: owner and non-owner (plus admin/staff if applicable). Capture at least one valid object ID per principal.
3. Exercise every action (R/W/D/Export) while swapping IDs, tokens, tenants, and channels (web, mobile, API, GraphQL, WebSocket, gRPC).
4. Track consistency: the same rule must hold regardless of transport, content-type, serialization, or gateway.

## Discovery Techniques

### Parameter Analysis

- Object references appear in: paths, query params, JSON bodies, form-data, headers, cookies, JWT claims, GraphQL arguments, WebSocket messages, gRPC messages
- Identifier forms: integers, UUID/ULID/CUID, Snowflake, slugs, composite keys (e.g., {orgId}:{userId}), opaque tokens, base64/hex-encoded blobs
- Relationship references: parentId, ownerId, accountId, tenantId, organization, teamId, projectId, subscriptionId
- Expansion/projection knobs: fields, include, expand, projection, with, select, populate (often bypass authorization in resolvers or serializers)
- Pagination/cursors: page[offset], page[limit], cursor, nextPageToken (often reveal or accept cross-tenant/state)

### Advanced Enumeration

- Alternate types: `{"id":123}` vs `{"id":"123"}`, arrays vs scalars, objects vs scalars, null/empty/0/-1/MAX_INT, scientific notation, overflows, unknown attributes retained by backend
- Duplicate keys/parameter pollution: id=1&id=2, JSON duplicate keys `{"id":1,"id":2}` (parser precedence differences)
- Case/aliasing: userId vs userid vs USER_ID; alt names like resourceId, targetId, account
- Path traversal-like in virtual file systems: /files/user_123/../../user_456/report.csv
- Directory/list endpoints as seeders: search/list/suggest/export often leak object IDs for secondary exploitation

## High Value Targets

- Exports/backups/reporting endpoints (CSV/PDF/ZIP)
- Messaging/mailbox/notifications, audit logs, activity feeds
- Billing: invoices, payment methods, transactions, credits
- Healthcare/education records, HR documents, PII/PHI/PCI
- Admin/staff tools, impersonation/session management
- File/object storage keys (S3/GCS signed URLs, share links)
- Background jobs: import/export job IDs, task results
- Multi-tenant resources: organizations, workspaces, projects

## Exploitation Techniques

### Horizontal Vertical

- Swap object IDs between principals using the same token to probe horizontal access; then repeat with lower-privilege tokens to probe vertical access
- Target partial updates (PATCH, JSON Patch/JSON Merge Patch) for silent unauthorized modifications

### Bulk And Batch

- Batch endpoints (bulk update/delete) often validate only the first element; include cross-tenant IDs mid-array
- CSV/JSON imports referencing foreign object IDs (ownerId, orgId) may bypass create-time checks

### Secondary Idor

- Use list/search endpoints, notifications, emails, webhooks, and client logs to collect valid IDs, then fetch or mutate those objects directly
- Pagination/cursor manipulation to skip filters and pull other users' pages

### Job Task Objects

- Access job/task IDs from one user to retrieve results for another (export/{jobId}/download, reports/{taskId})
- Cancel/approve someone else's jobs by referencing their task IDs

### File Object Storage

- Direct object paths or weakly scoped signed URLs; attempt key prefix changes, content-disposition tricks, or stale signatures reused across tenants
- Replace share tokens with tokens from other tenants; try case/URL-encoding variations

## Advanced Techniques

### Graphql

- Enforce resolver-level checks: do not rely on a top-level gate. Verify field and edge resolvers bind the resource to the caller on every hop
- Abuse batching/aliases to retrieve multiple users' nodes in one request and compare responses
- Global node patterns (Relay): decode base64 IDs and swap raw IDs; test `node(id: "...base64..."){...}`
- Overfetching via fragments on privileged types; verify hidden fields cannot be queried by unprivileged callers
- Example:
```
query IDOR {
  me { id }
  u1: user(id: "VXNlcjo0NTY=") { email billing { last4 } }
  u2: node(id: "VXNlcjo0NTc=") { ... on User { email } }
}
```

### Microservices Gateways

- Token confusion: a token scoped for Service A accepted by Service B due to shared JWT verification but missing audience/claims checks
- Trust on headers: reverse proxies or API gateways injecting/trusting headers like X-User-Id, X-Organization-Id; try overriding or removing them
- Context loss: async consumers (queues, workers) re-process requests without re-checking authorization

### Multi Tenant

- Probe tenant scoping through headers, subdomains, and path params (e.g., X-Tenant-ID, org slug). Try mixing org of token with resource from another org
- Test cross-tenant reports/analytics rollups and admin views which aggregate multiple tenants

### Uuid And Opaque Ids

- UUID/ULID are not authorization: acquire valid IDs from logs, exports, JS bundles, analytics endpoints, emails, or public activity, then test ownership binding
- Time-based IDs (UUIDv1, ULID) may be guessable within a window; combine with leakage sources for targeted access

### Blind Channels

- Use differential responses (status, size, ETag, timing) to detect existence; error shape often differs for owned vs foreign objects
- HEAD/OPTIONS, conditional requests (If-None-Match/If-Modified-Since) can confirm existence without full content

## Bypass Techniques

### Parser And Transport

- Content-type switching: application/json ↔ application/x-www-form-urlencoded ↔ multipart/form-data; some paths enforce checks per parser
- Method tunneling: X-HTTP-Method-Override, _method=PATCH; or using GET on endpoints incorrectly accepting state changes
- JSON duplicate keys/array injection to bypass naive validators

### Parameter Pollution

- Duplicate parameters in query/body to influence server-side precedence (id=123&id=456); try both orderings
- Mix case/alias param names so gateway and backend disagree (userId vs userid)

### Cache And Gateway

- CDN/proxy key confusion: responses keyed without Authorization or tenant headers expose cached objects to other users; manipulate Vary and Accept
- Redirect chains and 304/206 behaviors can leak content across tenants

### Race Windows

- Time-of-check vs time-of-use: change the referenced ID between validation and execution using parallel requests

## Special Contexts

### Websocket

- Authorization per-subscription: ensure channel/topic names cannot be guessed (user_{id}, org_{id}); subscribe/publish checks must run server-side, not only at handshake
- Try sending messages with target user IDs after subscribing to own channels

### Grpc

- Direct protobuf fields (owner_id, tenant_id) often bypass HTTP-layer middleware; validate references via grpcurl with tokens from different principals

### Integrations

- Webhooks/callbacks referencing foreign objects (e.g., invoice_id) processed without verifying ownership
- Third-party importers syncing data into wrong tenant due to missing tenant binding

## Chaining Attacks

- IDOR + CSRF: force victims to trigger unauthorized changes on objects you discovered
- IDOR + Stored XSS: pivot into other users' sessions through data you gained access to
- IDOR + SSRF: exfiltrate internal IDs, then access their corresponding resources
- IDOR + Race: bypass spot checks with simultaneous requests

## Validation

1. Demonstrate access to an object not owned by the caller (content or metadata).
2. Show the same request fails with appropriately enforced authorization when corrected.
3. Prove cross-channel consistency: same unauthorized access via at least two transports (e.g., REST and GraphQL).
4. Document tenant boundary violations (if applicable).
5. Provide reproducible steps and evidence (requests/responses for owner vs non-owner).

## False Positives

- Public/anonymous resources by design
- Soft-privatized data where content is already public
- Idempotent metadata lookups that do not reveal sensitive content
- Correct row-level checks enforced across all channels

## Impact

- Cross-account data exposure (PII/PHI/PCI)
- Unauthorized state changes (transfers, role changes, cancellations)
- Cross-tenant data leaks violating contractual and regulatory boundaries
- Regulatory risk (GDPR/HIPAA/PCI), fraud, reputational damage

## Pro Tips

1. Always test list/search/export endpoints first; they are rich ID seeders.
2. Build a reusable ID corpus from logs, notifications, emails, and client bundles.
3. Toggle content-types and transports; authorization middleware often differs per stack.
4. In GraphQL, validate at resolver boundaries; never trust parent auth to cover children.
5. In multi-tenant apps, vary org headers, subdomains, and path params independently.
6. Check batch/bulk operations and background job endpoints; they frequently skip per-item checks.
7. Inspect gateways for header trust and cache key configuration.
8. Treat UUIDs as untrusted; obtain them via OSINT/leaks and test binding.
9. Use timing/size/ETag differentials for blind confirmation when content is masked.
10. Prove impact with precise before/after diffs and role-separated evidence.

## Remember

Authorization must bind subject, action, and specific object on every request, regardless of identifier opacity or transport. If the binding is missing anywhere, the system is vulnerable.
