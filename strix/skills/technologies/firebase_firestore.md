---
name: firebase-firestore
description: Firebase/Firestore security testing covering security rules, Cloud Functions, and client-side trust issues
---

# Firebase / Firestore

Security testing for Firebase applications. Focus on Firestore/Realtime Database rules, Cloud Storage exposure, callable/onRequest Functions trusting client input, and incorrect ID token validation.

## Attack Surface

**Data Stores**
- Firestore (documents/collections, rules, REST/SDK)
- Realtime Database (JSON tree, rules)
- Cloud Storage (rules, signed URLs)

**Authentication**
- Auth ID tokens, custom claims, anonymous/sign-in providers
- App Check attestation (and its limits)

**Server-Side**
- Cloud Functions (onCall/onRequest, triggers)
- Admin SDK (bypasses rules)

**Infrastructure**
- Hosting rewrites, CDN/caching, CORS

## Architecture

**Endpoints**
- Firestore REST: `https://firestore.googleapis.com/v1/projects/<project>/databases/(default)/documents/<path>`
- Realtime DB: `https://<project>.firebaseio.com/.json`
- Storage REST: `https://storage.googleapis.com/storage/v1/b/<bucket>`

**Auth**
- Google-signed ID tokens (iss: `accounts.google.com` or `securetoken.google.com/<project>`)
- Audience: `<project>` or `<app-id>`, identity in `sub`/`uid`
- Rules engines: separate for Firestore, Realtime DB, and Storage
- Functions bypass rules when using Admin SDK

## High-Value Targets

- Firestore collections with sensitive data (users, orders, payments)
- Realtime Database root and high-level nodes
- Cloud Storage buckets with private files
- Cloud Functions (especially triggers that grant roles or issue signed URLs)
- Admin/staff routes and privilege-granting endpoints
- Export/report functions that generate signed outputs

## Reconnaissance

**Extract Project Config**

From client bundle:
```javascript
// apiKey, authDomain, projectId, appId, storageBucket, messagingSenderId
firebase.apps[0].options
```

**Obtain Principals**
- Unauthenticated
- Anonymous (if enabled)
- Basic user A, user B
- Staff/admin (if available)

Capture ID tokens for each.

## Key Vulnerabilities

### Firestore Rules

Rules are not filters—a query must include constraints that make the rule true for all returned documents.

**Common Gaps**
- `allow read: if request.auth != null` — any authenticated user reads all data
- `allow write: if request.auth != null` — mass write access
- Missing per-field validation (allows adding `isAdmin`/`role`/`tenantId` fields)
- Using client-supplied `ownerId`/`orgId` instead of `resource.data.ownerId == request.auth.uid`
- Over-broad list rules on root collections (per-doc checks exist but list still leaks)

**Secure Patterns**
```javascript
// Restrict write fields
request.resource.data.keys().hasOnly(['field1', 'field2', 'field3'])

// Enforce ownership
resource.data.ownerId == request.auth.uid &&
request.resource.data.ownerId == request.auth.uid

// Org membership check
exists(/databases/(default)/documents/orgs/$(org)/members/$(request.auth.uid))
```

**Tests**
- Compare results for users A/B on identical queries; diff counts and IDs
- Cross-tenant reads: `where orgId == otherOrg`; try queries without org filter
- Write-path: set/patch with foreign `ownerId`/`orgId`; attempt to flip privilege flags

### Firestore Queries

- Use REST to avoid SDK client-side constraints
- Probe composite index requirements (UI-driven queries may hide missing rule coverage)
- Explore `collectionGroup` queries that may bypass per-collection rules
- Use `startAt`/`endAt`/`in`/`array-contains` to probe rule edges and pagination cursors

### Realtime Database

- Misconfigured rules frequently expose entire JSON trees
- Probe `https://<project>.firebaseio.com/.json` with and without auth
- Confirm rules use `auth.uid` and granular path checks
- Avoid `.read/.write: true` or `auth != null` at high-level nodes
- Attempt to write privilege-bearing nodes (roles, org membership)

### Cloud Storage

**Common Issues**
- Public reads on sensitive buckets/paths
- Signed URLs with long TTL, no content-disposition controls, replayable across tenants
- List operations exposed: `/o?prefix=` enumerates object keys

**Tests**
- GET gs:// paths via HTTPS without auth; verify Content-Type and `Content-Disposition: attachment`
- Generate and reuse signed URLs across accounts and paths; try case/URL-encoding variants
- Upload HTML/SVG and verify `X-Content-Type-Options: nosniff`; check for script execution

### Cloud Functions

`onCall` provides `context.auth` automatically; `onRequest` must verify ID tokens explicitly. Admin SDK bypasses rules—all ownership/tenant checks must be in code.

**Common Gaps**
- Trusting client `uid`/`orgId` from request body instead of `context.auth`
- Missing `aud`/`iss` verification when manually parsing tokens
- Over-broad CORS allowing credentialed cross-origin requests
- Triggers (onCreate/onWrite) granting roles based on document content controlled by client

**Tests**
- Call both onCall and onRequest endpoints with varied tokens; expect identical decisions
- Create crafted docs to trigger privilege-granting functions
- Attempt SSRF via Functions to project/metadata endpoints

### Auth & Token Issues

**Verification Requirements**
- Issuer, audience (project), signature (Google JWKS), expiration
- Optionally App Check binding when used

**Pitfalls**
- Accepting any JWT with valid signature but wrong audience/project
- Trusting `uid`/account IDs from request body instead of `context.auth.uid`
- Mixing session cookies and ID tokens without verifying both paths equivalently
- Custom claims copied into docs then trusted by app code

**Tests**
- Replay tokens across environments/projects; expect strict `aud`/`iss` rejection
- Call Functions with and without Authorization; verify identical checks

### App Check

App Check is not a substitute for authorization.

**Bypasses**
- REST calls directly to googleapis endpoints with ID token succeed regardless of App Check
- Mobile reverse engineering: hook client and reuse ID token flows without attestation

**Tests**
- Compare SDK vs REST behavior with/without App Check headers
- Confirm no elevated authorization via App Check alone

### Tenant Isolation

Apps often implement multi-tenant data models (`orgs/<orgId>/...`). Bind tenant from server context (membership doc or custom claim), not client payload.

**Tests**
- Vary org header/subdomain/query while keeping token fixed; verify server denies cross-tenant access
- Export/report Functions: ensure queries execute under caller scope

## Bypass Techniques

- Content-type switching: JSON vs form vs multipart to hit alternate code paths in onRequest
- Parameter/field pollution: duplicate JSON keys (last-one-wins in many parsers); sneak privilege fields
- Caching/CDN: Hosting rewrites keying responses without Authorization or tenant headers
- Race windows: write then read before background enforcements complete

## Blind Enumeration

- Firestore: use error shape, document count, ETag/length to infer existence
- Storage: length/timing differences on signed URL attempts leak validity
- Functions: constant-time comparisons vs variable messages reveal authorization branches

## Testing Methodology

1. **Extract config** - Get project config from client bundle
2. **Obtain principals** - Collect tokens for unauth, anonymous, user A/B, admin
3. **Build matrix** - Resource × Action × Principal across Firestore/Realtime/Storage/Functions
4. **SDK vs REST** - Exercise every action via both to detect parity gaps
5. **Seed IDs** - Start from list/query paths to gather document IDs
6. **Cross-principal** - Swap document paths, tenants, and user IDs across principals

## Tooling

- SDK + REST: httpie/curl + jq for REST; Firebase emulator and Rules Playground for rapid iteration
- Rules analysis: script probes for common patterns (`auth != null`, missing field validation)
- Functions: fuzz onRequest with varied content-types and missing/forged Authorization
- Storage: enumerate prefixes; test signed URL generation and reuse patterns

## Validation Requirements

- Owner vs non-owner Firestore queries showing unauthorized access or metadata leak
- Cloud Storage read/write beyond intended scope (public object, signed URL reuse, list exposure)
- Function accepting forged/foreign identity (wrong `aud`/`iss`) or trusting client `uid`/`orgId`
- Minimal reproducible requests with roles/tokens used and observed deltas
