---
name: firebase
description: Firebase security testing covering Firestore, Storage rules, Realtime Database, Auth, Functions, and client-side trust issues
---

# Firebase

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
- GCS JSON API: `https://storage.googleapis.com/storage/v1/b/<bucket>`
- Firebase Storage rules API: `https://firebasestorage.googleapis.com/v0/b/<bucket>/o`

Cloud Storage has two front doors with different authorization engines:

| Front door | Authorization engine |
| --- | --- |
| `storage.googleapis.com/<bucket>/<object>` and `/storage/v1/b/<bucket>` | GCS IAM and per-object ACLs |
| `firebasestorage.googleapis.com/v0/b/<bucket>/o` | Firebase Storage Security Rules |

A `403` from a GCS URL does not prove that Firebase Storage rules deny access. Always test both doors.

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
- Firebase Storage rules allowing unauthenticated or overly broad reads and writes

**Firebase Storage rules checks**

Probe the rules door separately from GCS IAM and ACLs:

1. Unauthenticated list: `GET https://firebasestorage.googleapis.com/v0/b/<bucket>/o?prefix=<known-prefix>`
2. Unauthenticated read of a known object path
3. Unauthenticated write/upload to a uniquely named test object
4. Repeat list, read, and write as an anonymous-auth principal when anonymous sign-in is enabled
5. Repeat the same matrix as a low-privilege authenticated user

Write access is as important as read access and is routinely missed. Record status, response body, and object existence after each attempt; clean up only test objects that the test principal created.

Review rules source when present and flag:

- `allow read, write: if request.time < timestamp.date(...)` — the common console test-mode time gate
- `{allPaths=**}` catch-alls
- `request.auth != null` as the sole authorization gate
- Claim-presence checks such as `request.auth.token.roles.size() > 0` without role or tenant validation

Storage rules use OR-across-matches semantics: a later permissive match can reopen a path that an earlier match denied. Review every matching path, not only the most specific-looking deny.

**Bucket discovery**

- Extract `storageBucket` from `firebase.apps[0].options` and `NEXT_PUBLIC_FIREBASE_*` values in JavaScript bundles and source.
- Check `<project>.appspot.com` and `<project>.firebasestorage.app` bucket conventions.

**ACL and IAM checks are separate**

- Sweep object ACLs for `allUsers` and `allAuthenticatedUsers`, including objects made public by Admin SDK `makePublic()` or writers using `public: true`. Per-object public ACLs persist after Firebase rules are tightened and can remain on older prefixes.
- Check bucket IAM for `allUsers` and `allAuthenticatedUsers`.
- Check whether Uniform Bucket-Level Access is disabled; legacy object ACLs matter when it is off.
- Account for CDN caching of previously public objects; cache-bust when verifying a revocation.

**Tests**
- GET GCS object paths via HTTPS without auth; verify Content-Type and `Content-Disposition: attachment`
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

1. **Extract config** - Get project and storage bucket config from client bundles and source
2. **Obtain principals** - Collect tokens for unauth, anonymous, user A/B, and admin where authorized
3. **Build matrix** - Resource × Action × Principal across Firestore/Realtime/Storage/Functions
4. **Exercise both Storage doors** - Test Firebase Storage rules endpoints separately from GCS IAM/ACL URLs
5. **SDK vs REST** - Exercise every action via both to detect parity gaps
6. **Seed IDs** - Start from list/query paths to gather document and object paths
7. **Cross-principal** - Swap document paths, tenants, and user IDs across principals

## Whitebox Rules Review

- Inspect `firebase.json`, `.firebaserc`, deployment scripts, CI configuration, and infrastructure code for `storage.rules` / `firestore.rules` declarations.
- If `firebase.json` has no `storage` or `firestore` block, or the referenced rules file is absent from the tree, treat the live rules as unmanaged and force the live probe matrix. Absence of rules IaC is itself a finding; never conclude that there is nothing to review.
- Correlate configured rule files with deployed project and bucket identifiers. A source rule file for a different project does not establish live protection.

## Tooling

- SDK + REST: httpie/curl + jq for REST; Firebase emulator and Rules Playground for rapid iteration
- Rules analysis: script probes for common patterns (`auth != null`, missing field validation)
- Functions: fuzz onRequest with varied content-types and missing/forged Authorization
- Storage: enumerate prefixes; test signed URL generation and reuse patterns

## Validation Requirements

- Owner vs non-owner Firestore queries showing unauthorized access or metadata leak
- Firebase Storage unauthenticated, anonymous, or low-privilege read/list/write beyond intended scope, with minimal reproducible requests and observed deltas
- GCS object ACL or bucket IAM access beyond intended scope, including public object persistence after rules changes
- Function accepting forged/foreign identity (wrong `aud`/`iss`) or trusting client `uid`/`orgId`
- Minimal reproducible requests with roles/tokens used and observed deltas
