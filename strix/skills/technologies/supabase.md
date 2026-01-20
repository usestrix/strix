---
name: supabase
description: Supabase security testing covering Row Level Security, PostgREST, Edge Functions, and service key exposure
---

# Supabase

Security testing for Supabase applications. Focus on mis-scoped Row Level Security (RLS), unsafe RPCs, leaked `service_role` keys, lax Storage policies, and Edge Functions trusting headers without binding to issuer/audience/tenant.

## Attack Surface

**Data Access**
- PostgREST: table CRUD, filters, embeddings, RPC (remote functions)
- GraphQL: pg_graphql over Postgres schema with RLS interaction
- Realtime: replication subscriptions, broadcast/presence channels

**Storage**
- Buckets, objects, signed URLs, public/private policies

**Authentication**
- Auth (GoTrue): JWTs, cookie/session, magic links, OAuth flows

**Server-Side**
- Edge Functions (Deno): server-side code calling Supabase with secrets

## Architecture

**Endpoints**
- REST: `https://<ref>.supabase.co/rest/v1/<table>`
- RPC: `https://<ref>.supabase.co/rest/v1/rpc/<fn>`
- Storage: `https://<ref>.supabase.co/storage/v1`
- GraphQL: `https://<ref>.supabase.co/graphql/v1`
- Realtime: `wss://<ref>.supabase.co/realtime/v1`
- Auth: `https://<ref>.supabase.co/auth/v1`
- Functions: `https://<ref>.functions.supabase.co/`

**Headers**
- `apikey: <anon-or-service>` — identifies project
- `Authorization: Bearer <JWT>` — binds user context

**Roles**
- `anon`, `authenticated` — standard roles
- `service_role` — bypasses RLS, must never be client-exposed

**Key Principle**
`auth.uid()` returns current user UUID from JWT. Policies must never trust client-supplied IDs over server context.

## High-Value Targets

- Tables with sensitive data (users, orders, payments, PII)
- RPC functions (especially `SECURITY DEFINER`)
- Storage buckets with private files
- Edge Functions with `service_role` access
- Export/report endpoints generating signed outputs
- Admin/staff routes and privilege-granting endpoints

## Reconnaissance

**Enumerate Surfaces**
```
/rest/v1/<table>
/rest/v1/rpc/<fn>
/storage/v1/object/public/<bucket>/
/storage/v1/object/list/<bucket>?prefix=
/graphql/v1
/auth/v1
```

**Obtain Principals**
- Unauthenticated (anon key only)
- Basic user A, user B
- Admin/staff (if available)
- Check if `service_role` key leaked in client bundle or Edge Function responses

## Key Vulnerabilities

### Row Level Security (RLS)

Enable RLS on every non-public table; absence or "permit-all" policies → bulk exposure.

**Common Gaps**
- Policies check `auth.uid()` for SELECT but forget UPDATE/DELETE/INSERT
- Missing tenant constraints (`org_id`/`tenant_id`) allow cross-tenant access
- Policies rely on client-provided columns (`user_id` in payload) instead of JWT
- Complex joins where policy is applied after filters, enabling inference via counts

**Tests**
```bash
# Compare row counts for two users
GET /rest/v1/<table>?select=*&Prefer=count=exact

# Cross-tenant probe
GET /rest/v1/<table>?org_id=eq.<other_org>
GET /rest/v1/<table>?or=(org_id.eq.other,org_id.is.null)

# Write-path
PATCH /rest/v1/<table>?id=eq.<foreign_id>
DELETE /rest/v1/<table>?id=eq.<foreign_id>
POST /rest/v1/<table> with foreign owner_id
```

### PostgREST & REST

**Filters**
- `eq`, `neq`, `lt`, `gt`, `ilike`, `or`, `is`, `in`
- Embed relations: `select=*,profile(*)`—exploits overfetch if resolvers skip per-row checks
- Search leaks: generous `LIKE`/`ILIKE` filters combined with missing RLS → mass disclosure via wildcard queries

**Headers**
- `Prefer: return=representation` — echo writes
- `Prefer: count=exact` — exposure via counts
- `Accept-Profile`/`Content-Profile` — select schema

**IDOR Patterns**
```
/rest/v1/<table>?select=*&id=eq.<other_id>
/rest/v1/<table>?select=*&slug=eq.<other_slug>
/rest/v1/<table>?select=*&email=eq.<other_email>
```

**Mass Assignment**
- If RPC not used, PATCH can update unintended columns
- Verify restricted columns via database permissions/policies

### RPC Functions

RPC endpoints map to SQL functions. `SECURITY DEFINER` bypasses RLS unless carefully coded; `SECURITY INVOKER` respects caller.

**Anti-Patterns**
- `SECURITY DEFINER` + missing owner checks → vertical/horizontal bypass
- `set search_path` left to public; function resolves unsafe objects
- Trusting client-supplied `user_id`/`tenant_id` rather than `auth.uid()`

**Tests**
```bash
# Call as different users with foreign IDs
POST /rest/v1/rpc/<fn> {"user_id": "<foreign_id>"}

# Remove JWT entirely
Authorization: Bearer <anon_token>
```
Verify functions perform explicit ownership/tenant checks inside SQL.

### Storage

**Buckets**
- Public vs private; objects in `storage.objects` with RLS-like policies

**Misconfigurations**
```bash
# Public bucket with sensitive data
GET /storage/v1/object/public/<bucket>/<path>

# List prefixes without auth
GET /storage/v1/object/list/<bucket>?prefix=

# Signed URL reuse across tenants/paths
```

**Content-Type Abuse**
- Upload HTML/SVG served as `text/html` or `image/svg+xml`
- Verify `X-Content-Type-Options: nosniff` and `Content-Disposition: attachment`

**Path Confusion**
- Mixed case, URL-encoding, `..` segments may be rejected at UI but accepted by API
- Test path normalization differences between client validation and server handling

### Realtime

**Endpoint**: `wss://<ref>.supabase.co/realtime/v1`

**Risks**
- Channel names derived from table/schema/filters leaking other users' updates when RLS or channel guards are weak
- Broadcast/presence channels allowing cross-room join/publish without auth

**Tests**
- Subscribe to `public:realtime` changes on protected tables; confirm visibility aligns with RLS
- Attempt joining other users' channels: `room:<user_id>`, `org:<org_id>`

### GraphQL

**Endpoint**: `/graphql/v1` using pg_graphql with RLS

**Risks**
- Introspection reveals schema relations
- Overfetch via nested relations where resolvers skip per-row ownership checks
- Global node IDs leaked and reusable via different viewers

**Tests**
- Compare REST vs GraphQL responses for same principal and query shape
- Query deep nested fields; verify RLS holds at each edge

### Auth & Tokens

GoTrue issues JWTs with claims (`sub=uid`, `role`, `aud=authenticated`).

**Verification Requirements**
- Issuer, audience, expiration, signature, tenant context

**Pitfalls**
- Storing tokens in localStorage → XSS exfiltration
- Treating `apikey` as identity (it's project-scoped, not user identity)
- Exposing `service_role` key in client bundle or Edge Function responses
- Refresh token mismanagement leading to long-lived sessions beyond intended TTL

**Tests**
- Replay tokens across services; check audience/issuer pinning
- Try downgraded tokens (expired/other audience) against custom endpoints

### Edge Functions

Deno-based functions often initialize Supabase client with `service_role`.

**Risks**
- Trusting Authorization/apikey headers without verifying JWT against issuer/audience
- CORS: wildcard origins with credentials; reflected Authorization in responses
- SSRF via fetch; secrets exposed via error traces or logs

**Tests**
- Call functions with and without Authorization; compare behavior
- Try foreign resource IDs in payloads; verify server re-derives user/tenant from JWT
- Attempt to reach internal endpoints (metadata services) via function fetch

### Tenant Isolation

Ensure every query joins or filters by `tenant_id`/`org_id` derived from JWT context, not client input.

**Tests**
- Change subdomain/header/path tenant selectors while keeping JWT tenant constant
- Export/report endpoints: confirm queries execute under caller scope

## Bypass Techniques

- Content-type switching: `application/json` ↔ `application/x-www-form-urlencoded` ↔ `multipart/form-data`
- Parameter pollution: duplicate keys in JSON/query (PostgREST chooses last/first depending on parser)
- GraphQL+REST parity probing: protections often drift; fetch via the weaker path
- Race windows: parallel writes to bypass post-insert ownership updates

## Blind Enumeration

- Use `Prefer: count=exact` and ETag/length diffs to infer unauthorized rows
- Conditional requests (`If-None-Match`) to detect object existence
- Storage signed URLs: timing/length deltas to map valid vs invalid tokens

## Testing Methodology

1. **Inventory surfaces** - Map REST, Storage, GraphQL, Realtime, Auth, Functions endpoints
2. **Obtain principals** - Collect tokens for anon, user A/B, admin; check for `service_role` leaks
3. **Build matrix** - Resource × Action × Principal
4. **REST vs GraphQL** - Test both to find parity gaps
5. **Seed IDs** - Start with list/search endpoints to gather IDs
6. **Cross-principal** - Swap IDs, tenants, and transports across principals

## Tooling

- PostgREST: httpie/curl + jq; enumerate tables; fuzz filters (`or=`, `ilike`, `neq`, `is.null`)
- GraphQL: graphql-inspector, voyager; deep queries for field-level enforcement
- Realtime: custom ws client; subscribe to suspicious channels; diff payloads per principal
- Storage: enumerate bucket listing APIs; script signed URL patterns
- Auth/JWT: jwt-cli/jose to validate audience/issuer; replay against Edge Functions
- Policy diffing: maintain request sets per role; compare results across releases

## Validation Requirements

- Owner vs non-owner requests for REST/GraphQL showing unauthorized access (content or metadata)
- Mis-scoped RPC or Storage signed URL usable by another user/tenant
- Realtime or GraphQL exposure matching missing policy checks
- Minimal reproducible requests with role contexts documented
