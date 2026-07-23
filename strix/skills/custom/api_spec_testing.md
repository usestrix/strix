---
name: api_spec_testing
description: Spec-driven API pentesting — systematically exercise every endpoint from an ingested OpenAPI/Swagger/Postman inventory for authz, injection, and business-logic flaws
---

# API Spec Testing

When a target is an ingested API specification (OpenAPI 3.x, Swagger 2.0, or a
Postman collection), the root task already contains a normalized endpoint
inventory under **API Specifications** — every operation with its method, path,
declared parameters, request-body fields, and auth scheme. Do not rediscover the
surface by crawling. Walk the inventory operation-by-operation and prove
findings against the live base URL(s), which are authorized in scope.

## Methodology

**1. Baseline the contract.** For each endpoint, send a well-formed request that
matches the declared schema and record the normal response (status, shape,
auth requirement). This baseline is what every abuse case is compared against.

**2. Enumerate coverage.** Track every `METHOD path` in the inventory and mark it
tested. Undocumented-but-implied siblings are worth probing too (e.g. if
`GET /users/{id}` exists, try `PUT`/`DELETE`/`PATCH` on the same path even when
the spec omits them — specs routinely under-document write operations).

**3. Prioritize by risk.** Object-scoped reads/writes, exports, admin/staff
operations, and anything touching billing, auth, or PII first.

## What to test per endpoint

**Authorization (highest yield on APIs)**
- BOLA/IDOR: swap object identifiers in path/query/body across two accounts;
  confirm cross-account read or state change. Every `{id}`, `parentId`,
  `accountId`, `tenantId` in the inventory is a candidate.
- BFLA: call privileged operations (declared `auth` scopes, admin paths) with a
  lower-privilege token; confirm the action succeeds.
- Missing auth: replay each endpoint with the token stripped and with an expired
  token; the declared `auth: …` in the inventory tells you what should be
  required — flag any endpoint that returns data without it.

**Mass assignment / excessive data exposure**
- Use the declared `body:` fields as a starting point, then add sensitive fields
  the schema omits (`role`, `isAdmin`, `verified`, `balance`, `ownerId`) and
  confirm they are honored.
- Check responses for fields beyond what the caller should see.

**Injection & parameter abuse**
- For every parameter, test against its declared type: send strings where
  integers/UUIDs are expected, oversized values, and injection payloads
  (SQLi/NoSQLi/command/SSTI depending on backend). Type confusion often bypasses
  validation.
- Test `fields`/`include`/`expand`/`filter` style knobs for authorization
  bypass in resolvers/serializers.

**Business logic & rate limits**
- Chain operations across endpoints (create → approve → withdraw) looking for
  workflow/state bypass and race conditions on money/quota mutations.
- Confirm rate limiting on auth and expensive endpoints.

## Validation

A finding is only real once reproduced against the live base URL with a
concrete request/response pair. Capture the exact HTTP request (method, path,
headers, body) and the response proving impact (another account's data, a
privileged action succeeding, an injected payload executing). Prefer two-account
diffs for authorization findings: same request, different token, unauthorized
success.

## Tips

- The base URL(s) from the spec are authorized targets — send real traffic.
- Path templates use `{param}`; substitute real values from your baseline.
- For Postman collections, saved example values and environment variables are
  strong hints for valid inputs — use them to get past validation quickly.
- Keep a running coverage table so no operation in the inventory is skipped.
