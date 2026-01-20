---
name: fastapi
description: Security testing playbook for FastAPI applications covering ASGI, dependency injection, and API vulnerabilities
---

# FastAPI

Security testing for FastAPI/Starlette applications. Focus on dependency injection flaws, middleware gaps, and authorization drift across routers and channels.

## Attack Surface

**Core Components**
- ASGI middlewares: CORS, TrustedHost, ProxyHeaders, Session, exception handlers, lifespan events
- Routers and sub-apps: APIRouter prefixes/tags, mounted apps (StaticFiles, admin), `include_router`, versioned paths
- Dependency injection: `Depends`, `Security`, `OAuth2PasswordBearer`, `HTTPBearer`, scopes

**Data Handling**
- Pydantic models: v1/v2, unions/Annotated, custom validators, extra fields policy, coercion
- File operations: UploadFile, File, FileResponse, StaticFiles mounts
- Templates: Jinja2Templates rendering

**Channels**
- HTTP (sync/async), WebSocket, SSE/StreamingResponse
- BackgroundTasks and task queues

**Deployment**
- Uvicorn/Gunicorn, reverse proxies/CDN, TLS termination, header trust

## High-Value Targets

- `/openapi.json`, `/docs`, `/redoc` in production (full attack surface map, securitySchemes, server URLs)
- Auth flows: token endpoints, session/cookie bridges, OAuth device/PKCE
- Admin/staff routers, feature-flagged routes, `include_in_schema=False` endpoints
- File upload/download, import/export/report endpoints, signed URL generators
- WebSocket endpoints (notifications, admin channels, commands)
- Background job endpoints (`/jobs/{id}`, `/tasks/{id}/result`)
- Mounted subapps (admin UI, storage browsers, metrics/health)

## Reconnaissance

**OpenAPI Mining**
```
GET /openapi.json
GET /docs
GET /redoc
GET /api/openapi.json
GET /internal/openapi.json
```

Extract: paths, parameters, securitySchemes, scopes, servers. Endpoints with `include_in_schema=False` won't appear—fuzz based on discovered prefixes and common admin/debug names.

**Dependency Mapping**

For each route, identify:
- Router-level dependencies (applied to all routes)
- Route-level dependencies (per endpoint)
- Which dependencies enforce auth vs just parse input

## Key Vulnerabilities

### Authentication & Authorization

**Dependency Injection Gaps**
- Routes missing security dependencies present on other routes
- `Depends` used instead of `Security` (ignores scope enforcement)
- Token presence treated as authentication without signature verification
- `OAuth2PasswordBearer` only yields a token string—verify routes don't treat presence as auth

**JWT Misuse**
- Decode without verify: test unsigned tokens, attacker-signed tokens
- Algorithm confusion: HS256/RS256 cross-use if not pinned
- `kid` header injection for custom key lookup paths
- Missing issuer/audience validation, cross-service token reuse

**Session Weaknesses**
- SessionMiddleware with weak `secret_key`
- Session fixation via predictable signing
- Cookie-based auth without CSRF protection

**OAuth/OIDC**
- Device/PKCE flows: verify strict PKCE S256 and state/nonce enforcement

### Access Control

**IDOR via Dependencies**
- Object IDs in path/query not validated against caller
- Tenant headers trusted without binding to authenticated user
- BackgroundTasks acting on IDs without re-validating ownership at execution time
- Export/import pipelines with IDOR and cross-tenant leaks

**Scope Bypass**
- Minimal scope satisfaction (any valid token accepted)
- Router vs route scope enforcement inconsistency

### Input Handling

**Pydantic Exploitation**
- Type coercion: strings to ints/bools, empty strings to None, truthiness edge cases
- Extra fields: `extra = "allow"` permits injecting control fields (role, ownerId, scope)
- Union types and `Annotated`: craft shapes hitting unintended validation branches

**Content-Type Switching**
```
application/json ↔ application/x-www-form-urlencoded ↔ multipart/form-data
```
Different content types hit different validators or code paths (parser differentials).

**Parameter Manipulation**
- Case variations in header/cookie names
- Duplicate parameters exploiting DI precedence
- Method override via `X-HTTP-Method-Override` (upstream respects, app doesn't)

### CORS & CSRF

**CORS Misconfiguration**
- Overly broad `allow_origin_regex`
- Origin reflection without validation
- Credentialed requests with permissive origins
- Verify preflight vs actual request deltas

**CSRF Exposure**
- No built-in CSRF in FastAPI/Starlette
- Cookie-based auth without origin validation
- Missing SameSite attribute

### Proxy & Host Trust

**Header Spoofing**
- ProxyHeadersMiddleware without network boundary: spoof `X-Forwarded-For/Proto` to influence auth/IP gating
- Absent TrustedHostMiddleware: Host header poisoning in password reset links, absolute URL generation
- Cache key confusion: missing Vary on Authorization/Cookie/Tenant

### Server-Side Vulnerabilities

**Template Injection (Jinja2)**
```python
{{7*7}}  # Arithmetic confirmation
{{cycler.__init__.__globals__['os'].popen('id').read()}}  # RCE
```
Check autoescape settings and custom filters/globals.

**SSRF**
- User-supplied URLs in imports, previews, webhooks validation
- Test: loopback, RFC1918, IPv6, redirects, DNS rebinding, header control
- Library behavior (httpx/requests): redirect policy, header forwarding, protocol support
- Protocol smuggling: `file://`, `ftp://`, gopher-like shims if custom clients

**File Upload**
- Path traversal in `UploadFile.filename` with control characters
- Missing storage root enforcement, symlink following
- Vary filename encodings, dot segments, NUL-like bytes
- Verify storage paths and served URLs

### WebSocket Security

- Missing per-connection authentication
- Cross-origin WebSocket without origin validation
- Topic/channel IDOR (subscribing to other users' channels)
- Authorization only at handshake, not per-message

### Mounted Apps

Sub-apps at `/admin`, `/static`, `/metrics` may bypass global middlewares. Verify auth enforcement parity across all mounts.

### Alternative Stacks

- If GraphQL (Strawberry/Graphene) is mounted: validate resolver-level authorization, IDOR on node/global IDs
- If SQLModel/SQLAlchemy present: probe for raw query usage and row-level authorization gaps

## Bypass Techniques

- Content-type switching to traverse alternate validators
- Parameter duplication and case variants exploiting DI precedence
- Method confusion via proxies (`X-HTTP-Method-Override`)
- Race windows around dependency-validated state transitions (issue token then mutate with parallel requests)

## Testing Methodology

1. **Enumerate** - Fetch OpenAPI, diff with 404-fuzzing for hidden endpoints
2. **Matrix testing** - Test each route across: unauth/user/admin × HTTP/WebSocket × JSON/form/multipart
3. **Dependency analysis** - Map which dependencies enforce auth vs parse input
4. **Cross-environment** - Compare dev/stage/prod for middleware and docs exposure differences
5. **Channel consistency** - Verify same authorization on HTTP and WebSocket for equivalent operations

## Validation Requirements

- Side-by-side requests showing unauthorized access (owner vs non-owner, cross-tenant)
- Cross-channel proof (HTTP and WebSocket for same rule)
- Header/proxy manipulation showing altered outcomes (Host/XFF/CORS)
- Minimal payloads for template injection, SSRF, token misuse with safe/OAST oracles
- Document exact dependency paths (router-level, route-level) that missed enforcement
