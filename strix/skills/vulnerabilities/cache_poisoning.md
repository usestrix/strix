---
name: cache-poisoning
description: Web cache poisoning and web cache deception testing covering unkeyed header injection, fat GET poisoning, response splitting, and per-user cache isolation bypass
---

# Cache Poisoning

Web cache poisoning injects malicious content into a cache so that it is served to subsequent users who make the same cache key lookup. Web cache deception is the inverse: trick the cache into storing a private response and serve it to the attacker. Both abuse the mismatch between what the cache considers a unique request (the cache key) and what the origin server actually uses to generate the response. The impact of cache poisoning scales with cache TTL and traffic — a single poisoned entry can deliver XSS or redirect attacks to every user on a high-traffic site.

## Attack Surface

**Cache Infrastructure**
- CDN caches (Cloudflare, Fastly, Akamai, CloudFront, Varnish)
- Reverse proxy caches (Nginx `proxy_cache`, Apache `mod_cache`)
- Application-level caches (Redis, Memcached) with HTTP response caching
- Browser caches (local poisoning via response headers)
- Shared hosting caches and edge nodes

**Cache Key Components (Default)**
- URL (path + query string, sometimes excluding certain params)
- Host header (sometimes)
- Rarely: cookies, Authorization header, request body

**Unkeyed Inputs (Attack Surface)**
- `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`
- `X-Forwarded-For`, `X-Real-IP`, `X-Original-URL`
- `X-Forwarded-Proto`, `X-Forwarded-Scheme`
- `Origin` (when CORS response is cached)
- `Accept-Language`, `Accept-Encoding` (fat GET)
- UTM parameters, tracking query params excluded from cache key
- HTTP/2 pseudo-headers when downgraded

## High-Value Targets

**Cache Poisoning Targets**
- JavaScript and CSS resources loaded by all users (script src in `<head>`)
- Dynamic pages that reflect unkeyed input into script imports, redirect URLs, or resource references
- Login page (redirect after authentication), password reset page
- Error pages that reflect arbitrary input
- API responses cached with broad TTLs

**Cache Deception Targets**
- Profile pages, account settings, private data endpoints
- Authenticated API responses that return user-specific data
- Session tokens or CSRF tokens embedded in HTML responses

## Reconnaissance

### Identify Cache Behavior

- Send two identical requests and compare `Age`, `X-Cache`, `CF-Cache-Status`, `Cache-Control` headers
- `Age > 0` or `X-Cache: HIT` confirms the response was served from cache
- Identify which parameters are keyed: append a cache-buster `?cb=<random>` to force a miss and then remove it to confirm a hit

### Unkeyed Input Discovery

For each of the following headers, inject a canary value and check whether it appears in the response:
```
X-Forwarded-Host: canary.attacker.com
X-Host: canary.attacker.com
X-Forwarded-For: canary
X-Original-URL: /attacker-path
X-Rewrite-URL: /attacker-path
X-Forwarded-Proto: https://canary
Accept-Language: en-<script>alert(1)</script>
```

If the canary appears in the response body, the header is unkeyed and reflected — a cache poisoning primitive.

### Cache Key Exclusion (Query Parameters)

Many CDNs exclude certain query parameters from the cache key while the origin still processes them:
- UTM params: `?utm_source=`, `?utm_campaign=`
- Debug params: `?debug=`, `?preview=`
- Tracking: `?fbclid=`, `?gclid=`

If the origin reflects these parameters, a poisoned response keyed on the base URL (without the param) contaminates the cache for all subsequent visitors.

## Key Vulnerabilities

### Unkeyed Host Header Injection

Origin uses `X-Forwarded-Host` to generate absolute URLs for scripts, canonical links, or redirects. CDN does not include this header in the cache key.

**Probe:**
```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

→ Response: <script src="https://evil.com/app.js"></script>
```

**Poison:** Send the request with `X-Forwarded-Host: attacker.com` until the CDN caches the response. All subsequent users loading `/` will import `attacker.com/app.js`.

### Unkeyed `X-Forwarded-Proto` / Scheme Injection

Origin generates redirect URLs based on the scheme:
```http
X-Forwarded-Proto: http
→ Location: http://target.com/secure-page
```
If the redirect page is cached and the scheme is unkeyed, victims receive HTTP redirect, stripping HTTPS.

### Fat GET (Unkeyed Request Body)

Some servers process GET request bodies while caches key only on URL and method. Inject a parameter in the GET body that overrides a URL query parameter:
```http
GET /search?q=safe HTTP/1.1
Host: target.com
Content-Length: 15

q=<script>...
```
Origin reads `q` from body (overriding query), caches the XSS response under the `?q=safe` cache key.

### Cache Parameter Cloaking

A CDN parses query parameters differently from the origin:
- CDN: `/endpoint?param=safe&xss=injected` — keys on `/endpoint?param=safe` (drops unknown params)
- Origin: sees both params, reflects `xss=injected` in response

Result: XSS response cached under the safe URL, served to all users.

**Ambiguous delimiter variations:**
```
/endpoint?param=safe%26xss=injected    # encoded ampersand
/endpoint?param=safe;xss=injected      # semicolon delimiter (some origins split on ;)
/endpoint?param=safe#xss=injected      # fragment (CDN may strip, origin may not)
```

### Response Splitting via Unkeyed Headers

If an unkeyed header value is injected into a response header without sanitization (header injection), an attacker can inject a full HTTP response:
```
X-Custom-Header: value\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\n...
```
Combined with caching, the injected response is stored and served.

### CORS Poisoning

Origin generates CORS headers based on the `Origin` request header. CDN caches the response without keying on `Origin`:
```http
Origin: https://evil.com
→ Access-Control-Allow-Origin: https://evil.com
   (cached without Origin in cache key)
```
All users receive `ACAO: https://evil.com`, enabling cross-origin data reads.

### Web Cache Deception

Trick the cache into storing an authenticated page response by appending a cacheable-looking path segment:
```
/account/settings/..%2Ffake.css
/account/profile/fake.jpg
/account/profile%2Ffake.css
```
If the application ignores the suffix (serving the profile page) but the CDN caches based on file extension (`.css`, `.jpg` → cacheable), the private page response is stored under a public URL.

**Attack flow:**
1. Attacker sends the crafted URL to a victim (phishing link, email)
2. Victim loads the URL while authenticated — private page cached at that URL
3. Attacker fetches the same URL unauthenticated and receives the victim's data

## Exploitation Flow

**Generic Cache Poisoning:**
1. Identify an unkeyed input that influences the response (unkeyed header reflected in body)
2. Confirm the input is not included in the cache key (send with/without and compare cache headers)
3. Inject a payload via the unkeyed input: `X-Forwarded-Host: attacker.com` (for URL injection) or XSS payload in reflected header
4. Flood the endpoint with the poisoned request until a cache HIT is observed
5. Verify a clean browser (no cookies) receives the poisoned response

**Generic Cache Deception:**
1. Identify a page returning authenticated user data
2. Append a static file suffix and confirm the application still serves the data
3. Confirm the CDN caches the suffixed URL (check `Cache-Control`, extension rules)
4. Share the URL; load as a victim; verify the cache stores the authenticated response
5. Fetch as attacker (unauthenticated); verify receipt of victim's data

## Testing Methodology

1. **Fingerprint cache layer** — identify CDN/proxy from response headers (`CF-Cache-Status`, `X-Cache`, `Via`, `Age`)
2. **Identify keying behavior** — append cache-buster param; verify HIT on re-request without it
3. **Probe unkeyed headers** — inject canary values in host/forwarding/scheme headers; check reflection
4. **Probe unkeyed query params** — test UTM/tracking params for reflection and cache exclusion
5. **Test fat GET** — send GET with body; check if body param overrides query param
6. **Test parameter cloaking** — try encoded `&`, `;`, `#` to smuggle params past CDN key parser
7. **Test cache deception** — append `.css`, `.js`, `.png`, `..%2Ffile.jpg` to authenticated endpoint URLs
8. **Confirm exploitability** — send poisoned request, then fetch the same URL unauthenticated; confirm payload delivery
9. **Check TTL** — identify how long the poisoned entry persists; document scope of affected users

## Validation

1. Show unkeyed header reflected in response body; show the response has `X-Cache: MISS` on first request and `HIT` on second
2. Demonstrate poisoned response delivered to a client that never sent the injected header
3. For cache deception: show victim's session data delivered to an unauthenticated attacker fetch
4. Provide before/after: clean URL returns normal response; poisoned URL returns malicious payload
5. Document TTL: confirm the poisoned entry persists for at least two requests

## False Positives

- Cache explicitly keying on the tested header (`Vary: X-Forwarded-Host`)
- CDN stripping or sanitizing headers before forwarding to origin
- Application escaping reflected header values before output (HTML/URL encoding)
- Short TTL (< 1 second) making stable poisoning impractical
- Private cache (`Cache-Control: private`) preventing shared cache storage
- Single-user or session-bound responses not cacheable

## Impact

- **Cache poisoning:** XSS delivered to all users on a high-traffic cached page (script injection, redirect)
- **Cache poisoning:** Site-wide HTTP downgrade or malicious redirect via scheme/host injection
- **Cache poisoning:** CORS header poisoning enabling cross-origin read of cached API responses
- **Cache deception:** Exfiltration of any authenticated user's private page data to an unauthenticated attacker
- **Cache deception:** Session token, CSRF token, or PII leakage from authenticated-only pages
- **Scope:** Scales with cache TTL — a single poisoned entry can affect thousands of users before expiry

## Pro Tips

1. Always use a cache-buster query param during testing (`?cb=<random>`) to avoid accidentally poisoning the production cache with test payloads
2. Test `X-Forwarded-Host` first — it is the most commonly unkeyed host-influencing header and reflected by many frameworks
3. Web cache deception is often overlooked by CDN configurations that use file extension rules for cacheability — `.css`, `.js`, `.png`, `.svg` suffixes are the most reliable
4. For Cloudflare, check whether `Cache-Control: no-store` is respected — some configurations override it at the CDN level
5. `Vary` header lists the request headers that are included in the cache key; check it to understand what is and is not keyed
6. Parameter cloaking is CDN-specific; maintain a list of known delimiter handling differences between major CDN/origin combinations (Nginx, Varnish, Cloudflare, Fastly)
7. Combine cache poisoning with DOM XSS: inject a `<script>` tag via unkeyed host to deliver XSS to all users of a cached page
8. For internal CDNs, check Redis or Memcached key construction — app-level caches often key naively on request URL without considering all influencing headers

## Summary

Cache poisoning requires two conditions: a request component that influences the response but is excluded from the cache key, and a cache that stores and serves that poisoned response. Cache deception requires a mismatch between the application's routing logic and the cache's cacheability decision. Both are eliminated by keying on all inputs that influence the response, using `Cache-Control: private` for authenticated content, and validating CDN/proxy configuration against the origin's expectation.
