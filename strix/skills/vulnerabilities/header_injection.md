---
name: header-injection
description: HTTP header injection testing covering CRLF / response splitting, cache poisoning, Host-header confusion, cookie fixation, and proxy / forwarding header smuggling
---

# HTTP Header Injection

Header injection turns user input into protocol-level control: response splitting, cache poisoning, session fixation, authentication bypass, and request smuggling all trace back to a server-controlled header value that wasn't normalized. The bug usually lives in middle layers — frameworks that copy a request value into a response header, proxies that trust forwarded headers, caches keyed on something the attacker influences. Treat any user-controlled value that reaches a header as code-execution-equivalent until proven otherwise.

## Attack Surface

**Input shapes that reach headers**
- Query/body/path values echoed into `Set-Cookie`, `Location`, `Content-Type`, `Content-Disposition`, `Link`, custom `X-*`
- Request headers re-emitted into responses (Referer, User-Agent, X-Forwarded-*, custom correlation IDs)
- Webhook / callback flows where the server constructs outbound requests using user-supplied URLs (Host, Referer)
- Outbound email headers (To/From/Subject) populated from user input

**Code patterns that enable injection**
- Direct concatenation of user input into header values without CR/LF stripping
- Frameworks that accept header values as strings and serialize verbatim (no normalization)
- Proxy chains trusting `X-Forwarded-*` / `Forwarded` / `X-Real-IP` set by an upstream that anyone can spoof
- `X-HTTP-Method-Override` and similar method-shaping headers respected past auth layers

**Transports and parser layers**
- HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3 each parse framing differently
- CDN / reverse proxy → application server (where each side may disagree on framing)
- Chunked transfer encoding boundaries and multipart/form-data delimiters

## High-Value Targets

- Password-reset and account-recovery flows (Host header determines the link sent to the user)
- OAuth / SSO redirect endpoints (`Location`, `redirect_uri` echoes)
- Auth gateways that trust `X-Forwarded-For` / `X-Real-IP` for IP allowlists or rate limits
- CDN / WAF caches (poisoning a public cache with a per-user response)
- Multi-tenant routing keyed on Host or `X-Tenant-Id`
- File-download endpoints (`Content-Disposition` filename derived from user input)
- Outbound notification / email systems where user input lands in the message header

## Reconnaissance

### Header Inventory

- Enumerate every response header that varies with input — flip query / body / cookie values and diff `Set-Cookie`, `Location`, `Content-Type`, `Content-Disposition`, `ETag`, `Vary`, custom `X-*`
- For each varying header, identify the source field (user-controlled vs. server-derived)
- Look for request headers reflected into responses (Referer in error pages, User-Agent in correlation IDs, X-Forwarded-Host echoed back)

### CR/LF and Whitespace Variants

- Bare LF (`%0a`), bare CR (`%0d`), CRLF (`%0d%0a`)
- Double encoding (`%250d%250a`) for WAFs that decode once
- Overlong UTF-8 of CR/LF (`%c0%8d`, `%c0%8a`) — invalid per spec but accepted by some parsers
- Unicode line/paragraph separators (`%e2%80%a8` U+2028, `%e2%80%a9` U+2029) — sometimes folded to LF by intermediaries
- Tab (`%09`) — RFC 7230 allows tabs in field values, useful for sneaking past simple `\s+` filters
- Null byte (`%00`) — can truncate the header value in some parsers

### Parser and Server Fingerprinting

- `Server`, `Via`, `X-Powered-By`, `X-AspNet-Version`, `X-Served-By`, `CF-Ray`, `X-Amzn-RequestId` reveal the stack
- `Vary`, `Age`, `X-Cache`, `CF-Cache-Status` reveal caching layer and key composition
- Same payload over HTTP/1.1 vs HTTP/2 vs chunked — diff status, headers, body length to map parsing differences
- Compare `Host` and `X-Forwarded-Host` precedence: send both with different values and observe which wins in redirects, links, log entries

## Key Vulnerabilities

### CRLF Response Splitting and Smuggling

Inject `\r\n\r\n` to terminate the current response and prepend a second attacker-controlled response. Cache or downstream proxy may key on the first response and serve the second to other users.

```
GET /redirect?to=foo%0d%0aSet-Cookie:%20admin=1%0d%0a%0d%0a<html>poisoned</html> HTTP/1.1
```

Request smuggling is the same primitive at the request layer: inject a header that causes the proxy and backend to disagree on message framing — most commonly conflicting `Content-Length` and `Transfer-Encoding`, or two `Content-Length` headers with different values. Backend reads one request, frontend reads a different one; the leftover bytes become a smuggled request prepended to the next victim's connection.

### Cache Poisoning

- **Unkeyed input → keyed response**: input that influences the response body but not the cache key (an `X-Forwarded-Host` echoed in a link, an unkeyed query parameter reflected in HTML)
- **`Vary` manipulation**: inject a `Vary` header to over-fragment the cache (DoS-flavored) or under-fragment it (cross-user serving)
- **`X-Forwarded-Proto` / `X-Forwarded-Host` poisoning**: backend uses these to build canonical URLs in the response; CDN caches the response with attacker-controlled links
- **`Cache-Control` / `Age` injection**: flip `private` to `public` (or vice versa), or set `Age: 0` for immediate revalidation
- **Web cache deception**: trick the cache into storing an authenticated response at a public-looking URL (`/account/profile.css`) by appending a cacheable extension

### Host Header Confusion

Backends often trust `Host` (or `X-Forwarded-Host`) when constructing absolute URLs — password reset emails, OAuth `redirect_uri`, canonical link tags. Sending a forged Host produces a reset link pointing at attacker-controlled infrastructure that still carries the victim's reset token.

```
POST /password-reset HTTP/1.1
Host: attacker.tld
```

Also test: precedence between `Host` and `X-Forwarded-Host`, IPv6 bracketing (`Host: [::1]:80`), trailing dot (`Host: example.com.`), and port confusion (`Host: example.com:@attacker.tld`).

### Cookie / Set-Cookie Manipulation

- Inject `Domain=.example.com` or `Path=/` to widen scope of an attacker-set cookie
- Inject `SameSite=None; Secure` to allow cross-site inclusion
- Inject `Max-Age=999999999` for persistence, or `Max-Age=-1` to nuke the victim's session
- Inject a cookie with the same name as a real session cookie — precedence rules let a same-domain attacker shadow it (cookie tossing)
- Reflected cookie XSS: if a cookie value is later rendered unescaped in HTML, the injection point is the header but the sink is the page

### Proxy and Forwarding Header Spoofing

The `X-Forwarded-*` family is informational — there is no protocol guarantee about who set them. Any application that trusts them past the boundary it controls is exploitable.

- `X-Forwarded-For: 127.0.0.1` to bypass IP allowlists or rate limits keyed on client IP
- `X-Forwarded-Proto: https` to satisfy "HTTPS-only" checks while still using HTTP
- `X-Forwarded-Host: attacker.tld` for the Host-confusion variants above
- `X-Real-IP`, `Client-IP`, `True-Client-IP`, `CF-Connecting-IP`, `Forwarded` (RFC 7239) — same primitive, different header names; spray all of them
- `X-Original-URL` / `X-Rewrite-URL` (IIS, ASP.NET) — server-side URL rewriting after auth check, classic admin-panel auth bypass

### Content-Type / Encoding Confusion

- Inject `Content-Type: text/html` into an endpoint that returned JSON; browsers may sniff and render → XSS
- Inject `charset=utf-7` in `Content-Type` for legacy XSS via UTF-7-encoded payloads
- Inject `Content-Disposition: inline` to switch a download into in-page rendering
- Inject `Content-Encoding: gzip` without actually compressing — clients decode-fail and may reveal raw response bytes in error paths
- Inject `X-Content-Type-Options: nosniff` to flip behavior (or remove an existing header by overriding it)

### XSS via Response Headers

- `Location: javascript:alert(1)` if redirect target is reflected unescaped (browsers usually block, but some legacy clients and Electron-style hosts don't)
- `Location: data:text/html,<script>alert(1)</script>` — same caveat
- `Refresh: 0; url=javascript:alert(1)` — the legacy `Refresh` header is a JavaScript-free meta-refresh equivalent
- Reflected request header XSS: `Referer` echoed into a custom error page, `User-Agent` echoed into a debug header — combine CRLF injection with a body-injection sink

### Open Redirect via Headers

- `Location` is the obvious one
- `Refresh: 0; url=https://attacker.tld` — bypasses some `Location`-only filters
- `Link: <https://attacker.tld>; rel="canonical"` — usually informational but consumed by SEO tooling and some clients
- `X-Accel-Redirect: /internal/file` (Nginx) — if user input reaches this, internal-only files become accessible

### HTTP/2 Pseudo-Header and Frame Confusion

- HTTP/2 splits headers into pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`) and regular fields. Servers downgrading to HTTP/1.1 sometimes mishandle pseudo-header values, enabling smuggling across the H2 → H1 boundary.
- HTTP/2 lowercases header names; an upstream H1 filter that's case-sensitive may miss a lowercase variant that the H2 backend then accepts.
- HEADERS / CONTINUATION frame splitting: payload spans frames, intermediaries differ on whether they reassemble before applying filters.

## Bypass Techniques

**Encoding**
- URL-encode (`%0d%0a`) and double-encode (`%250d%250a`) for WAFs that decode the wrong number of times
- Mix encodings within one payload: `%0d%0A`, `%0D\n`, alternating case
- Newline-equivalent Unicode: U+2028 / U+2029 (sometimes folded to LF), overlong UTF-8 of CR/LF

**Header normalization edges**
- Leading / trailing whitespace and tabs in header names and values
- Header folding (obs-fold per RFC 7230 — formally obsolete, but some parsers still accept continuation lines starting with whitespace)
- Duplicate headers — RFC says join with `,`; in practice servers pick first, last, or differ from the proxy in front of them

**Method and method-override**
- `X-HTTP-Method-Override: PUT` (and `X-Method-Override`, `X-HTTP-Method`) to reach state-changing handlers from a CSRF-friendly `POST`
- Combine method override with content-type switch to bypass CORS preflight

**Header name games**
- Case mangling for filters that key off exact casing
- Null byte truncation in header name (`X-Forwarded-For\x00Evil`) on parsers that stop at NUL

## Testing Methodology

1. **Inventory varying headers** — enumerate every response header whose value moves with input
2. **Probe CR/LF normalization** — inject `%0d%0a` (and the encoding variants) into each varying header source; observe whether the second line lands as a real header
3. **Test Host / X-Forwarded-Host** — submit a password-reset or any link-generating flow with attacker-controlled Host; confirm the link in the response or follow-up email
4. **Probe forwarding headers** — spoof `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP` against IP-restricted endpoints (admin, rate-limited)
5. **Test cache key / response content split** — find inputs that change the body but not the cache key; confirm a second request from a different session sees the poisoned response
6. **Test method override** — `X-HTTP-Method-Override` paired with state-changing endpoints reachable via POST or GET
7. **Test request smuggling pairs** — conflicting `Content-Length` and `Transfer-Encoding`, two `Content-Length` headers, malformed chunked encoding, against any frontend → backend pair
8. **Cross-protocol** — replay payloads over HTTP/1.1 and HTTP/2; diff behavior

## Validation

1. Show two distinct users (or sessions) receiving content keyed on attacker-supplied header — proves cache poisoning
2. Capture a password-reset / OAuth link pointing at attacker-controlled host — proves Host injection
3. Demonstrate the same endpoint returning different auth decisions with and without a forged forwarding header
4. For response splitting: show a downstream cache or proxy serving the injected second response to an unrelated request
5. For request smuggling: show one victim request seeing data from a different request appended (not just timing or single-shot anomaly)
6. All findings should produce a durable artifact (cached response, sent email, log entry, session change) — transient anomalies are not validation

## False Positives

- Headers that vary by input but are correctly keyed in the cache (intentional personalization, Vary set correctly)
- `X-Forwarded-*` reflected back but only used for logging — not a security boundary, may not be exploitable
- Browsers blocking `Location: javascript:` or `Location: data:` — capability exists in the protocol but most modern browsers refuse to navigate
- CRLF appearing in response headers but stripped by an outer proxy before reaching any client or cache
- Request smuggling indicators that turn out to be normal pipelining or keep-alive behavior

## Impact

- Cross-user cache poisoning (defacement, XSS, account takeover via cached auth response)
- Account takeover via Host-confused password-reset / OAuth flows
- Auth bypass on endpoints trusting forwarding headers
- Session fixation and cookie tossing leading to account hijack
- Open redirect for phishing / OAuth `redirect_uri` abuse
- Request smuggling — one victim's request reads another victim's response, including auth headers and cookies
- WAF / detection bypass via header-name and encoding tricks

## Pro Tips

1. The fastest win is usually Host / `X-Forwarded-Host` in a password-reset or OAuth flow — try first, costs one request
2. For cache poisoning, find the *unkeyed* input first (header that influences body but not cache key); the rest follows
3. Pair `X-HTTP-Method-Override` with content-type switching to hop CSRF and CORS preflight in one request
4. Smuggling lives at the boundary — identify the proxy → backend pair (CDN → origin, ingress → service) and target the framing disagreement
5. `X-Original-URL` / `X-Rewrite-URL` against IIS / ASP.NET admin endpoints is still a high-yield bypass
6. Before claiming a CRLF win, verify the second line landed as a real header in the cache or downstream consumer — many servers strip CRLF silently
7. Outbound email flows are a separate but related surface — user input flowing into SMTP headers (To, Cc, Subject, Reply-To) is its own injection class with the same root cause

## Summary

Header injection is fundamentally a normalization failure: somewhere on the request → response path, user input reached a header value without CR/LF stripping or proper escaping. The impact tiers up from open redirect to cache poisoning to request smuggling depending on which downstream component trusts the resulting header. Audit every header whose value moves with input, and treat every `X-Forwarded-*` / Host trust as a security boundary that needs explicit justification.
