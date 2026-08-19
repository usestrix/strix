---
name: web_cache_poisoning
description: Web cache poisoning and cache deception testing covering cache-key probing, unkeyed headers, parameter cloaking, and CDN-specific behavior
---

# Web Cache Poisoning

A cache stores a response and serves it to other users based on a cache key (usually method, URL, and sometimes headers). Cache poisoning occurs when an attacker can make the origin store a response influenced by attacker-controlled, *unkeyed* input - then deliver that poisoned response to a victim. Cache deception is the sibling bug: tricking the cache into storing a sensitive, per-user response under a key an attacker can later fetch. Together they turn a single crafted request into stored XSS, defacement, DoS, or data leak served to many users.

## Attack Surface

- Cache layers: CDNs (Cloudflare, Akamai, Fastly, CloudFront), reverse proxies (Varnish, Nginx `fastcgi_cache`/`proxy_cache`), app-level caches (Redis/Django/Spring caches), service workers
- Cacheable content: pages without session-specific `Set-Cookie`, static assets, error pages, redirects, API responses with cache headers
- Inputs that influence responses but are rarely keyed: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Proto`, `X-Forwarded-Scheme`, `X-Forwarded-Port`, `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For`, cookies, `User-Agent`, custom `X-*` headers, `utm_*` query parameters, fragments
- Sinks that reflect unkeyed input: `Location`/redirects, `Set-Cookie` values, HTML injection points, JSONP responses, `Content-Type`/`Content-Disposition` headers

## Reconnaissance

1. **Find the cache**: response headers `Age`, `X-Cache: HIT/MISS`, `CF-Cache-Status`, `X-Cache-Status`, `Via`, `X-Served-By`, `Cache-Control`/`Expires`, and behavior (identical response served fast on repeat)
2. **Learn the key**: add a harmless cache-buster (`?cb=1`), then vary one input at a time and watch whether the response changes *and* stays cached:
   - `?cb=1` + `X-Forwarded-Host: test` - does a header change the response while `?cb=1` stays in the key?
3. **Identify unkeyed reflections**: every input that changes the response without changing the key is a candidate poison
4. **Classify cacheability**: pages that set `Cache-Control: public`/`s-maxage` or lack `Set-Cookie`/`Vary` are prime targets; observe `X-Cache: MISS` -> `HIT` transitions

## Key Vulnerabilities

### Unkeyed Header Poisoning

`X-Forwarded-Host` (or `X-Host`, `X-Forwarded-Proto`) used to build URLs or redirects without being keyed:

```
GET /redirect?url=/account HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.example
```

If the app redirects to `https://attacker.example/account` and the cache stores it under `GET /redirect?url=/account`, every user gets the attacker's redirect (phishing) or, with header injection, stored XSS.

### Cache Poisoning via HTML Injection

An unkeyed header reflected into HTML (correlation IDs, `X-Forwarded-For` in a footer, debug headers) plus a cacheable page equals stored XSS delivered to all users:

```
GET / HTTP/1.1
Host: target.com
X-Forwarded-For: <script>alert(document.domain)</script>
```

### Fat GET / Body-Influenced Responses

Some frameworks cache responses based on the body even when the key is GET-only (`fat GET`). An attacker-controlled body poisons a shared cache entry.

### Parameter Cloaking

The cache-key parser and the application parser disagree. Classic case: a cache treats `?utm_content=x` as part of the key while the app reads a *different* `utm_content` value when both are present, or `?foo=bar;foo=payload` where the cache keys the first and the app uses the second. Common separators: `;`, `#`, `%23`, and `&` handling differences between CDN and origin.

### Cache Deception

The app serves an authenticated, sensitive page for any path that matches a cacheable extension/pattern, and the cache stores it:

```
GET /account/settings/nonexistent.css HTTP/1.1   (app returns /account/settings HTML)
GET /account.css                                  (path normalization)
```

If `/account/*` renders the account page for any suffix and the cache stores it, the attacker fetches `/account/settings/nonexistent.css` and may receive a victim's cached account page (when a victim's request cached it first). Test with two sessions and a fresh cache.

## Bypass Techniques

- **Header name variations**: `X-Forwarded-Host` vs `X-Host` vs `Forwarded` vs `X-Forwarded-Server`; mix case; duplicate headers
- **Host confusion**: `Host: target.com.evil.com`, `Host: evil.com` when the app trusts Host for redirects but the cache keys a different virtual host
- **Encoding/normalization**: path normalization (`/./`, `//`, `%2e`, `..;/`), Unicode normalization, backslash tricks, `?x=1#` fragments that hide state from the cache
- **Method confusion**: `GET` with body, `HEAD` returning body content, `OPTIONS`/`POST` cached, `X-HTTP-Method-Override`
- **Cookie-keyed caches**: if cookies are in the key, a `Set-Cookie` reflecting unkeyed input can still poison per-session entries or, with weak keying, cross-session ones

## CDN-Specific Notes

- **Cloudflare**: `CF-Cache-Status: HIT/EXPIRED/MISS`; by default caches static extensions and ignores most headers, but custom cache rules can key or ignore specific headers; `Cache-Control: private` and `Set-Cookie` generally stop caching unless overridden
- **Fastly**: `X-Cache`/`X-Served-By`; `Vary` handling is explicit - missing `Vary: Origin` is a classic CORS+poison combo
- **Akamai**: `X-Cache: TCP_HIT`; serial-number headers identify edge; cookie and header keying rules vary by property config
- **Varnish/Nginx**: `X-Cache` via config; `Vary` is honored; `proxy_cache_key` decides what is keyed; `X-Original-URL`/`X-Rewrite-URL` poisoning is common behind Nginx

## Testing Methodology

1. **Probe cacheability** - `X-Cache`/`CF-Cache-Status` MISS then HIT on repeat with a cache-buster
2. **Map the key** - vary query params, headers, cookies, body; note which inputs change the cached response
3. **Find unkeyed reflections** - inject into every varying header/param and diff the response
4. **Poison** - craft the request, confirm the poisoned state persists across a cache-buster-free repeat (a second request from a clean session gets the attacker-controlled content)
5. **Deliver** - the poison is delivered when any user (or the app's crawler/OG-fetch) requests the poisoned key; document the delivery path (share URL, social preview, link in email, bot)
6. **Deception** - request sensitive paths with cacheable suffixes and check whether the cache stores and serves the sensitive response

## Validation

1. Prove the poisoned response is served to a *different* session (no attacker cookies, clean UA/IP) with `X-Cache: HIT`/`Age` evidence
2. Show the exact unkeyed input, the key it escaped, and the reflected sink
3. For deception: two-account proof that a victim's authenticated response is stored and fetchable by the attacker
4. Reproduce without cache-busters; the final proof must be cache-key-clean

## False Positives

- Response changes but is never cached (no HIT for other sessions) - no poisoning possible
- The "unkeyed" header is actually keyed (per-header cache entries)
- Poison only affects the attacker's own cache entry (session-cookie-keyed cache with strong keying)
- No victim delivery path (nobody else can be induced to request the poisoned key)
- Cache deception stores only the attacker's own unauthenticated response (server strips session data for that path)

## Impact

- Stored XSS delivered to every visitor of a poisoned page
- Mass phishing via poisoned redirects/login links
- Denial of service via poisoned error pages or resource exhaustion
- Account-data leakage via cache deception of authenticated responses

## Pro Tips

1. Use a unique cache-buster per probe so you never confuse app-level changes with cache state; strip it for the final proof
2. Watch `X-Cache` transitions (MISS -> HIT) as ground truth for what is actually stored
3. Test duplicate and case-varied header names; CDNs and origins disagree on which wins
4. Parameter cloaking is the highest-yield modern bypass - test `;`, `#`, `%23`, and duplicate params
5. Pair with `cors_misconfiguration` when `Vary: Origin` is missing, and with `header_injection` for CRLF-based poisoning
6. Report the delivery mechanism, not just the poison - without delivery it is a lower-severity cache issue
7. `Cache-Control: public` on authenticated pages is a deception enabler; flag it even when header-only poisoning fails

## Summary

Cache poisoning and deception are cache-key bugs: find what the cache keys, find unkeyed inputs that change the response, poison a shared entry, and prove delivery to another session. Parameter cloaking and unkeyed `X-Forwarded-*` headers are the highest-yield modern paths.
