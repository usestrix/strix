---
name: cache-poisoning
description: Web cache poisoning and cache deception testing across CDN, reverse-proxy, and origin cache layers
---

# Web Cache Poisoning & Cache Deception

A cache stores a response and replays it to other users. If the cache key doesn't include everything that varies the response, or the origin trusts a header the cache doesn't key on, an attacker can poison the cached copy — turning a single malicious request into a stored, self-replaying payload served to every subsequent visitor.

## Attack Surface

- **Cache layers**: CDN (Cloudflare, Fastly, Akamai, CloudFront), reverse proxy (Varnish, Nginx, Squid), application-level cache (Rails/Django page cache), API gateway cache
- **Cacheable endpoints**: static-looking paths, `Cache-Control: public`/`s-maxage` responses, anything fronted by a CDN with a permissive default TTL
- **Unkeyed inputs**: headers, cookies, query params the origin reads but the cache doesn't include in its cache key

## Reconnaissance

**Identify what's cached**
- Probe for `X-Cache: HIT/MISS`, `Age`, `CF-Cache-Status`, `X-Varnish`, `Via` headers
- Send the same request twice with a cache-buster (`?cb=<random>`); if the second identical request (same cache-buster) returns identical content on repeat, it's cached
- Check `Cache-Control`, `Vary`, `Surrogate-Control`, `Expires` on responses — `Vary` lists what the cache *does* key on; anything the origin reflects that's absent from `Vary` is a candidate unkeyed input

**Find unkeyed inputs**
- Use `param-miner`/`Param Miner` (Burp) or manual probing: inject a header/param with an easily-identifiable reflected marker, reload with a cache-buster, check if the marker persists in the cached response
- High-value unkeyed headers: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Original-URL`, `X-Rewrite-URL`, `X-Host`, `X-HTTP-Method-Override`

## Key Vulnerabilities

### Unkeyed-Header Poisoning

Inject a payload via a header the origin trusts but the cache doesn't key on, then confirm the poisoned response is served to a clean, unauthenticated request:

```
GET /page?cb=12345 HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
```

If the origin reflects `X-Forwarded-Host` into an absolute URL, canonical link, or a loaded script `src`, and the cache stores the response keyed only on path+query, every subsequent visitor to `/page?cb=12345` gets the poisoned response pointing at `evil.com` — a stored, cache-wide XSS/redirect.

Also test: `X-Forwarded-Scheme: http` downgrading HTTPS-only assets, `X-Forwarded-Port` altering generated links, and header **duplication** (`X-Forwarded-Host: legit.com` + a second `X-Forwarded-Host: evil.com` — front-end and origin may pick different instances).

### Cache-Key Normalization Mismatches

- **Case sensitivity**: `/Page` vs `/page` — cache may treat as distinct or identical, differently from the origin's router
- **Trailing slash / double slash**: `/api//user` vs `/api/user`
- **Parameter order/casing**: some caches normalize query param order, others don't; the origin might treat `?a=1&b=2` differently from `?B=2&A=1` while the cache serves the same cached entry for both
- **Query param cloaking (fat GET)**: append an ignored param the cache doesn't key on but that still lets you target a specific cached slot: `/reset-password?utm_source=x` — vary `utm_source` to poison distinct cache entries without colliding with legitimate traffic, then wait for a real victim to hit the exact same cache-buster value (or brute a low-entropy value range)

### Cache Deception

The inverse of poisoning: trick the cache into storing a **personalized, authenticated** response under a path the cache treats as static.

```
GET /account/settings.js HTTP/1.1
Cookie: session=victim_session_here
```

If the routing framework treats `.js`/`.css`/`.jpg` as static-file extensions and serves the authenticated page content anyway (path confusion — the router matches `/account/settings` and ignores the fake extension, or falls through to a catch-all), and the CDN caches based on the static-looking extension, the victim's authenticated response — including PII, CSRF tokens, session-bound data — gets cached and served to the next unauthenticated visitor of that exact URL. Confirm by requesting the same crafted URL unauthenticated afterward.

### CDN-Specific Quirks

- **Cloudflare**: caches by default on `Cache Everything` page rules or `Cache-Control` presence; check for `CF-Cache-Status`; Cloudflare Workers/Transform Rules can introduce their own unkeyed logic
- **Fastly (VCL)**: custom VCL often manually copies headers into the cache key or origin request — audit for `X-Forwarded-*` handling in any exposed VCL snippets or via differential probing
- **Akamai**: cache-key includes/excludes are configured per-property; test `Accept-Encoding` variance (gzip vs identity) as a common unkeyed axis
- **CloudFront**: cache behaviors define which headers/cookies/query strings are forwarded and keyed — anything forwarded-but-not-keyed is poisonable

## Bypass Techniques

- **Internal cache poisoning**: some apps have an internal cache in front of a slower cache (e.g., app-level fragment cache behind a CDN) — poison the inner layer even when the outer CDN correctly keys everything
- **Cache probing via timing**: when `X-Cache` headers are stripped, use response-time deltas (cache HIT is faster) to infer cache behavior blind
- **Multiple header instances**: send the same header twice with different values to exploit front-end/origin disagreement on which one wins
- **HTTP/1.1 request smuggling into cache**: combine with `http_request_smuggling` techniques to poison a shared front-end cache with a desynced response

## Chaining Attacks

- Cache poisoning + reflected XSS: turn a reflected XSS into a stored, cache-wide XSS served to every visitor without further interaction
- Cache poisoning + open redirect: poison the cache with a redirect payload for mass phishing
- Cache deception + IDOR: deceive the cache into storing another user's authenticated page, then read it unauthenticated

## Testing Methodology

1. Enumerate cache-presence signals (`X-Cache`, `Age`, `Via`, response-time deltas)
2. Fuzz for unkeyed inputs (headers, cookies, params) using a unique reflected marker + cache-buster
3. For each unkeyed input found, test whether the origin's use of it is exploitable (XSS, redirect, SSRF-adjacent path)
4. Confirm poisoning persists: request the exact poisoned URL from a **second, clean session/IP** and verify the payload is served without re-injecting it
5. For cache deception, test static-extension path confusion against every authenticated, personalized endpoint

## Validation

1. Demonstrate the payload persists in the cache and is served to a request that never sent the payload itself
2. Show the poisoned response is served to an unauthenticated/different-session client
3. Quantify blast radius: shared cache key (all users) vs per-user/per-geo cache partition

## False Positives

- Cache correctly varies on the injected input (`Vary` includes it, or a second clean request doesn't reflect the payload)
- Reflected value present in the response but not cached (private/no-store responses)
- CDN configured with short TTL that self-heals before a practical exploitation window — still report, but note reduced severity

## Impact

- Mass stored XSS / malicious redirect served to every visitor of the poisoned URL
- Cross-user PII/session data exposure via cache deception
- Denial of service (poisoning critical paths like login/checkout with broken responses)

## Pro Tips

1. Always confirm with a *second, independent* request — a single reflection isn't poisoning, persistence is
2. `Vary` header lies less than documentation; diff it against what the origin actually reads
3. Cache deception needs no header injection at all — just a routing/extension confusion, making it viable even when no unkeyed input exists
4. Test both the CDN edge and any internal/origin-adjacent cache layer separately
5. Low-TTL caches still matter for high-traffic endpoints — poisoning a 60-second cache on a login page hits many victims

## Summary

Cache poisoning exploits the gap between what a cache keys on and what the origin actually uses to build a response; cache deception exploits routing confusion to make a cache store something it was never meant to. Both turn a single request into a stored attack against every subsequent visitor.
