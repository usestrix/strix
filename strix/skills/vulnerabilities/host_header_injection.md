---
name: host-header-injection
description: Host header injection testing for password-reset poisoning, routing SSRF, and virtual-host confusion
---

# Host Header Injection

The `Host` header (and its `X-Forwarded-*` cousins) is frequently trusted by application code to build absolute URLs, route requests internally, or select a tenant — while being entirely attacker-controlled on the wire. Any place a server reflects or routes on `Host` without validating it against an allowlist is exploitable.

## Attack Surface

- Password-reset / email-verification link generation (`https://{Host}/reset?token=...`)
- Internal routing/load-balancer logic keyed on `Host` for multi-tenant or microservice dispatch
- Absolute-URL generation in any server-rendered page (canonical links, Open Graph tags, redirect targets)
- Virtual-host-based backend selection (shared infra serving multiple domains off one IP)

## Reconnaissance

```
curl -H "Host: attacker-controlled.com" https://target.com/
curl -H "Host: target.com" -H "X-Forwarded-Host: attacker-controlled.com" https://target.com/
```
- Diff the response for reflected values: absolute URLs, `Location` redirects, rendered links, meta tags
- Enumerate every header variant a front-end/CDN might forward but not validate: `Host`, `X-Forwarded-Host`, `X-Forwarded-Server`, `X-Host`, `X-Original-Host`

## Key Vulnerabilities

### Password-Reset Poisoning

If the reset-link email is generated server-side using the request's `Host` header:
```
POST /forgot-password HTTP/1.1
Host: attacker.com
X-Forwarded-Host: attacker.com

email=victim@target.com
```
The victim receives a legitimate email from the real sending domain, but the reset link points at `https://attacker.com/reset?token=<real_token>`. If the victim (or their mail client's link-preview bot) clicks it, the token is delivered to the attacker's server logs — full account takeover without ever touching the victim's session.

Test both `Host` directly and every `X-Forwarded-*` variant, since front-end proxies often normalize `Host` but forward `X-Forwarded-Host` unchecked to the origin.

### Routing-Based SSRF

In environments where `Host` selects an internal upstream (common in shared reverse-proxy setups, multi-tenant SaaS, or internal service meshes), setting `Host` to an internal address can cause the front-end to route the request to unintended internal infrastructure:
```
GET / HTTP/1.1
Host: 169.254.169.254
```
or an internal service name (`Host: internal-admin.svc.cluster.local`) — if the routing layer resolves upstream by `Host` value rather than a fixed backend pool, this is effectively SSRF via routing confusion. Cross-reference the `ssrf` skill for cloud-metadata-endpoint follow-up once internal routing is confirmed.

### Cache Poisoning Overlap

Host-header injection is frequently the *mechanism* behind a cache-poisoning finding (unkeyed `X-Forwarded-Host` reflected into cached HTML) — see `cache_poisoning` skill for the caching-layer half of this technique. Always test whether a successful Host-header injection is also **cacheable**, which upgrades a single-victim attack into a mass one.

### Virtual-Host / Internal-Host Confusion

- Shared hosting/CDN edges terminate TLS for many domains on one IP; sending a `Host` for a *different* customer's domain to that shared IP can reveal internal-only vhosts, staging environments, or admin panels not meant to be reachable from the public internet
- Try common internal hostnames: `admin.internal`, `localhost`, `127.0.0.1`, the bare IP, `default`, staging/dev subdomain guesses
- Absolute-`request-target` HTTP/1.1 requests (`GET http://internal-host/ HTTP/1.1`) can bypass front-end `Host`-based routing entirely on some proxy configurations

### `X-Forwarded-Host` vs `Host` Precedence

Test which header wins when both are present and disagree — front-end and origin frequently pick different ones, and the discrepancy itself can be abused to smuggle a value past a `Host`-only allowlist check while the origin's URL-generation code reads `X-Forwarded-Host` instead.

## Bypass Techniques

- Header duplication: send `Host` twice with different values (`Host: target.com\r\nHost: evil.com`) to exploit front-end/origin disagreement on which one wins
- Absolute-URI request line instead of a `Host` header (HTTP/1.1 allows `GET http://host/path HTTP/1.1`)
- Port injection: `Host: target.com:evil.com` or `Host: target.com@evil.com` to exploit URL-parsing confusion in code that naively string-concatenates the header into a URL
- Case variation and whitespace padding around the header value if the allowlist check is a naive string match

## Chaining Attacks

- Host header poisoning + cache poisoning: mass-deliver the poisoned reset link to every visitor, not just one victim
- Host header SSRF + cloud metadata: pivot internal routing confusion into cloud credential theft
- Virtual-host confusion + subdomain takeover: discover an internal/staging vhost that's independently vulnerable

## Testing Methodology

1. Send baseline request, capture all URLs/redirects/reflected values in the response
2. Vary `Host` and every `X-Forwarded-*` variant independently, diffing the response each time
3. Specifically trigger the password-reset flow with a manipulated `Host`/`X-Forwarded-Host` and inspect the actual email/token delivery
4. Test absolute-request-target and header-duplication bypasses if a naive allowlist is suspected
5. Confirm whether any successful injection is cacheable

## Validation

1. Show the manipulated host value appearing in a security-relevant context (reset link, redirect target, internal route)
2. For reset-poisoning: demonstrate the actual token reaching attacker-controlled infrastructure (use a request-bin/collaborator domain, not a real third party)
3. For routing SSRF: demonstrate a response distinguishable from the normal target (internal service banner, different content, internal-only data)

## False Positives

- `Host` validated against a strict allowlist server-side (reflected value visually looks attacker-controlled but is actually rejected/normalized before use)
- Reflection present in a non-security-relevant context (e.g., a debug/error page only reachable by admins)

## Impact

- Full account takeover via poisoned password-reset links
- Internal network access / SSRF pivot via routing confusion
- Mass exploitation when chained with cache poisoning

## Pro Tips

1. Always test the actual password-reset email delivery, not just the HTTP response — the injection matters most where it reaches a human via email/SMS
2. Test every `X-Forwarded-*` variant independently; apps validate `Host` far more often than they validate its forwarded cousins
3. A successful Host-header finding with no cacheability is still a real, single-victim finding — don't discard it for lack of chaining
4. Collaborator/request-bin domains make blind confirmation of email-based poisoning straightforward

## Summary

Host-header trust is an authorization/allowlisting bug disguised as a convenience feature — any server-side use of `Host` or its forwarded variants to build a URL or route a request must be checked against a strict allowlist, not just reflected as received.
