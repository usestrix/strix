---
name: shadow-api-spa-discovery
description: Shadow/undocumented API and SPA client-side-only authorization discovery through bundle analysis and version diffing
---

# Shadow API & SPA Attack-Surface Discovery

Modern SPAs and mobile-backed APIs ship far more attack surface than the documented API spec admits: old API versions kept alive behind a "current" facade, endpoints only called from the mobile app bundle, GraphQL fields hidden from the public schema, and client-side route guards with no server-side equivalent. This surface is undocumented by design (or by neglect), which is exactly why it's under-tested.

## Attack Surface

- Any SPA/mobile app bundle, which embeds the *complete* set of API calls the client can make — a strictly larger set than what's in the public API docs
- Deprecated-but-still-live API versions (`/api/v1/` behind current `/api/v2/` docs)
- GraphQL endpoints with introspection disabled but a guessable/leaked schema
- Client-side-only route guards (React Router / Vue Router auth wrappers with no server enforcement)

## Reconnaissance

### JS-Bundle Endpoint Extraction

Pull every JS chunk the app loads (including lazy-loaded/code-split chunks, which often contain admin-only or feature-flagged routes not reachable from the default UI flow):
```
# Crawl and collect bundle URLs
katana -u https://target.com -jc -d 3 -o urls.txt
grep -E "\.js(\?|$)" urls.txt | sort -u

# Pull every chunk, extract route/API-looking strings
for js in $(cat js_urls.txt); do curl -s "$js"; done > all_bundles.js
grep -oE '"/api/[a-zA-Z0-9_/{}.\-]+"' all_bundles.js | sort -u
grep -oE '(fetch|axios\.(get|post|put|delete|patch))\([`"'"'"'][^`"'"'"']+' all_bundles.js | sort -u
```
Webpack chunks frequently contain the full route table for code-split admin panels or feature-flagged UIs even when those routes aren't linked anywhere in the currently-rendered page — grep for `route`, `path:`, and role-looking strings (`admin`, `internal`, `staff`, `ops`) across all chunks, not just the main bundle.

For mobile apps, decompile the APK/IPA (see `mobile_apk_ipa_static` skill) and grep the decompiled source/strings for base URLs and endpoint paths the mobile client calls that the web app never does — mobile apps frequently talk to a leaner, less-hardened internal API tier.

### Versioned-Endpoint Discovery

- Try incrementing/decrementing any version segment found in a documented endpoint: `/api/v2/users` → probe `/api/v1/users`, `/api/v3/users`
- Check for version negotiation via headers (`Accept: application/vnd.company.v1+json`) even when the URL shows only the current version
- Old versions are frequently kept alive for backward compatibility with an old mobile app release still in the wild, and receive far less security attention than the documented current version — test the *same* vulnerability classes (IDOR, auth bypass, injection) against the old version even if the current one is hardened

### GraphQL Schema Recovery Without Introspection

If `__schema`/`__type` introspection is disabled:
- Try field-suggestion errors: many GraphQL servers return "Did you mean `fieldName`?" on a near-miss query even with introspection off — iteratively probe common field name guesses to reconstruct the schema
- Check for a public schema file accidentally shipped in the JS bundle (some GraphQL codegen tooling embeds the schema client-side for type generation)
- Try alternate/legacy introspection-adjacent queries some implementations forget to disable: `__typename` on arbitrary fields, or the `IntrospectionQuery` sent with a modified operation name to dodge a naive string-match block
- Use `clairvoyance` or `graphql-cop`-style schema-guessing wordlists against the endpoint once you have a partial field list

### SPA Client-Side-Only Authorization

- Identify role-gated UI elements/routes (an "Admin" nav item, a `/admin` route) that are conditionally rendered based on a client-side JWT claim or Redux/Vuex store value
- Directly navigate to the gated route's URL, or directly call the API endpoint that route's UI would call, without going through the UI gate — if the server-side API doesn't independently re-check the role/claim, the "protection" was purely cosmetic
- This is functionally an authorization-testing exercise (see `broken_function_level_authorization` skill) but the discovery method here — reading the client bundle's route table — is what surfaces gated routes that aren't linked anywhere reachable in the normal UI flow

## Key Vulnerabilities

### Shadow Endpoint Exposure

Endpoints called only by the mobile app or an internal admin SPA, never documented, often skip the security review the public API received: missing rate limiting, weaker auth (API key instead of full session), verbose error messages/stack traces, or debug flags left enabled.

### Deprecated Version Regression

The old version reintroduces vulnerability classes already fixed in current — test systematically, not just spot-check, since old versions are a real regression-testing surface, not just a curiosity.

### Client-Only Route Guards

Any role/permission check implemented exclusively in client-side routing logic is bypassable by any client that doesn't run that JS — curl, a modified mobile app, or a browser devtools override of the store value before navigation.

## Bypass Techniques

- Mobile-app API endpoints frequently authenticate via a static/embedded API key instead of user session tokens — extract the key from the decompiled app and replay requests directly, bypassing any web-tier protections entirely
- GraphQL batching/aliasing to probe multiple guessed field names in a single request, reducing detection footprint from rate-limiting/WAF

## Chaining Attacks

- Shadow API discovery + IDOR: undocumented endpoints frequently have weaker object-level authorization than their documented counterparts
- Old API version + auth bypass already patched in current: full account access via a version the security team forgot still exists
- Client-side route guard bypass + sensitive data exposure: reach an "admin-only" data view directly via its underlying API call

## Testing Methodology

1. Crawl and collect every JS chunk (including lazy-loaded ones); extract every route/endpoint string
2. Decompile any associated mobile app; diff its endpoint list against the web app's
3. Probe version-segment variations on every documented endpoint
4. Attempt schema recovery on any GraphQL endpoint with introspection disabled
5. Identify client-side-only gated routes; test their underlying API calls directly, unauthenticated or under-privileged

## Validation

1. Demonstrate an endpoint/route reachable and functional that is absent from the official API documentation
2. Show it exhibits a real vulnerability (not just "exists") — auth bypass, IDOR, data exposure, injection
3. For deprecated versions: show the same class of bug already fixed in current still present in the old version

## False Positives

- Endpoint documented elsewhere (internal wiki, partner API docs) even if absent from the primary public spec
- Old version present but functionally identical in its authorization enforcement to current (no regression)
- Client-side route guard backed by an equivalent, independently-enforced server-side check

## Impact

- Full bypass of security controls applied only to the "known" API surface
- Access to admin/internal functionality via unlinked-but-live routes
- Regression exploitation of vulnerabilities already fixed in the current API version

## Pro Tips

1. Every lazy-loaded JS chunk is a potential route table for functionality not linked from the current page — always crawl deep, not just the landing page
2. Decompiling the mobile app is often the single highest-yield recon step for shadow API discovery — mobile clients rarely hide their API surface as carefully as web bundles
3. Version-segment probing is cheap and frequently productive — always try it even without other evidence of an old version's existence
4. A client-side route guard with no server-side equivalent is a complete authorization bypass, not a minor issue — treat it at the severity of the data/action it gates

## Summary

The real attack surface of a modern app is whatever its clients can call, not whatever its docs describe — bundle analysis, mobile decompilation, and version probing consistently surface endpoints the security review never saw.
