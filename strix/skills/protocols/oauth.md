---
name: oauth
description: OAuth 2.0 and OIDC flow security testing covering redirect manipulation, token leakage, PKCE bypass, and client misconfiguration
---

# OAuth 2.0 / OIDC

OAuth and OIDC failures often enable account takeover, token theft, and cross-client token confusion. Treat every redirect, client identifier, and token exchange as an authorization boundary — not a convenience layer.

## Attack Surface

**Flows**
- Authorization code (with/without PKCE)
- Implicit (legacy), hybrid, device authorization, client credentials
- Refresh token rotation, token introspection, revocation

**Endpoints**
- `/authorize`, `/token`, `/userinfo`, `/introspect`, `/revoke`, `/logout`
- `/.well-known/openid-configuration`, `/jwks.json`
- Dynamic client registration (if enabled)

**Token Types**
- Authorization codes, access tokens, refresh tokens, ID tokens
- Opaque vs JWT formats; reference tokens vs self-contained JWTs

**Client Types**
- Public clients (SPAs, mobile) vs confidential (server-side)
- Multiple redirect URIs, wildcard/pattern matching, custom URI schemes

## Reconnaissance

**Discovery**
```
GET /.well-known/openid-configuration
GET /oauth2/.well-known/openid-configuration
GET /.well-known/oauth-authorization-server
```

Extract: `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, supported `response_types`, `code_challenge_methods_supported`, `grant_types_supported`.

**Client Enumeration**
- Inspect JS bundles, mobile APK/IPA configs, GitHub repos for `client_id`, redirect URIs, scopes
- Check error messages for client validation hints ("invalid redirect_uri", "unregistered client")

## Key Vulnerabilities

### Redirect URI Manipulation

**Open Redirect Chains**
- Register or guess permissive redirect patterns: `https://app.com/callback`, path-prefix only, subdomain wildcards
- Test: append paths, fragments, query injection, `@` tricks, encoded slashes, backslash variants

```
https://app.com/callback.evil.com
https://app.com/callback%2f..%2f@evil.com
https://app.com/callback?next=https://evil.com
com.app://callback  (mobile custom scheme)
```

**Redirect URI Validation Bypasses**
- Trailing slash, case, port, scheme downgrade (`http` vs `https`)
- Path normalization differentials between IdP validator and consuming app
- `redirect_uri` parameter pollution (first vs last wins)
- Wildcard subdomain acceptance: `*.app.com` → register `attacker.app.com` or find dangling subdomain

#### Decode / Parse / Render Differentials

Treat validation, redirect construction, and browser navigation as separate consumers. For each candidate, preserve this representation ledger:

```text
raw authorize-request bytes
  -> query-parser value
  -> explicit decode/canonicalization
  -> URL components checked by the validator
  -> value used to build Location
  -> browser-parsed origin/path/query/fragment
  -> authorization-code destination
```

Do not collapse these stages into “URL decoded.” Disable redirect following while mapping server behavior, then use a controlled browser to prove the final origin and the component containing the code.

#### Mandatory Execution Gate

Before ruling out a `redirect_uri` differential:

1. Keep one owner across the authorization server and client callback. Use a discovered receiver only when it is authorized. Otherwise, start a distinct-origin receiver inside the controlled test environment; this is test instrumentation, not permission to probe the discovered asset. If no controlled receiver is reachable from the browser, record `needs_follow_up` rather than a negative result.
2. Execute the reference harness below before any ad hoc payload list. Substitute only the controlled receiver and trusted callback values. Do not replace it with a custom generator; a port to another language must preserve its completeness and round-trip assertions. Never hand-splice already-encoded wire fragments.
3. Capture a bounded compound matrix for controlled-receiver prefix + trusted-authority suffix using `#`, `?`, slash, and backslash boundaries combined with authority delimiters at independent depths, plus clean and obvious-rejection controls. Do not privilege a presumed winning tuple; derive interesting rows from observed response differences.
4. Persist a row ledger containing the tuple, framework value, intended wire token, captured wire token, status, raw `Location`, browser-final origin, code destination, and redemption result. Missing, duplicate, timed-out, or killed rows are incomplete coverage regardless of payload count.

#### Transport Round-Trip Contract

Define depth at the post-query-parser value `F`, not at the source literal. Use this executable pattern, substituting authorized receiver and trusted callback values:

```python
from urllib.parse import quote, unquote

def E(value, depth):
    for _ in range(depth):
        value = quote(value, safe="")
    return value

def prepare(receiver, left, left_depth, right, right_depth, trusted):
    F = receiver + E(left, left_depth) + E(right, right_depth) + trusted
    T = quote(F, safe="")
    V = unquote(F)
    R = unquote(V)
    assert unquote(T) == F
    return {
        "left": left,
        "left_depth": left_depth,
        "right": right,
        "right_depth": right_depth,
        "F": F,
        "T": T,
        "V": V,
        "R": R,
    }

LEFTS = ("#", "?", "/", "\\")
RIGHTS = ("@",)
DEPTHS = tuple(range(3))

rows = [
    prepare(
        "http://receiver.invalid",
        left,
        left_depth,
        right,
        right_depth,
        "trusted.invalid/callback",
    )
    for left in LEFTS
    for right in RIGHTS
    for left_depth in DEPTHS
    for right_depth in DEPTHS
]
expected = len(LEFTS) * len(RIGHTS) * len(DEPTHS) * len(DEPTHS)
tuples = {
    (row["left"], row["left_depth"], row["right"], row["right_depth"])
    for row in rows
}
assert len(rows) == expected
assert len(tuples) == expected
assert all(unquote(row["T"]) == row["F"] for row in rows)
```

When manually building the query, send `T` unchanged after `redirect_uri=`. When using `params=`, `URLSearchParams`, or `urlencode`, pass `F` and inspect the prepared request to confirm it produced `T`; never pass raw `F` or serialize `T` again. Never mark `%` safe. Apply depth by repeated calls to `E`; repeating an encoded substring is not nested encoding. Reject placeholder expressions, unused loop variables, or a ledger whose observed and unique tuple counts do not equal `expected`. Extend the named stages if the observed pipeline has more or fewer transformations. Store `F`, `T`, `query_decode(T)`, `V`, `R`, status, and raw `Location`; label any mismatch `harness_invalid`. Payload count alone is not coverage.

Send this bounded matrix before expanding into a larger generic fuzz set. Batch or resume it if necessary. A timeout, killed process, partial output, handwritten substitute, or uncaptured request leaves the family `needs_follow_up`; none can support `ruled_out`.

Use a bounded matrix rather than a generic spray:

- vary fragment, query, slash, backslash, and userinfo delimiters independently at depths `E0..E2`, extending only when evidence shows another transformation;
- cover `#` + `@`, `?` + `@`, slash + `@`, and backslash + `@`, including asymmetric depths;
- test both mutations after the trusted callback and this controlled-prefix layout:

```text
<controlled-receiver-origin>
  + E_i(<late structural delimiter>)
  + E_j(<authority/userinfo delimiter>)
  + <registered-authority-and-callback-path>
```

- pair every candidate with clean registered, obvious foreign, literal, and shallower-encoded controls.

Synthesize backward from the dangerous browser-final structure: choose the receiver and code boundary, encode each delimiter enough to remain non-structural during validation, then verify both validator components and browser-final URL. The finding requires a security-relevant difference, not merely an accepted encoded string.

**Closure gate:** after decoder or parser drift appears, do not rule out an external-origin bypass until the compound matrix has passing completeness and round-trip assertions, every row has a captured request and raw response, and a controlled browser verifies the final origin for every accepted differential. A same-origin fragment is a primitive to compose with authority-changing delimiters. If the intended framework value cannot be proven from the captured request, the matrix was partial, or a receiver/browser proof was unavailable, record `needs_follow_up`, not `ruled_out`. Do not claim structural impossibility while an observed extra decode or reparse remains unmodeled.

Keep testing local and authorized. Use a synthetic account and a controlled receiver on a distinct origin. Never send a code or token to an unapproved external collector.

### Authorization Code Issues

**Code Leakage**
- Codes in URL fragments, Referer headers, browser history, server logs, analytics
- Code replay before expiry; missing one-time-use enforcement
- Code sent to wrong redirect_uri if binding is weak
- When a crafted redirect changes origin after validation, determine whether the code lands in the request URL, query, or fragment. URL fragments are not sent in the receiver's HTTP request; browser-side evidence such as `location.hash` is required to prove collection.

**Code Injection / Mix-Up**
- Attacker initiates flow, victim completes login, code delivered to attacker's redirect
- Mix-up attack: swap `client_id` between authorize and token steps
- Missing `redirect_uri` binding at token endpoint

### State and Nonce

- Missing, predictable, or reusable `state` → test CSRF on OAuth login (session fixation, account linking); RFC 9700 also permits correctly bound PKCE, or OIDC `nonce`, to provide CSRF protection, so establish whether that protection survives a cross-session callback
- Missing `nonce` in OIDC → ID token injection/replay
- `state` not bound to client session or PKCE verifier

### PKCE Bypass

- `code_challenge_method` downgrade: accept `plain` instead of `S256`
- Missing PKCE requirement on public clients
- `code_verifier` not validated or compared case-insensitively with weak matching
- Authorization code issued without challenge, token endpoint accepts any verifier

### Client Authentication

**Public Client Abuse**
- Token endpoint accepts requests without `client_secret` for confidential clients
- `client_id` only authentication on token/introspection endpoints
- Dynamic registration with attacker-controlled redirect URIs

**Secret Leakage**
- Hardcoded secrets in mobile apps, SPAs, or public repos
- `client_secret` accepted in query string or logged in access logs

### Scope and Token Issues

- Scope escalation: request `admin`/`offline_access`/`openid profile email` beyond app need; server grants all requested scopes
- Public-client refresh tokens neither sender-constrained nor rotated with reuse detection → persistent access; a non-rotating token bound to the client's key is permitted by RFC 9700, so test replay without that key
- Access token accepted across services (missing audience/resource binding)
- Token introspection returns `active:true` without proper auth on introspection endpoint

### OpenID Connect Specific

- ID token accepted as access token at resource servers (token confusion)
- `acr`, `amr`, `auth_time` not validated for step-up requirements
- Userinfo endpoint returns PII without matching access token scope
- `sub` collision across issuers if `iss` not validated

### OAuth Security BCP (RFC 9700)

Authorization servers must support PKCE, public clients must use it, and confidential clients are also recommended to use it. Test challenge stripping and verifier injection across both client types. Resource-owner-password grants must not be used; implicit access-token responses are discouraged because tokens can leak or be replayed. For mix-up defenses, bind the selected issuer and endpoints to the authorization transaction; validate an authorization-response `iss` when that defense is used, rather than merely checking the issuer of a later ID token ([RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)).

## Advanced Techniques

**Referer Leakage**
- Embed authorized redirect as subresource on attacker page; harvest `code` from Referer if policy allows

**Device Flow Abuse**
- Poll `device_code` endpoint with guessed codes; slow rate limits only
- User approves attacker-initiated device login

**Account Linking**
- OAuth login links attacker's IdP identity to victim's local account without re-auth
- Email collision: same email from different IdP providers

## Testing Methodology

1. **Map flows** — Identify all grant types, clients, and redirect URIs in use
2. **Map representations** — Preserve raw request bytes, query-decoded value, validator components, emitted `Location`, and browser-final URL
3. **Redirect matrix** — For each client, test bounded asymmetric delimiter-depth pairs, including receiver-prefix + trusted-authority-suffix candidates, with clean and obvious-rejection controls
4. **Prove destination** — Use a controlled distinct-origin receiver; capture the final origin and the exact component containing the code
5. **CSRF** — Initiate OAuth without `state`; swap sessions mid-flow
6. **PKCE** — Replay codes with wrong/missing verifier; downgrade challenge method
7. **Token exchange** — Compare authorize-step and token-step binding of the exact `redirect_uri`; test cross-client/audience acceptance
8. **Mobile/deep links** — Custom schemes, intent filters, universal links hijacking

## Validation

1. Demonstrate stolen authorization code or token via redirect manipulation or Referer leak
2. Show account takeover or access to victim resources with attacker's OAuth session
3. Prove CSRF: victim completes login into attacker's linked session without consent UI bypass where applicable
4. Document exact validation gap (redirect binding, PKCE, state, audience)
5. Provide full authorize → callback → token request chain with before/after evidence
6. For parser/decoding mismatches, include the validator-seen URL components, raw `Location`, browser-final origin, and whether the code was in query or fragment
7. State whether PKCE, confidential-client authentication, redirect binding, one-time use, or sender constraints prevent redemption; code disclosure and account takeover are separate claims

## False Positives

- Redirect URI rejected consistently across all bypass attempts
- After the closure gate is satisfied, a strange encoded URI is accepted but the emitted and browser-final origins remain registered and no code/token reaches another origin. A same-origin result from only one delimiter/depth is not enough to close the family.
- Public client correctly requires PKCE S256 with strict verifier validation
- `state`/`nonce` enforced and bound; CSRF test fails as expected
- Token audience/issuer correctly validated at resource server
- Custom scheme redirects require app ownership proof (verified Android/iOS app links)

## Impact

- Full account takeover via stolen authorization codes or tokens
- Persistent access through refresh token theft
- Cross-tenant or cross-client data access via token confusion
- PII exposure from userinfo or ID token claim leakage

## Pro Tips

1. Always capture the full redirect chain including intermediate 302 locations
2. Compare authorize-step and token-step parameter binding (`redirect_uri`, `client_id`, PKCE)
3. Test both web and mobile clients — validation rules often differ
4. Check logout/revocation — tokens may remain valid after "logout"
5. Chain with open redirect or XSS on the legitimate redirect_uri to exfiltrate codes
6. `state` protects transaction integrity; it does not make a code safe after the browser is redirected to an attacker-controlled origin
7. A code leak can be valid even when PKCE prevents redemption, but severity must reflect the demonstrated capability and deployment prerequisites

## Tooling

The sandbox ships **jwt_tool** (already cloned at `/home/pentester/tools/jwt_tool`) plus `curl` — enough for the token side of OAuth/OIDC.

- **jwt_tool** (ticarpi) — inspect and tamper ID tokens / JWT access tokens: `alg:none`, `HS256`/`RS256` key confusion, `kid` injection, claim editing (`sub`, `aud`, `iss`, `exp`):
  ```
  python3 /home/pentester/tools/jwt_tool/jwt_tool.py <ID_TOKEN>                    # decode/inspect
  python3 /home/pentester/tools/jwt_tool/jwt_tool.py <ID_TOKEN> -X a               # alg:none
  python3 /home/pentester/tools/jwt_tool/jwt_tool.py <ID_TOKEN> -X k -pk pub.pem   # RS256->HS256 confusion
  ```
- **curl** — drive the authorize → callback → token chain by hand so you control every parameter (`redirect_uri`, `client_id`, `state`, PKCE `code_challenge`/`code_verifier`) and can test the binding/downgrade cases above.

Humans often use Burp's **EsPReSSO** (RUB-NDS) SSO extension for flow visualization; it is GUI-only, so prefer manual `curl` + `jwt_tool` in-sandbox.

## Summary

OAuth security hinges on strict redirect URI binding, unguessable state/nonce, PKCE for public clients, and consistent token audience validation. Any gap in the authorize-to-token chain is a potential account takeover.
