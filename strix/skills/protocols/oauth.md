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

### Authorization Code Issues

**Code Leakage**
- Codes in URL fragments, Referer headers, browser history, server logs, analytics
- Code replay before expiry; missing one-time-use enforcement
- Code sent to wrong redirect_uri if binding is weak

**Code Injection / Mix-Up**
- Attacker initiates flow, victim completes login, code delivered to attacker's redirect
- Mix-up attack: swap `client_id` between authorize and token steps
- Missing `redirect_uri` binding at token endpoint

### State and Nonce

- Missing, predictable, or reusable `state` → CSRF on OAuth login (session fixation, account linking)
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
- Refresh token not rotated or reuse not detected → persistent access
- Access token accepted across services (missing audience/resource binding)
- Token introspection returns `active:true` without proper auth on introspection endpoint

### OpenID Connect Specific

- ID token accepted as access token at resource servers (token confusion)
- `acr`, `amr`, `auth_time` not validated for step-up requirements
- Userinfo endpoint returns PII without matching access token scope
- `sub` collision across issuers if `iss` not validated

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
2. **Redirect matrix** — For each client, fuzz redirect_uri validation with encoding and parser tricks
3. **CSRF** — Initiate OAuth without `state`; swap sessions mid-flow
4. **PKCE** — Replay codes with wrong/missing verifier; downgrade challenge method
5. **Token exchange** — Swap codes/tokens between clients; test cross-audience acceptance
6. **Mobile/deep links** — Custom schemes, intent filters, universal links hijacking

## Validation

1. Demonstrate stolen authorization code or token via redirect manipulation or Referer leak
2. Show account takeover or access to victim resources with attacker's OAuth session
3. Prove CSRF: victim completes login into attacker's linked session without consent UI bypass where applicable
4. Document exact validation gap (redirect binding, PKCE, state, audience)
5. Provide full authorize → callback → token request chain with before/after evidence

## False Positives

- Redirect URI rejected consistently across all bypass attempts
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
