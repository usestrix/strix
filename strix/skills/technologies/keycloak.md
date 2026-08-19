---
name: keycloak
description: Keycloak identity-provider security testing covering realm/client misconfiguration, redirect_uri abuse, identity broker SSRF, and token handling
---

# Keycloak

Keycloak is the most widely deployed open-source identity provider (IdP). Compromise it and you control every application that trusts it. The attack surface is mostly configuration: exposed admin consoles, permissive realm settings (self-registration, direct access grants), public clients with weak redirect validation, identity-broker federation that fetches attacker-chosen metadata, and JWT handling on both the Keycloak side and the relying apps.

## Attack Surface

- Admin console: `/admin` (master realm), realm admin consoles, REST `/admin/realms/*`
- Well-known and protocol endpoints: `/realms/{realm}/.well-known/openid-configuration`, `/realms/{realm}/protocol/openid-connect/{auth,token,userinfo,logout,registrations}`, `/realms/{realm}/account`, `/realms/{realm}/protocol/saml`
- Dynamic client registration: `/realms/{realm}/clients-registrations/openid-connect` (with/without initial access token)
- Identity brokering: OIDC/SAML IdP federation ("import from URL", metadata fetch), first-login flows, account linking
- Default credentials and bootstrap admin: admin account created on first boot with a console-generated or configured password; check for default/weak/leaked admin creds
- Clients: public vs confidential, redirect URIs, direct access grants, service accounts, token lifetime and audience settings
- Custom themes (FreeMarker templates) and SPI extensions - template injection when user input reaches them
- End-user flows: registration, password reset, account console, brute-force protection config, user enumeration

## Reconnaissance

1. **Enumerate realms**: `/realms/master/.well-known/openid-configuration` confirms the server; guess/scan realm names (`master`, app names) via `/realms/<name>/.well-known/openid-configuration` or `/auth/realms/...` (older prefix)
2. **Check the admin console**: reachable? Login page realm? Try default credentials only when engagement rules allow; otherwise note exposure
3. **Pull client metadata**: from the OpenID config (`authorization_endpoint`, `token_endpoint`), then `client_id` values visible in the login page/network traffic
4. **Test dynamic registration**:
   ```
   POST /realms/{realm}/clients-registrations/openid-connect
   Content-Type: application/json
   {"client_name":"x","redirect_uris":["https://attacker.example/"]}
   ```
   If a client is created without an initial access token, you can register your own OAuth client (often abused for authorization-code theft or token minting in misconfigured realms)
5. **Fingerprint version** from headers (`Server: Keycloak`), error pages, or `/realms/master/.well-known/openid-configuration` issuer format
6. **Source-aware** (self-hosted configs): `realm-export.json`, `keycloak.conf`, custom themes, and client settings in the repo

## Key Vulnerabilities

### Exposed/Weak Admin Console

- `/admin` reachable from the internet with no IP restriction - brute-force/credential-stuffing target and config hijack vector
- Default bootstrap admin credentials never changed (admin/admin is only default in dev images, but weak passwords are common)
- Realm admin accounts with excessive roles; `manage-realm`/`manage-clients` on shared accounts

### Realm Misconfiguration

- **Self-registration enabled** with default roles that include privileged groups or no verification
- **Direct access grants** enabled on public clients: password grant without 2FA/rate limiting -> credential stuffing
- **Brute-force protection disabled** (`bruteForceProtected=false`) - unlimited login attempts
- **Password policy weak/absent**; email verification disabled
- Realm shared with production apps (master realm used for real apps) - any realm admin becomes cross-app admin

### Client Misconfiguration

- Public clients (no secret) where confidential flow is required
- `redirect_uris` too broad: `*` suffix, path-prefix matches that accept attacker paths, wildcard hosts
- `web_origins` misconfig enabling token theft via registered CORS origins
- Token lifetimes too long; refresh tokens not rotated; audience not enforced by relying apps
- Service accounts with excessive client roles

### Redirect URI / Authorization Code Abuse

With a permissive redirect allowlist:

```
/realms/{realm}/protocol/openid-connect/auth?client_id=app&redirect_uri=https://attacker.example/&response_type=code&scope=openid
```

If `redirect_uri` is accepted, the authorization code lands on the attacker's origin and can be exchanged for a token (account takeover, see `oauth` skill for the full flow matrix).

### Identity Broker SSRF

Adding/federating an IdP by URL makes Keycloak fetch attacker-controlled metadata (OIDC discovery, SAML metadata, JWKS):

- Attacker-hosted metadata -> Keycloak SSRF to internal endpoints (metadata URL validation gaps; historical CVEs)
- OIDC "issuer" trust confusion -> login CSRF / token injection
- Account linking with attacker-controlled email/attributes -> account takeover of linked identities

Test with an OAST/metadata endpoint you control (see `ssrf` and `interactsh` skills) and internal URL targets when in scope.

### Token / JWT Handling

- Relying apps that verify signature but not `iss`/`aud`/`azp` accept tokens minted for other clients/realms (see `authentication_jwt`)
- JWKS caching/rotation gaps in apps; key confusion across realms
- `typ` confusion: ID token accepted where access token required

### User Enumeration and Flows

- Login error differences (`Invalid username or password` vs `Account with this username already exists` in registration)
- Password-reset responses differ for existing vs nonexistent accounts
- Account console endpoints leak user attributes

## Advanced Techniques

- **Client registration abuse**: register a client with broad redirect URIs, then run the full OAuth attack set against apps using it
- **Broker account linking**: federate an attacker-controlled OIDC IdP with matching email, then link to a victim account during first-login (classic account-takeover chain)
- **Admin REST without auth**: probe `/admin/realms/{realm}` and `/admin/serverinfo` unauthenticated; older versions leaked server info or allowed unauthenticated client registration
- **Custom theme injection**: FreeMarker templates that render user input -> SSTI (see `ssti`)
- **Token minting via service account**: if a service account has realm-management roles (`realm-admin`), its token can call admin APIs - check its effective roles
- **Cross-realm token reuse**: token from realm A accepted at realm B's apps when audience/issuer checks are weak

## Testing Methodology

1. Enumerate realms, admin console exposure, and version
2. Pull OpenID configs and client IDs; test dynamic registration
3. Test redirect_uri validation with attacker origins (full OAuth flow)
4. Audit realm settings: registration, direct grants, brute-force protection, password policy
5. Test identity-broker metadata fetch for SSRF/OAST
6. Check user enumeration in login/register/reset flows
7. Validate relying apps' token checks (iss/aud/typ)

## Validation

1. Redirect abuse: complete the code exchange and authenticate as the victim user (minimal, non-destructive)
2. Registration: create an account and demonstrate access to a restricted resource
3. Broker SSRF: OAST hit or internal response from the metadata fetch
4. Token confusion: show a token accepted by the wrong app/realm
5. Admin exposure: show reachable admin console and its protection status (no brute force attempted unless authorized)

## False Positives

- Redirect_uri rejects attacker origins (validation working) - no finding
- Registration enabled but new accounts get no privileged roles (low severity at most)
- Direct access grants present but rate-limited and 2FA-enforced
- Broker metadata fetch blocked by allowlist/DNS pinning
- Admin console reachable but locked with strong auth (exposure note only)

## Impact

- IdP compromise = trust compromise: mint tokens for any user of any connected app
- Account takeover via redirect/registration/linking flaws
- SSRF pivot into the IdP's network
- Privilege escalation via client roles and realm roles

## Pro Tips

1. Enumerate realms early - `master` plus app-named realms are the common set
2. Dynamic client registration is often left open; a registered attacker client is a huge multiplier
3. Test redirect_uri with the *full* code exchange, not just the redirect - acceptance alone is not account takeover
4. Broker metadata fetch is the modern SSRF surface on Keycloak; use OAST to prove it
5. Pair with `oauth`, `authentication_jwt`, `ssrf`, `ssti`, and `weak_password_detection` skills

## Summary

Keycloak attacks are configuration attacks: exposed admin, permissive realms and clients, redirect abuse, broker SSRF, and weak token validation downstream. Enumerate realms and clients, test the flows end-to-end, and validate relying apps' token checks to convert config gaps into account takeover.
