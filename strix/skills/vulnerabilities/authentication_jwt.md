# AUTHENTICATION AND JWT/OIDC

## Critical

JWT/OIDC failures often enable token forgery, token confusion, cross-service acceptance, and durable account takeover. Do not trust headers, claims, or token opacity without strict validation bound to issuer, audience, key, and context.

## Scope

- Web/mobile/API authentication using JWT (JWS/JWE) and OIDC/OAuth2
- Access vs ID tokens, refresh tokens, device/PKCE/Backchannel flows
- First-party and microservices verification, gateways, and JWKS distribution

## Methodology

1. Inventory issuers and consumers: identity providers, API gateways, services, mobile/web clients.
2. Capture real tokens (access and ID) for multiple roles. Note header, claims, signature, and verification endpoints (/.well-known, /jwks.json).
3. Build a matrix: Token Type × Audience × Service; attempt cross-use (wrong audience/issuer/service) and observe acceptance.
4. Mutate headers (alg, kid, jku/x5u/jwk, typ/cty/crit), claims (iss/aud/azp/sub/nbf/iat/exp/scope/nonce), and signatures; verify what is actually enforced.

## Discovery Techniques

### Endpoints

- Well-known: /.well-known/openid-configuration, /oauth2/.well-known/openid-configuration
- Keys: /jwks.json, rotating key endpoints, tenant-specific JWKS
- Auth: /authorize, /token, /introspect, /revoke, /logout, device code endpoints
- App: /login, /callback, /refresh, /me, /session, /impersonate

### Token Features

- Headers: `{"alg":"RS256","kid":"...","typ":"JWT","jku":"...","x5u":"...","jwk":{...}}`
- Claims: `{"iss":"...","aud":"...","azp":"...","sub":"user","scope":"...","exp":...,"nbf":...,"iat":...}`
- Formats: JWS (signed), JWE (encrypted). Note unencoded payload option ("b64":false) and critical headers ("crit").

## Exploitation Techniques

### Signature Verification

- RS256→HS256 confusion: change alg to HS256 and use the RSA public key as HMAC secret if algorithm is not pinned
- "none" algorithm acceptance: set `"alg":"none"` and drop the signature if libraries accept it
- ECDSA malleability/misuse: weak verification settings accepting non-canonical signatures

### Header Manipulation

- kid injection: path traversal `../../../../keys/prod.key`, SQL/command/template injection in key lookup, or pointing to world-readable files
- jku/x5u abuse: host attacker-controlled JWKS/X509 chain; if not pinned/whitelisted, server fetches and trusts attacker keys
- jwk header injection: embed attacker JWK in header; some libraries prefer inline JWK over server-configured keys
- SSRF via remote key fetch: exploit JWKS URL fetching to reach internal hosts

### Key And Cache Issues

- JWKS caching TTL and key rollover: accept obsolete keys; race rotation windows; missing kid pinning → accept any matching kty/alg
- Mixed environments: same secrets across dev/stage/prod; key reuse across tenants or services
- Fallbacks: verification succeeds when kid not found by trying all keys or no keys (implementation bugs)

### Claims Validation Gaps

- iss/aud/azp not enforced: cross-service token reuse; accept tokens from any issuer or wrong audience
- scope/roles fully trusted from token: server does not re-derive authorization; privilege inflation via claim edits when signature checks are weak
- exp/nbf/iat not enforced or large clock skew tolerance; accept long-expired or not-yet-valid tokens
- typ/cty not enforced: accept ID token where access token required (token confusion)

### Token Confusion And Oidc

- Access vs ID token swap: use ID token against APIs when they only verify signature but not audience/typ
- OIDC mix-up: redirect_uri and client mix-ups causing tokens for Client A to be redeemed at Client B
- PKCE downgrades: missing S256 requirement; accept plain or absent code_verifier
- State/nonce weaknesses: predictable or missing → CSRF/logical interception of login\n- Device/Backchannel flows: codes and tokens accepted by unintended clients or services

### Refresh And Session

- Refresh token rotation not enforced: reuse old refresh token indefinitely; no reuse detection
- Long-lived JWTs with no revocation: persistent access post-logout
- Session fixation: bind new tokens to attacker-controlled session identifiers or cookies

### Transport And Storage

- Token in localStorage/sessionStorage: susceptible to XSS exfiltration; cookie vs header trade-offs with SameSite/CSRF
- Insecure CORS: wildcard origins with credentialed requests expose tokens and protected responses
- TLS and cookie flags: missing Secure/HttpOnly; lack of mTLS or DPoP/"cnf" binding permits replay from another device

## Advanced Techniques

### Microservices And Gateways

- Audience mismatch: internal services verify signature but ignore aud → accept tokens for other services
- Header trust: edge or gateway injects X-User-Id; backend trusts it over token claims
- Asynchronous consumers: workers process messages with bearer tokens but skip verification on replay

### Jws Edge Cases

- Unencoded payload (b64=false) with crit header: libraries mishandle verification paths
- Nested JWT (JWT-in-JWT) verification order errors; outer token accepted while inner claims ignored

### Special Contexts

#### Mobile

- Deep-link/redirect handling bugs leak codes/tokens; insecure WebView bridges exposing tokens
- Token storage in plaintext files/SQLite/Keychain/SharedPrefs; backup/adb accessible

#### Sso Federation

- Misconfigured trust between multiple IdPs/SPs, mixed metadata, or stale keys lead to acceptance of foreign tokens

### Chaining Attacks

- XSS → token theft → replay across services with weak audience checks
- SSRF → fetch private JWKS → sign tokens accepted by internal services
- Host header poisoning → OIDC redirect_uri poisoning → code capture
- IDOR in sessions/impersonation endpoints → mint tokens for other users

### Validation

1. Show forged or cross-context token acceptance (wrong alg, wrong audience/issuer, or attacker-signed JWKS).
2. Demonstrate access token vs ID token confusion at an API.
3. Prove refresh token reuse without rotation detection or revocation.
4. Confirm header abuse (kid/jku/x5u/jwk) leading to key selection under attacker control.
5. Provide owner vs non-owner evidence with identical requests differing only in token context.

### False Positives

- Token rejected due to strict audience/issuer enforcement
- Key pinning with JWKS whitelist and TLS validation
- Short-lived tokens with rotation and revocation on logout
- ID token not accepted by APIs that require access tokens

### Impact

- Account takeover and durable session persistence
- Privilege escalation via claim manipulation or cross-service acceptance
- Cross-tenant or cross-application data access
- Token minting by attacker-controlled keys or endpoints

### Pro Tips

1. Pin verification to issuer and audience; log and diff claim sets across services.
2. Attempt RS256→HS256 and "none" first only if algorithm pinning is unclear; otherwise focus on header key control (kid/jku/x5u/jwk).
3. Test token reuse across all services; many backends only check signature, not audience/typ.
4. Exploit JWKS caching and rotation races; try retired keys and missing kid fallbacks.
5. Exercise OIDC flows with PKCE/state/nonce variants and mixed clients; look for mix-up.
6. Try DPoP/mTLS absence to replay tokens from different devices.
7. Treat refresh as its own surface: rotation, reuse detection, and audience scoping.
8. Validate every acceptance path: gateway, service, worker, WebSocket, and gRPC.
9. Favor minimal PoCs that clearly show cross-context acceptance and durable access.
10. When in doubt, assume verification differs per stack (mobile vs web vs gateway) and test each.

### Remember

Verification must bind the token to the correct issuer, audience, key, and client context on every acceptance path. Any missing binding enables forgery or confusion.
