---
name: okta
description: Okta-specific IdP testing covering org/app misconfiguration, API token abuse, MFA factor edge cases, and custom-domain takeover
---

# Okta

Okta sits in front of everything else a target owns, so a single tenant misconfiguration — an over-scoped API token, a factor that can be silently downgraded, an unclaimed custom domain — becomes org-wide account takeover. This skill covers Okta-the-product; use `oauth` for the generic authorization-code/PKCE flow layer once you've located the Okta-issued tokens, and `saml` when the target app federates via Okta's SAML app rather than OIDC.

## Attack Surface

**Org components**
- Okta org (`*.okta.com` / `*.oktapreview.com` / custom domain), Universal Directory, groups, group rules
- Applications: OIDC (native/web/SPA), SAML, SWA (Secure Web Authentication — stores raw creds!), bookmark apps
- Authentication policies (Sign-On Policy, App Sign-On Policy), Okta ThreatInsight, Okta FastPass
- Okta Workflows (low-code automation with its own OAuth scopes and API tokens)
- Okta API (`/api/v1/`) — Users, Groups, Apps, System Log, Policies, Factors

**Token types**
- Okta session cookie (`sid`), OIDC access/ID/refresh tokens issued by `/oauth2/default` or a custom auth server
- SSWS API tokens (org-admin bound, `Authorization: SSWS <token>`)
- Okta Workflows connection/OAuth tokens

## Reconnaissance

**Org discovery**
```
GET https://TENANT.okta.com/.well-known/okta-organization
GET https://TENANT.okta.com/.well-known/openid-configuration
GET https://TENANT.okta.com/oauth2/<auth-server-id>/.well-known/openid-configuration
```
Custom domains front the same org — check `CNAME`/`Set-Cookie` for the underlying `*.okta.com` tenant (`GET /sso/idps` or the login page's embedded config often leaks it).

**App enumeration**
- Login-page JS bundles and mobile app configs leak `clientId`, `issuer`, `redirectUri` for every Okta-fronted app the org has
- `GET https://TENANT.okta.com/api/v1/apps` (unauthenticated — often 401, but misconfigured orgs leave admin API reachable with a leaked SSWS token)
- Okta widget config (`okta-signin-widget`) embeds `baseUrl`, `clientId`, and sometimes `authParams.issuer` in page source

**User enumeration**
- `POST /api/v1/authn` with a guessed username often returns distinguishable errors (`E0000004` invalid creds vs a different code for unknown user) unless the org enabled the generic-error setting
- Password-recovery flow (`/signin/forgot-password`) frequently has the same enumeration oracle

## Key Vulnerabilities

### SWA (Secure Web Authentication) apps

SWA apps store the target app's actual username/password inside Okta and replay them via a hidden form POST. Any XSS or clipboard/DOM access on the SWA redirect page can exfiltrate raw downstream credentials — this is a materially worse bug class than OIDC/SAML misconfig because it's the plaintext password, not a token.

### API token / SSWS scope abuse

- Leaked SSWS tokens (CI logs, JS bundles, public repos, Okta Workflows connectors) are bound to the *creating admin's* privilege — a token from a Super Admin is full org takeover
- `GET /api/v1/users?search=...` with a leaked token enumerates every user, MFA factor status, and group membership
- `POST /api/v1/users/{id}/lifecycle/reset_password` with a privileged token resets arbitrary user passwords without the user's involvement

### Authentication/Sign-On policy gaps

- App Sign-On Policy allowing a weaker factor (or no MFA) for a subset of network zones/device conditions that an attacker can spoof (X-Forwarded-For zone bypass, unmanaged-device rules)
- Sign-On Policy rule order: a catch-all "Allow with password only" rule placed above a stricter rule silently wins
- Okta FastPass / device-bound tokens accepted from a policy that doesn't actually verify device trust attestation

### MFA factor edge cases

- Factor enrollment self-service without re-verifying the existing factor first — attacker with a stolen session token enrolls their own TOTP/SMS factor as a persistence backdoor
- SMS/voice factor reachable via `POST /api/v1/authn/factors/{id}/verify` with no meaningful rate limit — OTP brute force
- "Remember this device" cookie (`okta_persistent_session`) skipping MFA entirely on subsequent logins from a device an attacker controls (session cookie theft = permanent MFA bypass)
- MFA push (Okta Verify) fatigue: unlimited push retries with no cooldown or number-matching enabled — flag as a finding but never actually push-bomb a real user; this is social-engineering territory and out of scope for automated testing per program rules on no social engineering

### Custom domain takeover

Orgs that configure a custom domain (`sso.company.com`) via CNAME to Okta but later deprovision the Okta org (M&A, tenant migration) leave a dangling CNAME — same subdomain-takeover pattern as any other SaaS CNAME dangling record. Check via `dig CNAME sso.company.com` against the `hunt-subdomain` methodology.

### Okta Workflows

- Workflow connectors holding OAuth tokens/API keys for downstream systems (Slack, AWS, ServiceNow) — a workflow editable by a non-admin flow builder role can exfiltrate those connector credentials via a custom HTTP action
- Workflows triggered by unauthenticated webhooks (`/api/v1/eventHooks`) without a verified signing secret

### System Log exposure

- `GET /api/v1/logs` with a narrowly-scoped read-only API token still discloses full auth event detail (source IP, user agent, target app, MFA factor used) for every user in the org — useful for reconnaissance if a low-privilege token is found, and a privacy/impact factor if the token was meant to be scoped to a single app's logs

## Testing Methodology

1. **Fingerprint the org** — resolve the underlying `*.okta.com` tenant behind any custom domain, pull `.well-known` metadata, enumerate every app the org fronts from login-page JS.
2. **Enumerate apps by type** — flag every SWA app first (plaintext downstream creds); map OIDC apps to `oauth` skill, SAML apps to `saml` skill.
3. **Probe for leaked SSWS tokens** — GitHub/GitLab code search, JS bundle grep, Okta Workflows connector exports, CI config files.
4. **Policy matrix** — for each App Sign-On Policy, test from a spoofed "trusted" network zone/device condition to see if MFA drops.
5. **Factor enrollment check** — with a valid low-priv session, attempt self-service factor enrollment without step-up re-auth.
6. **Custom domain DNS check** — dangling CNAME after tenant decommission.
7. **Workflows audit (white-box/authenticated)** — connector credential exposure to non-admin flow editors.

## Validation

1. Demonstrate the concrete privilege gained (password reset on a victim account, MFA bypass on a real login, plaintext SWA credential extraction) with request/response evidence.
2. For policy-bypass findings, show the same login attempt succeeding without MFA under the spoofed condition and failing without it.
3. For leaked-token findings, show the token's actual scope via `GET /api/v1/users/me` (or equivalent) rather than assuming worst-case.

## False Positives

- Org enforces phishing-resistant MFA (FastPass/WebAuthn) org-wide with no fallback factor — SMS/push-fatigue findings don't apply.
- SSWS token found in a log/repo is already revoked — confirm liveness before reporting (`GET /api/v1/users/me` with the token).
- Sign-On Policy "weaker" rule is scoped to a genuinely trusted, non-spoofable network zone (verified server-side IP allowlist, not client-supplied header).

## Impact

- Org-wide account takeover via leaked admin-scoped SSWS token.
- Plaintext downstream-application credential theft via SWA app compromise.
- Persistent MFA bypass via self-service factor enrollment backdoor or stolen "remember device" cookie.
- Cross-tenant/downstream compromise of every app the Okta org fronts.

## Pro Tips

1. Always classify apps as SWA vs OIDC vs SAML first — the impact ceiling is completely different per type.
2. `okta-signin-widget` config in page source is often the fastest way to get `issuer`/`clientId` without touching the API.
3. Pair with `oauth` for OIDC token-layer bugs and `saml` for XML signature/assertion bugs in Okta's SAML apps.
4. A leaked SSWS token's actual privilege is not implied by where it was found — always confirm scope with a low-impact read call first.

## Summary

Okta bugs cluster in three places: the org/app configuration layer (SWA plaintext creds, policy rule ordering, custom-domain DNS), the API token layer (SSWS scope, Workflows connector credentials), and the factor layer (self-enrollment backdoors, remember-device cookie theft). Fingerprint every app's auth type before testing — the same misconfiguration class has a very different blast radius on a SWA app than an OIDC one.
