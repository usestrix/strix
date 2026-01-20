# CROSS-SITE REQUEST FORGERY (CSRF)

## Critical

CSRF abuses ambient authority (cookies, HTTP auth) across origins. Do not rely on CORS alone; enforce non-replayable tokens and strict origin checks for every state change.

## Scope

- Web apps with cookie-based sessions and HTTP auth
- JSON/REST, GraphQL (GET/persisted queries), file upload endpoints
- Authentication flows: login/logout, password/email change, MFA toggles
- OAuth/OIDC: authorize, token, logout, disconnect/connect

## Methodology

1. Inventory all state-changing endpoints (including admin/staff) and note method, content-type, and whether they are reachable via top-level navigation or simple requests (no preflight).
2. For each, determine session model (cookies with SameSite attrs, custom headers, tokens) and whether server enforces anti-CSRF tokens and Origin/Referer.
3. Attempt preflightless delivery (form POST, text/plain, multipart/form-data) and top-level GET navigation.
4. Validate across browsers; behavior differs by SameSite and navigation context.

## High Value Targets

- Credentials and profile changes (email/password/phone)
- Payment and money movement, subscription/plan changes
- API key/secret generation, PAT rotation, SSH keys
- 2FA/TOTP enable/disable; backup codes; device trust
- OAuth connect/disconnect; logout; account deletion
- Admin/staff actions and impersonation flows
- File uploads/deletes; access control changes

## Discovery Techniques

### Session And Cookies

- Inspect cookies: HttpOnly, Secure, SameSite (Strict/Lax/None). Note that Lax allows cookies on top-level cross-site GET; None requires Secure.
- Determine if Authorization headers or bearer tokens are used (generally not CSRF-prone) versus cookies (CSRF-prone).

### Token And Header Checks

- Locate anti-CSRF tokens (hidden inputs, meta tags, custom headers). Test removal, reuse across requests, reuse across sessions, and binding to method/path.
- Verify server checks Origin and/or Referer on state changes; test null/missing and cross-origin values.

### Method And Content Types

- Confirm whether GET, HEAD, or OPTIONS perform state changes.
- Try simple content-types to avoid preflight: application/x-www-form-urlencoded, multipart/form-data, text/plain.
- Probe parsers that auto-coerce text/plain or form-encoded bodies into JSON.

### Cors Profile

- Identify Access-Control-Allow-Origin and -Credentials. Overly permissive CORS is not a CSRF fix and can turn CSRF into data exfiltration.
- Test per-endpoint CORS differences; preflight vs simple request behavior can diverge.

## Exploitation Techniques

### Navigation Csrf

- Auto-submitting form to target origin; works when cookies are sent and no token/origin checks are enforced.
- Top-level GET navigation can trigger state if server misuses GET or links actions to GET callbacks.

### Simple Ct Csrf

- application/x-www-form-urlencoded and multipart/form-data POSTs do not require preflight; prefer these encodings.
- text/plain form bodies can slip through validators and be parsed server-side.

### Json Csrf

- If server parses JSON from text/plain or form-encoded bodies, craft parameters to reconstruct JSON server-side.
- Some frameworks accept JSON keys via form fields (e.g., `data[foo]=bar`) or treat duplicate keys leniently.

### Login Logout Csrf

- Force logout to clear CSRF tokens, then chain login CSRF to bind victim to attacker’s account.
- Login CSRF: submit attacker credentials to victim’s browser; later actions occur under attacker’s account.

### Oauth Oidc Flows

- Abuse authorize/logout endpoints reachable via GET or form POST without origin checks; exploit relaxed SameSite on top-level navigations.
- Open redirects or loose redirect_uri validation can chain with CSRF to force unintended authorizations.

### File And Action Endpoints

- File upload/delete often lack token checks; forge multipart requests to modify storage.
- Admin actions exposed as simple POST links are frequently CSRFable.

## Advanced Techniques

### Samesite Nuance

- Lax-by-default cookies are sent on top-level cross-site GET but not POST; exploit GET state changes and GET-based confirmation steps.
- Legacy or nonstandard clients may ignore SameSite; validate across browsers/devices.

### Origin Referer Obfuscation

- Sandbox/iframes can produce null Origin; some frameworks incorrectly accept null.
- about:blank/data: URLs alter Referer; ensure server requires explicit Origin/Referer match.

### Method Override

- Backends honoring _method or X-HTTP-Method-Override may allow destructive actions through a simple POST.

### Graphql Csrf

- If queries/mutations are allowed via GET or persisted queries, exploit top-level navigation with encoded payloads.
- Batched operations may hide mutations within a nominally safe request.

### Websocket Csrf

- Browsers send cookies on WebSocket handshake; enforce Origin checks server-side. Without them, cross-site pages can open authenticated sockets and issue actions.

## Bypass Techniques

### Token Weaknesses

- Accepting missing/empty tokens; tokens not tied to session, user, or path; tokens reused indefinitely; tokens in GET.
- Double-submit cookie without Secure/HttpOnly, or with predictable token sources.

### Content Type Switching

- Switch between form, multipart, and text/plain to reach different code paths and validators.
- Use duplicate keys and array shapes to confuse parsers.

### Header Manipulation

- Strip Referer via meta refresh or navigate from about:blank; test null Origin acceptance.
- Leverage misconfigured CORS to add custom headers that servers mistakenly treat as CSRF tokens.

## Special Contexts

### Mobile Spa

- Deep links and embedded WebViews may auto-send cookies; trigger actions via crafted intents/links.
- SPAs that rely solely on bearer tokens are less CSRF-prone, but hybrid apps mixing cookies and APIs can still be vulnerable.

### Integrations

- Webhooks and back-office tools sometimes expose state-changing GETs intended for staff; confirm CSRF defenses there too.

## Chaining Attacks

- CSRF + IDOR: force actions on other users' resources once references are known.
- CSRF + Clickjacking: guide user interactions to bypass UI confirmations.
- CSRF + OAuth mix-up: bind victim sessions to unintended clients.

## Validation

1. Demonstrate a cross-origin page that triggers a state change without user interaction beyond visiting.
2. Show that removing the anti-CSRF control (token/header) is accepted, or that Origin/Referer are not verified.
3. Prove behavior across at least two browsers or contexts (top-level nav vs XHR/fetch).
4. Provide before/after state evidence for the same account.
5. If defenses exist, show the exact condition under which they are bypassed (content-type, method override, null Origin).

## False Positives

- Token verification present and required; Origin/Referer enforced consistently.
- No cookies sent on cross-site requests (SameSite=Strict, no HTTP auth) and no state change via simple requests.
- Only idempotent, non-sensitive operations affected.

## Impact

- Account state changes (email/password/MFA), session hijacking via login CSRF, financial operations, administrative actions.
- Durable authorization changes (role/permission flips, key rotations) and data loss.

## Pro Tips

1. Prefer preflightless vectors (form-encoded, multipart, text/plain) and top-level GET if available.
2. Test login/logout, OAuth connect/disconnect, and account linking first.
3. Validate Origin/Referer behavior explicitly; do not assume frameworks enforce them.
4. Toggle SameSite and observe differences across navigation vs XHR.
5. For GraphQL, attempt GET queries or persisted queries that carry mutations.
6. Always try method overrides and parser differentials.
7. Combine with clickjacking when visual confirmations block CSRF.

## Remember

CSRF is eliminated only when state changes require a secret the attacker cannot supply and the server verifies the caller’s origin. Tokens and Origin checks must hold across methods, content-types, and transports.
