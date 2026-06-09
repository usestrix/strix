---
name: mfa_bypass
description: MFA/2FA bypass testing — pre-auth session gaps, OTP brute force/reuse, recovery downgrade, enrollment flaws, client-side gates
---

# MFA Bypass

Multi-factor authentication is a baseline control, but it is frequently bolted onto an existing single-factor flow and leaks. The attacker's goal is to reach the authenticated state (or perform sensitive actions) without presenting the second factor. Treat the password step and the MFA step as two separate authorization checks and probe the seam between them. CWE-308.

## Attack Surface

- **Login flow**: the window between password verification and MFA completion — what session/token is issued, and what it can already do.
- **OTP/TOTP verification endpoint**: rate limits, single-use enforcement, code lifetime, value space (6 digits = 1e6).
- **Recovery & fallback**: backup codes, "lost device", SMS fallback, email magic links, support-driven reset.
- **Enrollment / management**: adding, removing, or replacing a factor; whether the existing factor is re-verified first.
- **Client-side trust**: MFA state encoded in a JWT claim, cookie, localStorage flag, or a hidden form field.
- **Step-up / sensitive actions**: re-auth gates on password change, email change, payout, API key creation.

## Reconnaissance

- Map the full sequence with the proxy: `POST /login` -> response (cookies, tokens, `mfa_required` flag) -> `POST /verify-otp`. Capture every request/response.
- Decode any JWT issued at the password step (`jwt_tool <token>` or base64) — look for `mfa: false`, `amr`, `acr`, `auth_level`, `2fa_passed` style claims.
- Enumerate which endpoints accept the post-password / pre-MFA token (replay it against `/api/me`, `/api/account`, data endpoints).
- Identify all factor types offered and every recovery path (often under `/account/security`).

## Key Vulnerabilities

### Pre-MFA session access (most common)
The cookie/token issued after the password is already valid for some routes. Log in with valid creds, stop before submitting the OTP, and replay the session against sensitive endpoints. If `/api/*` data or state-changing actions work, MFA is decorative.

### OTP brute force / missing rate limit
6-digit codes have only 1,000,000 values and often live 5–10 minutes. Spray with a script (never by hand):
- Fix the session, iterate `000000`–`999999` via `exec_command` Python with `aiohttp` concurrency, watch for a status/length/redirect change.
- Test for limit resets: does requesting a new code reset the attempt counter? Does changing IP/`X-Forwarded-For` or rotating the session reset it?

### OTP reuse / non-single-use / prediction
- Submit the same valid code twice — is the second accept?
- Does a code from an old request still validate? Are codes tied to the specific session/device?
- Check for predictable or server-disclosed codes (leaked in a response body, header, or `Set-Cookie`).

### Recovery & fallback downgrade
- Force a method downgrade (strong TOTP -> SMS/email) and attack the weaker channel.
- Backup codes: are they rate-limited? Single-use? Generated with weak entropy? Exposed in the enrollment response?
- Account recovery that resets the password may drop MFA entirely — full bypass.

### Enrollment flaws
- Add a new attacker-controlled factor without re-verifying the current one — then authenticate with it.
- Disable/remove MFA without step-up — combined with an account-takeover primitive (e.g. session fixation), this is a clean takeover.

### Client-side / response-tamper gates
- Flip the failing response: change `{"mfa":false}` / `"status":"PENDING"` to `true`/`"SUCCESS"` and see if the client proceeds with a usable session.
- Tamper the JWT/cookie claim (`mfa:false`->`true`); test alg confusion / weak signing per the `authentication_jwt` skill.
- Force-browse past the MFA page directly to the post-login landing route.

## Bypass Techniques

- Reuse the pre-MFA token directly on the API (skip the UI gate).
- Race the verify endpoint (parallel valid+invalid submissions) — see `race_conditions`.
- Null/empty/array OTP values (`otp=`, `otp[]=`, `otp=null`) to hit a comparison flaw.
- Response/JWT tampering on the MFA-state field.
- Recovery-flow pivot to escape the second factor entirely.

## Testing Methodology

1. Capture the complete login -> MFA -> landing flow in the proxy.
2. Replay the pre-MFA session against sensitive/API endpoints (access without MFA?).
3. Attack the OTP endpoint: brute force, reuse, lifetime, limit resets — all scripted.
4. Walk every recovery/fallback path for downgrade and MFA-skip.
5. Test enrollment add/remove without step-up re-verification.
6. Tamper client-side MFA state (JSON flags, JWT claims, cookies) and force-browse.
7. Check step-up enforcement on each sensitive action independently.

## Validation

1. Demonstrate a concrete authenticated action (read private data, change state) reached without a valid second factor.
2. For brute force, show the request count and the success transition (with throttling absent).
3. Keep PoCs minimal and on a tester-owned account; do not touch real user data.

## False Positives

- A pre-MFA token that only reaches public/`mfa_required` endpoints and nothing sensitive.
- Rate limiting that is present but slow (still effective — note it, don't over-claim).
- "Reuse" that actually issued a fresh equal-looking code.
- Recovery flows that re-trigger MFA after reset.

## Impact

Full account takeover, authentication bypass, and defeat of the primary compensating control for credential theft/phishing. Often chains with leaked/guessable passwords into direct compromise.

## Pro Tips

1. The richest bug is almost always the pre-MFA token — test it against the API before anything fancy.
2. Always script OTP work; manual attempts miss the missing-rate-limit window.
3. Re-test limits after a new-code request and after session/IP rotation — counters often reset.
4. Treat enrollment and recovery as separate attack surfaces from login; they bypass MFA more often than login itself.
5. Pair with `authentication_jwt` whenever MFA state rides in a token.
