---
name: captcha-mfa-bypass
description: CAPTCHA and multi-factor authentication bypass testing across replay, race, and channel-inconsistency vectors
---

# CAPTCHA & MFA Bypass

CAPTCHA and MFA are both "extra step" defenses layered in front of an otherwise-normal flow — which means they fail the same way: the extra step is enforced on one channel/client and not another, or the server trusts a client-side signal that the response was satisfied. Treat both as authorization checks that must be enforced identically everywhere the underlying action is reachable.

## Attack Surface

- Login, signup, password reset, and OTP-verification endpoints protected by CAPTCHA and/or MFA
- Mobile app API equivalents of web forms (often missing the CAPTCHA the web form has)
- "Remember this device" / trusted-device cookie logic
- Backup/recovery codes as an MFA fallback path

## Key Vulnerabilities

### CAPTCHA Bypass

**Response reuse/replay**
- Solve a CAPTCHA once, capture the token/response value, and replay the same token across multiple subsequent requests — if the server doesn't invalidate the token after first use, or doesn't bind it to the specific form submission, it's reusable indefinitely
- Test whether the CAPTCHA token is checked against the CAPTCHA provider's verification API server-side at all, or only checked for presence/non-empty

**Client-side-only validation**
- Inspect whether the "CAPTCHA solved" state is a JS flag (e.g., a hidden field flips to `1`) that's never independently verified server-side — submit the form directly (via API/curl) with that field pre-set and the actual CAPTCHA challenge omitted entirely

**Missing on equivalent channel**
- Compare the web login/signup form (CAPTCHA present) against the mobile app's API endpoint or any public API doing the same operation — mobile apps frequently hit a leaner backend endpoint that skips CAPTCHA because "the app handles it," when in practice the API endpoint itself has no server-side enforcement and is reachable directly
- Check for a GraphQL mutation or legacy `/api/v1/` endpoint performing the same action without the CAPTCHA gate present on the current UI flow

**Bypassing image/audio challenges directly**
- Not in scope for most engagements (relies on third-party solving services/ML) — note the theoretical gap in the report but focus effort on the enforcement-logic bypasses above, which are far more common in practice and don't require breaking the CAPTCHA provider itself

### MFA Bypass

**Race condition in verification**
- Submit the primary-factor login (password) and the second-factor OTP verification as near-simultaneous parallel requests; if session elevation happens on password-success before the MFA check completes, the race can grant a fully authenticated session before the OTP check ever runs — see `race_conditions` skill for the parallel-request harness pattern

**Response manipulation**
- Intercept the MFA-check response and flip a `"success": false` → `"success": true` (or an HTTP 401 → 200) if the client-side JS trusts the response body/status to decide whether to redirect into the authenticated app, rather than relying on a server-issued session cookie that's only set on genuine success

**Backup-code brute force**
- Backup/recovery codes are often shorter-entropy or a fixed small set (e.g., 8-10 alphanumeric codes) with no rate limiting distinct from the primary OTP flow — test the backup-code entry endpoint for its own rate limit independently

**OTP brute-forceability**
- 6-digit numeric OTPs (1,000,000 space) are brute-forceable in minutes without rate limiting; test:
  - Per-IP vs per-account rate limiting (rotate IP/headers to bypass IP-based limits)
  - Whether the rate limit resets on a new OTP request (request a fresh OTP mid-brute to reset the counter)
  - Whether the OTP endpoint accepts requests for enumeration of valid session/challenge IDs across accounts

**"Remember this device" cookie forgery**
- Inspect the trusted-device cookie/token for predictability (sequential ID, unsigned JWT, reversible encoding) — if forgeable, an attacker can mint a valid "already verified this device" token for a victim account without ever completing MFA
- Check if the trusted-device token is bound to device fingerprint/IP or purely to account ID (a purely account-bound token is replayable from anywhere)

**Password-reset flow skipping MFA**
- Complete a password reset (email-based) and check whether the resulting session bypasses the MFA requirement entirely, or whether MFA re-enrollment/disable is reachable mid-reset-flow before the account owner would notice

**MFA-disable without re-auth**
- Check whether disabling MFA from account settings requires re-entering the current MFA code / password, or just a single click while already authenticated — if a session can be hijacked another way (XSS, stolen cookie), an MFA-disable-without-reauth endpoint removes the second factor permanently

## Chaining Attacks

- CAPTCHA bypass + credential stuffing: removes the rate-limiting benefit CAPTCHA was meant to provide, enabling automated brute force at scale
- MFA race condition + session fixation: combine to plant a pre-authenticated session before the victim's MFA check resolves
- Trusted-device forgery + password reset: mint a trusted-device cookie, then trigger password reset knowing the subsequent login will skip MFA

## Testing Methodology

1. Map every entry point into the protected action (web form, mobile API, legacy API versions, GraphQL)
2. For CAPTCHA: test token replay, client-only validation, and channel parity across all entry points
3. For MFA: test race conditions on the verify step, response-trust behavior, backup-code rate limiting, OTP brute-forceability, and trusted-device token forgery
4. Always test the MFA-disable and password-reset flows for silent MFA bypass

## Validation

1. Demonstrate a session obtained/action completed without a valid, freshly-solved CAPTCHA or without a valid second factor
2. Reproduce reliably (race conditions: state success rate across N attempts)
3. Show the bypass works via the standard, unauthenticated attacker path — not just with elevated tooling access

## False Positives

- CAPTCHA/MFA enforced correctly on every reachable channel, including mobile/legacy API paths
- Rate limiting present but with a threshold high enough to be a design choice, not a bypass (report as a hardening suggestion, not a bypass finding)

## Impact

- Account takeover at scale (CAPTCHA bypass enabling credential stuffing)
- Full authentication bypass despite MFA being enabled (false sense of security for the account owner)
- Persistent unauthorized access via forged trusted-device tokens

## Pro Tips

1. Compare every channel (web, mobile, GraphQL, legacy API) for the same operation — parity gaps are the highest-yield bypass source
2. Race the MFA verify step before trying anything cryptographic — it's the cheapest test and frequently works
3. Backup codes are consistently under-rate-limited relative to the primary OTP — always test them as a separate endpoint
4. A CAPTCHA/MFA check that trusts a client-supplied boolean is common in apps that added the feature as UI polish rather than a security control

## Summary

CAPTCHA and MFA are only as strong as their weakest enforcement point — one unprotected channel, one race window, or one client-trusted flag undoes the whole control. Test every path to the protected action, not just the one the UI shows you.
