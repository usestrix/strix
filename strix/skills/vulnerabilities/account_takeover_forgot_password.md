---
name: account-takeover-forgot-password
description: Account-takeover chain testing through password-reset, email-change, and session-management flow weaknesses
---

# Account Takeover via Forgot-Password & Identity-Change Flows

Account takeover (ATO) is rarely one bug — it's usually a chain through the identity-lifecycle flows: password reset, email change, session issuance. Each step needs to independently verify the actor is who they claim to be; a single weak link (a predictable token, a leaked token, an un-invalidated old session) collapses the whole chain.

## Attack Surface

- Forgot-password request → token generation → token delivery → token verification → new-password submission → session issuance
- Email-change flow (with or without re-authentication)
- Session/device management (active sessions not invalidated on password change)

## Key Vulnerabilities

### Token Predictability / Entropy Analysis

- Request several reset tokens in succession (same account, or across test accounts) and inspect for patterns: sequential IDs, timestamp-derived values, short numeric codes, non-cryptographic PRNG output
- If tokens are JWTs, decode and check for predictable/absent signature validation, or claims that let you forge a token for an arbitrary `user_id`/`email` without the signing key (see `authentication_jwt` skill for algorithm-confusion and signature-bypass techniques)
- For numeric OTP-style reset codes, test rate limiting on the verification endpoint independently — a 6-digit code with no rate limit is brute-forceable in minutes

### Token Leakage via Referer

- If the reset-confirmation page loads any external resource (analytics pixel, CDN-hosted image/CSS, third-party widget) **before** the token is stripped from the URL or exchanged for a session, the full reset URL — including the token in the query string — leaks via the `Referer` header to that third party
- Test: load the reset-confirmation page, inspect network tab for outbound requests, check their `Referer` header for the token
- This is exploitable even without XSS: any link the victim clicks in the reset email that lands on a page with third-party resource loads is enough

### Race Conditions in Reset-Token Verification

- Submit the same reset token in parallel requests with *different* new passwords — if the endpoint isn't atomic (check-then-invalidate), multiple concurrent requests may all succeed before the token is marked used, or worse, a race between "verify OTP" and "issue session" can let the flow proceed on a still-unconfirmed token (see `race_conditions` skill for the harness pattern)

### Email-Change-Without-Reauth Chains

- Check whether changing the account's email address requires re-entering the current password or a fresh MFA challenge
- If not, chain: obtain a low-privilege foothold (XSS, stolen short-lived token, IDOR on a settings endpoint) → change email to attacker-controlled address → trigger password reset on the new email → full takeover, all without ever knowing the original password
- Also check whether the *old* email address receives any notification of the change, and whether that notification includes a "wasn't you? undo" link that's itself exploitable or simply informational-only with no actual revocation

### Response-Manipulation ("success": true toggling)

- Intercept the reset-token-verification response; if a `200 OK` with `{"valid": false}` is returned for an invalid token (rather than a `4xx`), and the client-side JS branches on the JSON body to decide whether to show the "set new password" form, flip the body client-side to proceed past an unverified/incorrect token directly to password-set — only works if the actual password-set endpoint doesn't independently re-validate the token server-side, so always confirm server-side enforcement, not just the UI gate

### IDOR-in-Profile-Update Chaining

- If the account-settings/profile-update endpoint takes a `user_id`/`account_id` parameter (rather than deriving it from the session) and lacks ownership checks, an attacker can change *another* user's email or password-reset-adjacent fields (recovery email, security question) directly — see `idor` skill for the full parameter-swapping methodology, applied specifically here to identity-recovery fields

### Session-Fixation Post-Reset

- After a successful password reset, check whether all **other** active sessions for the account are invalidated
- If an attacker had a live session on the victim's account (via an earlier, now-revoked-by-password credential, or a fixated session ID) and the victim resets their password believing they've secured the account, an un-invalidated attacker session persists — this defeats the entire point of the reset
- Test: establish session A, reset password from session B, confirm whether session A is still valid

## Chaining Attacks

- Referer-leak token theft + no single-use enforcement: steal a token via a leaked Referer log, then use it any time before natural expiry
- Email-change-without-reauth + password reset: full takeover from a minor foothold with no password knowledge required
- IDOR-on-recovery-email + password reset: redirect password recovery to an attacker-controlled address without ever touching the victim's actual email inbox

## Testing Methodology

1. Map the full identity-recovery flow end to end: request → generation → delivery → verification → completion → post-completion session state
2. Test token entropy/predictability across several requests
3. Test for leakage via Referer, logs, or any third-party resource load on the confirmation page
4. Test rate limiting and race conditions independently on the verification step
5. Test email-change flow for re-authentication requirements and old-session invalidation
6. Test whether a password reset invalidates all other active sessions

## Validation

1. Demonstrate a successful password reset / email change performed without possessing the legitimate token or credential
2. Show reproducibility (not a one-off race win) where relevant
3. For session-fixation: prove a pre-existing session survives a password reset with a concrete before/after request

## False Positives

- Tokens with sufficient entropy (cryptographically random, ≥128 bits) and enforced single-use + short expiry
- Referer leakage present but resource-loading happens only *after* token exchange for a session (token already consumed, no longer valid)
- Email-change requiring re-auth and properly invalidating other sessions

## Impact

- Full account takeover without password knowledge
- Persistent unauthorized access surviving a victim's own remediation attempt (password reset that doesn't kill other sessions)
- Mass exploitation if token predictability allows scripted account enumeration + takeover

## Pro Tips

1. Always check what happens to *other* sessions after a password reset — this is the most commonly missed step in an otherwise-solid flow
2. Referer-leakage is a zero-interaction-beyond-the-email-click bug; test it before anything more elaborate
3. Treat the reset-token verification and password-set steps as two independent authorization checks — a bug in either one breaks the chain
4. Cross-reference `idor` and `authentication_jwt` skills — most real-world ATO chains are two or three small bugs stacked, not one big one

## Summary

Account takeover through identity-recovery flows is a chain-of-trust problem: every step from token generation to session issuance must independently verify the actor, and every step after completion must revoke prior trust. Test the whole chain, not just the token itself.
