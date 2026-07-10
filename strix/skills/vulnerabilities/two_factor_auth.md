---
name: two-factor-auth
description: 2FA/MFA/OTP/TOTP flow security testing — setup flaws, verification bypass, and disable-flow abuse across authenticator, SMS, email, and backup-code factors
---

# Two-Factor Authentication (2FA / MFA)

Most 2FA weaknesses are logic flaws in the flow, not cryptography. Three attack surfaces frame the whole methodology: **Setup** (enabling the factor), **Bypass** (getting past the code prompt), and **Disable** (turning the factor off). For any account-security control, the question is whether the server independently re-verifies identity and the factor on the step that matters, or trusts a client-supplied signal, a stale session, or an unbound code.

## Attack Surface

**Which surface to test**
- Feature lets you enable 2FA → run **Setup** checks
- A code prompt stands between login and the account → run **Bypass** checks
- Feature lets you turn 2FA off → run **Disable** checks

**Factors and endpoints**
- Authenticator/TOTP (QR + shared secret), SMS/voice OTP, email OTP, push approval, backup/recovery codes, WebAuthn
- Endpoints: `send`/`resend`/`verify`/`enable`/`disable`/`reset`, backup-code generation, and any in-account step-up prompt (change email/password/phone)

**Always test regardless of surface**
- Rate limits on send + verify + resend + reset
- Code reuse (same account) and cross-account code reuse
- Response/status-code manipulation of the verify result
- Session state: what boolean/flag the backend flips after a passed factor, and whether it is bound to the specific account/flow

## Key Vulnerabilities

### Setup Flaws

- **Secret not rotated / still retrievable after enable** — the TOTP shared secret or QR should be one-time and non-retrievable once 2FA is active. Look in JS, account APIs, and replayed setup requests for the secret leaking after activation; a leaked secret lets an attacker generate valid codes.
- **Response-manipulation logic flaw** — submit a wrong code during setup, intercept the verify response, and flip it to success. If the server trusts the manipulated response, 2FA "activates" bound to an attacker secret (or bricks the victim's login).
- **Old session survives enable** — enabling 2FA in one session should invalidate other pre-2FA sessions. If a second, pre-existing session keeps full access without a code, a hijacked pre-2FA session defeats the control.
- **Enable without email verification** — if an unverified signup (attacker registering the victim's email) can enable 2FA, the attacker locks the real owner out even after a password reset (pre-account-takeover).
- **IDOR at enable/verify** — if `enable`/`verify` take a user/account ID, enabling 2FA (or verifying a code) against *another* user's ID binds attacker-controlled 2FA to the victim → ATO.

### Bypass (getting past the code prompt)

- **Code not refreshed on resend** — request a new code; if the previous value still works (or resend returns the same value), guessing/brute force is easier.
- **Old code not invalidated** — a used code, or a code superseded by a newer one, still verifies. Test: reuse a consumed code; use an old code after generating a new one; reuse after a long delay; use codes from a rotated-out secret.
- **Code leakage in response** — the `send`/`resend` response body (or a debug field/header) contains the OTP.
- **Missing rate limit → brute force** — no cap on `verify` lets a 6-digit code be brute-forced; combine issue-on-one-side with brute-on-another; retry via host/subdomain variation if the limit is edge-keyed. Also check for missing limits on `resend` (cost/DoS) and on the post-password-reset verify step.
- **Missing code-integrity / cross-account reuse** — a code minted for the attacker's account verifies the victim's prompt. The code must be bound to the account+session it was issued for.
- **Null / default codes** — try empty, `null`, `000000`, `123456`, blank, `%00` at the verify step.
- **Referrer / direct-request bypass** — navigate straight to the post-2FA page (or an authenticated endpoint), or forge the `Referer` as if arriving from the 2FA page; if the gate is only front-end, access is granted.
- **Session-permission misconfiguration** — run two flows on one session (attacker + victim) to the 2FA point; complete the factor on the attacker flow, then proceed on the victim flow. If the backend sets only a session-wide "passed 2FA" boolean not bound to the specific flow, the victim's prompt is bypassed.
- **Factor/mode switching** — at verify, change the request's `mode`/`method` (e.g. `sms`→`email`) or a `secureLogin:true`→`false` flag; a weaker/disabled path may skip the code.
- **OAuth/social-login bypass** — logging in via a linked social provider may complete auth without ever hitting the 2FA gate.
- **Timeout/race quirk** — a small number of rapid wrong attempts, or a specific timing window, may drop the user past the check.
- **Cookie tampering** — strip or alter the cookie segment that encodes 2FA state; if the rest of the session is honored, the factor is skipped.

### Disable-Flow Abuse

- **No rate limit on disable** — disable often re-prompts for password/code; if unthrottled, brute-force that confirmation.
- **Disable via CSRF** — if the disable request lacks anti-CSRF (or the token is not validated / can be nulled/overridden), a cross-site request turns 2FA off for a victim.
- **Password reset / email change disables 2FA** — after a reset, if login no longer asks for the code, the reset silently cleared the factor (chains with any reset-token weakness into full ATO).
- **Password/identity not actually checked** — supply a wrong password (or omit it) on disable; if it still succeeds, the confirmation is cosmetic.
- **Logic bug via alternate endpoint** — the UI disable button hits a guarded endpoint, but a sibling API (e.g. `two-factor/set` with `method=sms&phone=...`) reconfigures/disables without the check.
- **Backup-code abuse** — apply the same bypass techniques (brute force, response manipulation) to the backup-code path; backup codes that are static across regenerations, or pullable via CORS/XSS from the backup-code endpoint, let a known-password attacker bypass 2FA.
- **Clickjacking the disable page** — if the disable page is framable, trick the victim into disabling it.

## Bypass Methods (quick reference)

- Response/status-code flip on any `verify`/`disable` step
- Value fuzzing: `null`, `000000`, `123456`, empty, `%00`
- Cross-account and reused/old codes
- `mode`/`method`/boolean flag switching in the verify body
- Referer forgery / direct navigation to post-2FA routes
- Host/subdomain variation to dodge edge-keyed rate limits
- Cookie-segment stripping for the 2FA marker

## Validation

- Prove the bypass end to end: reach an authenticated action that the 2FA gate was meant to protect, using a second (attacker) account or a controlled victim account you own
- For code-reuse/cross-account issues, show the exact code issued to account A verifying account B's prompt (paste both requests)
- For disable flaws, show the factor turning off with a wrong/absent password or via CSRF/alternate endpoint, then a subsequent login not prompting for a code
- For rate-limit findings, show the request count and the absence of lockout/backoff (a resend/cost-only issue is lower impact than a verify brute force — state which)
- Confirm the flaw is server-side, not a client-only redirect that still enforces on the backend

## False Positives

- A front-end-only skip where the protected API still independently enforces the factor
- "No rate limit" on `resend` that wastes cost but cannot bypass the code (impact is DoS/cost, not ATO)
- Codes that appear reusable within the same valid 30s TOTP window (expected) versus genuinely accepted after expiry/rotation
- Backup codes shown once at enable by design, not retrievable afterward
- Disable that does re-verify via a code even if the password field is optional
- OAuth login that itself enforced MFA at the identity provider

## Chaining

- **Reset-token weakness → disable via reset → ATO:** a predictable/leaked reset token plus "reset clears 2FA" yields full takeover
- **CSRF → disable 2FA → login:** turn the factor off for a victim, then take over with known/guessed credentials
- **IDOR at enable/verify → ATO:** bind attacker 2FA to a victim account, or verify against the victim's ID
- **XSS/CORS → backup-code theft → bypass:** exfiltrate backup codes from the endpoint response, then bypass with a known password
- **Pre-account-takeover:** enable 2FA on an unverified signup of the victim's email to lock them out post-reset

## Pro Tips

1. Always identify the exact session flag the backend sets after a passed factor — most bypasses come from that flag being unbound to the account or flow
2. Test the disable path as hard as the verify path; disable flaws are common and often skip the password check entirely
3. Cross-account code reuse is the highest-signal single test — mint a code on your account and fire it at another
4. Password-reset and 2FA interact constantly: always check whether a reset clears the factor or skips the prompt
5. `resend` and `verify` frequently have different (or missing) rate limits than the initial `send`
6. Watch for a second, unguarded endpoint that mutates 2FA state behind the guarded UI action
7. Distinguish cost/DoS rate-limit issues from real brute-force bypasses when scoring impact

## Summary

2FA security is about whether the server re-establishes identity and binds the factor to the specific account, session, and step — on setup, on every verify, and on disable. Walk all three surfaces, hammer rate limits and code binding, and prove any bypass by reaching a protected action as another principal.
