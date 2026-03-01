---
name: mfa-bypass
description: MFA bypass testing for session fixation, code reuse, fallback abuse, and enrollment flow weaknesses
category: vulnerabilities
tags: [mfa, authentication, session-fixation, otp]
cwe: 308
---

# MFA Bypass

Multi-factor authentication failures allow attackers to skip or circumvent the second factor entirely. Focus on session state between authentication steps, code validation logic, fallback mechanisms, and enrollment flows.

## Attack Surface

**MFA Delivery Channels**
- TOTP (authenticator apps)
- SMS/voice OTP
- Email OTP/magic links
- Push notifications
- Hardware tokens (FIDO2/WebAuthn, U2F)
- Backup/recovery codes

**Authentication Flow States**
- Pre-MFA (password verified, MFA pending)
- MFA challenge issued
- MFA verified
- MFA enrollment/setup
- MFA recovery/reset

**Administrative Controls**
- MFA enforcement policies (org-wide, per-role)
- MFA disable/reset by admin or self-service
- Trusted device/remember-me logic

## High-Value Targets

- Pre-MFA session tokens and cookies that grant partial access
- MFA challenge endpoints and verification handlers
- Backup code generation and redemption
- MFA enrollment and unenrollment flows
- Trusted device registration and revocation
- Account recovery bypassing MFA (password reset, support flows)
- Admin endpoints for MFA reset on behalf of users

## Reconnaissance

### Session State Mapping

- Capture cookies and tokens at each authentication step (pre-password, post-password/pre-MFA, post-MFA)
- Identify which endpoints are accessible at each state; look for partial session access
- Map session identifiers: do they change after MFA completion or persist from pre-MFA?
- Check for separate MFA challenge tokens (mfa_token, challenge_id, mfa_session)

### MFA Configuration Discovery

- Enumerate supported MFA methods per account and org
- Check if MFA is enforced server-side or only prompted client-side
- Identify fallback order: TOTP -> SMS -> backup codes -> support
- Look for MFA status in user profile APIs or JWT claims (mfa_verified, amr, acr)

## Key Vulnerabilities

### Session Fixation / Pre-MFA Access

- **Pre-MFA session reuse**: After password verification, the session cookie or token may already grant access to some or all API endpoints without completing MFA
- **Session ID persistence**: If the session ID does not rotate after MFA completion, an attacker who captures the pre-MFA session can wait for the victim to complete MFA and inherit the authenticated session
- **Parallel session abuse**: Start login in session A, complete MFA in session B; check if session A is now fully authenticated

### Code Validation Flaws

- **Code reuse**: Submit a valid OTP code multiple times; server should invalidate after first use
- **Brute force**: No rate limiting or lockout on MFA code submission; 6-digit TOTP has only 1M possibilities
- **Time window abuse**: TOTP codes valid for extended windows (multiple 30s periods); try codes from adjacent time steps
- **Race conditions**: Submit multiple valid codes simultaneously to bypass single-use enforcement
- **Code leakage**: OTP codes reflected in responses, error messages, or logs
- **Predictable codes**: SMS/email codes using weak random number generators

### Fallback and Recovery Abuse

- **Backup code weaknesses**: Backup codes not rate-limited, not invalidated after use, or regeneratable without MFA
- **Method downgrade**: Force fallback from TOTP to SMS by claiming device unavailable; SMS interception is easier
- **Recovery flow bypass**: Account recovery (password reset, support ticket) does not require MFA, effectively bypassing it
- **Remember-me token theft**: Trusted device tokens stored insecurely, valid indefinitely, or not bound to device fingerprint

### Enrollment Flow Weaknesses

- **Enrollment without current MFA**: Add a new MFA method without verifying the existing one
- **TOTP secret exposure**: Secret key visible in API responses after initial enrollment; re-enrollment leaks new secret without invalidating old
- **Unenrollment without MFA**: Remove MFA method via API without proving possession of the factor
- **Race during enrollment**: Complete enrollment from two sessions simultaneously to register attacker-controlled device

### State Machine Abuse

- **Step skipping**: Call the post-MFA endpoint directly without completing the MFA challenge
- **Step repetition**: Replay the MFA success response to re-authenticate without a new code
- **Cross-flow confusion**: Use a password reset token or email verification flow to satisfy MFA requirements
- **Downgrade to single factor**: Modify client request to indicate MFA is not enabled for the account

### Token and Claim Manipulation

- **JWT amr/acr claims**: If MFA status is stored in JWT claims, modify them when signature verification is weak
- **MFA status in cookies**: Flip mfa_verified=true in a cookie or local storage value if server trusts client state
- **OAuth scope abuse**: Request tokens with scopes that bypass MFA checks on certain endpoints

## Bypass Techniques

- Content-type switching to hit alternate validation code paths
- Manipulate request flow: intercept redirect after password, modify to skip MFA challenge page
- Use API endpoints directly instead of UI flow to avoid client-side MFA enforcement
- Exploit inconsistent MFA enforcement between web, mobile, and API channels
- Abuse password reset or magic link flows that authenticate without MFA

## Special Contexts

### OAuth/OIDC Integration

- MFA enforced at IdP but relying party accepts tokens without checking amr/acr claims
- Step-up authentication not triggered for sensitive operations
- Federated logins bypassing org MFA policy (social login without MFA)

### Mobile Applications

- Biometric prompt bypassed by hooking native APIs
- MFA state cached locally; modify app storage to skip challenge
- Push notification MFA: fatigue attacks (repeated prompts until user approves)

### API Keys and Service Accounts

- API keys bypass MFA entirely since they are single-factor by design
- Service account tokens not subject to MFA policy enforcement

## Chaining Attacks

- Session fixation + MFA bypass: fix pre-MFA session, wait for victim to complete MFA
- XSS + MFA bypass: steal pre-MFA cookies and access endpoints that do not enforce MFA completion
- CSRF + MFA unenrollment: force victim to disable MFA via cross-site request
- Account recovery + MFA bypass: reset password without MFA, then login without second factor

## Testing Methodology

1. **Map authentication states** - Document session tokens/cookies at each step; identify what changes after MFA
2. **Test pre-MFA access** - Try accessing protected resources with pre-MFA session tokens
3. **Validate code handling** - Test reuse, brute force, timing windows, and race conditions on OTP submission
4. **Probe fallbacks** - Attempt method downgrade, backup code abuse, recovery flow bypass
5. **Test enrollment** - Add/remove MFA methods without proper verification
6. **Cross-channel** - Verify MFA enforcement is consistent across web, mobile, and API
7. **Token inspection** - Check if MFA status is in JWT/cookie and if it can be manipulated

## Validation

1. Show access to protected resources using only a pre-MFA session (no second factor provided)
2. Demonstrate OTP code reuse or brute force resulting in successful MFA completion
3. Prove MFA can be disabled or a new method enrolled without verifying the existing factor
4. Show cross-channel inconsistency where one channel enforces MFA and another does not
5. Provide side-by-side evidence of normal MFA flow vs bypassed flow with the same account

## False Positives

- Remember-me functionality working as designed with proper device binding and expiry
- Step-up auth correctly gating sensitive operations while allowing read-only access pre-MFA
- Backup codes functioning as intended with single-use enforcement and rate limiting
- Account recovery requiring identity verification equivalent to MFA (e.g., identity document)

## Impact

- Full account takeover without possession of the second factor
- Bypass of compliance requirements (PCI DSS, SOC2, HIPAA) mandating MFA
- Persistent access after credential theft since MFA was the last line of defense
- Lateral movement in organizations where MFA is the primary access control

## Pro Tips

1. Always map the full session lifecycle; the gap between password verification and MFA completion is the primary attack surface
2. Test OTP validation with codes from adjacent time windows (T-1, T+1, T+2 for TOTP)
3. Check if pre-MFA sessions have any API access; even read-only access is a finding
4. Probe MFA enforcement at the service layer, not just the gateway/middleware
5. Try completing MFA on one session while accessing resources on a parallel pre-MFA session
6. Look for MFA status in JWTs and cookies; client-side MFA gates are common
7. Test account recovery and password reset flows separately; they often skip MFA
8. Push notification MFA is vulnerable to fatigue attacks; document the prompt rate and lockout behavior
9. Check if API keys or service tokens bypass MFA policy for the same account
10. Verify that MFA unenrollment requires the current factor, not just a password

## Summary

MFA security depends on the integrity of the entire authentication state machine, not just the code verification step. If any transition allows skipping the second factor, or if pre-MFA sessions grant meaningful access, the MFA implementation is broken.
