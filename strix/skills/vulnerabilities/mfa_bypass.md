---
name: mfa-bypass
description: MFA implementation testing covering pre-MFA session access, OTP brute force, recovery flow abuse, enrollment weaknesses, and client-side MFA gate bypasses
---

# MFA Bypass

Multi-factor authentication is a critical security control, but implementations frequently contain bypasses that reduce it to single-factor or no-factor authentication. The gap between password verification and MFA completion, weak OTP enforcement, abusable recovery flows, and client-side MFA gates are all common real-world findings. Test MFA as a system, not just the code entry step.

## Attack Surface

**MFA Methods**
- TOTP (Google Authenticator, Authy, etc.)
- SMS/voice OTP
- Email OTP/magic links
- Push notifications (Duo, Microsoft Authenticator)
- Hardware tokens (FIDO2/WebAuthn, YubiKey)
- Backup/recovery codes
- Security questions (weakest — often the bypass itself)

**Authentication Flow Stages**
```
[Password] → [Pre-MFA State] → [MFA Challenge] → [Authenticated]
     ↓              ↓                  ↓                ↓
  Login page    Partial session    Code entry       Full access
                API access?        Brute force?     Complete
                Skip possible?     Replay?
```

**Target Surfaces**
- Web application login flows
- API authentication endpoints
- Mobile app authentication
- SSO/federation flows (SAML, OIDC)
- Admin panels and privileged access
- Account recovery and password reset
- MFA enrollment and management

## Key Vulnerabilities

### Pre-MFA Session Access

The most common MFA bypass. After password verification but before MFA completion, the application issues a session token or cookie that grants partial (or full) API access.

**Test**
1. Complete password authentication
2. Stop at MFA prompt — do NOT submit the code
3. Inspect cookies/tokens received after password step
4. Use those cookies/tokens to access API endpoints directly

```
POST /login  {"username":"user","password":"pass"}
Response: Set-Cookie: session=abc123; ...
          {"status":"mfa_required","redirect":"/mfa"}

# Now try accessing protected endpoints with the session cookie
GET /api/profile  Cookie: session=abc123
GET /api/settings Cookie: session=abc123
GET /api/users    Cookie: session=abc123
```

**What to Look For**
- API endpoints accessible with the pre-MFA session
- Different privilege levels between pre-MFA and post-MFA tokens
- JWT claims like `mfa_verified: false` that are checked client-side but not server-side
- GraphQL introspection or data queries working with partial auth

### OTP Brute Force

6-digit TOTP has 1,000,000 combinations. Without rate limiting, it's brutable.

**Rate Limit Testing**
```
POST /mfa/verify {"code":"000001"}  → 403
POST /mfa/verify {"code":"000002"}  → 403
POST /mfa/verify {"code":"000003"}  → 403
...
# Does the server lock out, throttle, or block after N attempts?
```

**Bypass Techniques**
- **No rate limit** — Brute force all 6 digits
- **Per-IP rate limit** — Rotate IPs via proxy
- **Reset on new code** — Wait for TOTP window to rotate (30s), counter resets
- **Race condition** — Send many parallel requests before lockout triggers
- **Response manipulation** — Change `403` to `200` or `mfa_verified: false` to `true` if client-side
- **Null/empty code** — Submit empty string, `null`, `0`, `000000`

**OTP Window Testing**
```
# Test if expired TOTP codes are accepted (window too large)
# Generate code at T, wait 60-90 seconds, submit
POST /mfa/verify {"code":"<expired_code>"}

# Test if the same code can be reused (replay)
POST /mfa/verify {"code":"123456"}  → 200 (success)
POST /mfa/verify {"code":"123456"}  → 200? (should be rejected)
```

### Recovery Flow Abuse

**Backup Code Weaknesses**
- Backup codes not rate-limited separately from TOTP
- Predictable backup code format (sequential, low entropy)
- Backup codes not invalidated after use
- No notification when backup code is used

**Account Recovery Bypasses MFA**
```
# Password reset flow
POST /forgot-password {"email":"victim@target.com"}
# Click reset link
POST /reset-password {"token":"reset_token","password":"newpass"}
# Login with new password — is MFA required? Or was it silently disabled?
```

**Method Downgrade**
- TOTP configured, but SMS fallback available without restriction
- Push notification → can fall back to email OTP
- Request a different MFA method on the challenge page
- API parameter: `{"mfa_method":"sms"}` to force weaker method

**Security Question Fallback**
- MFA can be bypassed by answering security questions
- Questions are often guessable or researchable (OSINT)

### Enrollment Flow Weaknesses

**Adding New MFA Without Verification**
```
# Can you add a new TOTP device without verifying the existing one?
POST /settings/mfa/enroll {"method":"totp"}
Response: {"secret":"JBSWY3DPEHPK3PXP","qr_url":"..."}
# Is the current MFA factor required to complete this?
```

**Removing MFA**
```
# Can MFA be disabled without re-authentication?
DELETE /settings/mfa
POST /settings/mfa/disable {"confirm": true}
# Does this require entering a current TOTP code?
```

**Enrollment Token Leaks**
- TOTP secret visible in page source, API response, or QR code URL
- Secret transmitted over non-HTTPS channels
- Secret logged in server-side logs or analytics

### Client-Side MFA Gates

**JWT/Token Manipulation**
```json
// Decode JWT
{"sub":"user123","mfa_verified":false,"role":"user"}

// Modify and re-sign (if weak/no signature verification)
{"sub":"user123","mfa_verified":true,"role":"user"}
```

**Cookie/Parameter Tampering**
```
# Check if MFA state is in a cookie
Cookie: mfa_complete=0
# Change to
Cookie: mfa_complete=1

# Check URL parameters
GET /dashboard?mfa_verified=true
```

**Response Manipulation**
```
# Original response to MFA check
{"mfa_required": true, "redirect": "/mfa"}

# Intercept and change to
{"mfa_required": false, "redirect": "/dashboard"}
# Does the server enforce MFA on subsequent requests?
```

### Direct Navigation Bypass

```
# After password auth, instead of following redirect to /mfa:
GET /dashboard          # Try accessing protected pages directly
GET /api/v1/user/me     # Try API endpoints
GET /admin              # Try admin pages
```

### SSO/Federation MFA Bypass

**IdP vs SP MFA**
- IdP enforces MFA, but SP accepts the SAML assertion without checking MFA claim
- IdP issues assertion after password-only auth for certain apps
- SP trusts `AuthnContextClassRef` value without IdP actually performing MFA

**Session Persistence**
- SSO session outlives MFA policy — user authenticates with MFA once, then has a long-lived SSO token
- Re-authentication policy not enforced for sensitive operations

### API Key/Token Bypass

- API keys generated before MFA enrollment still work without MFA
- Personal access tokens bypass MFA entirely (by design in some systems — document it)
- OAuth refresh tokens survive MFA policy changes

## Testing Methodology

1. **Map the MFA flow** — Document every step from password entry to full authentication; identify session tokens issued at each stage
2. **Pre-MFA access** — Test API access with the session token received after password-only auth
3. **Rate limiting** — Submit 10+ incorrect OTP codes rapidly; check for lockout, throttle, or CAPTCHA
4. **Code validation** — Test expired codes, reused codes, empty/null codes, codes from wrong device
5. **Recovery flows** — Test password reset, backup codes, security questions — do they bypass MFA?
6. **Method downgrade** — If multiple MFA methods available, test switching to the weakest
7. **Enrollment** — Test adding/removing MFA devices without re-verification
8. **Client-side gates** — Inspect JWT claims, cookies, and response bodies for MFA state; tamper and test
9. **Direct navigation** — Skip the MFA page and navigate directly to authenticated pages
10. **SSO integration** — If SSO is used, test whether MFA enforcement is at IdP, SP, or neither

## Validation

1. **Pre-MFA access** — Show API responses with sensitive data using only the post-password, pre-MFA session token. Include paired requests: same endpoint with full MFA token vs pre-MFA token
2. **Rate limit absence** — Determine the application's actual lockout threshold (if any) by incrementally increasing failed attempts. Show that the threshold is either absent or set unreasonably high (e.g., >100 attempts). Include timestamps proving no throttle or lockout at the tested volume. Note: 10 failed attempts alone does NOT prove absence of rate limiting if the threshold is set higher — continue testing until you observe either enforcement or reach a brute-forceable volume
3. **Code replay** — Show the same OTP code accepted for **two separate authentication sessions** (not just two requests within the same session). Demonstrate that the replay enables unauthorized access — e.g., an attacker who captured a valid code can use it after the legitimate user has already consumed it. Same-window duplicate verification without a concrete security consequence is not a vulnerability
4. **Recovery bypass** — Show complete password reset flow resulting in login without MFA prompt
5. **Client-side gate** — Show tampered JWT/cookie granting access to protected resources with `mfa_verified=false` → `true`
6. Provide full HTTP request/response pairs for each finding

## False Positives

- Pre-MFA session token exists but grants zero API access (server validates MFA completion on every endpoint)
- Rate limiting kicks in after N attempts but error response doesn't change (silent lockout — verify with a correct code after N failures)
- TOTP window accepts T-1 and T+1 codes (30s tolerance is standard and by design per RFC 6238)
- API keys bypass MFA by design and this is documented/intended (still worth noting in report)
- SSO session persistence is configured with appropriate re-auth policies for sensitive operations

## Impact

- **Full authentication bypass** — Access authenticated resources without completing MFA, reducing security to single-factor
- **Account takeover** — Brute force OTP or bypass MFA after credential stuffing/phishing
- **Privilege escalation** — Pre-MFA session may have different privilege boundaries than post-MFA
- **Compliance violation** — PCI DSS (8.3), HIPAA, SOC 2, and most frameworks require functional MFA; a bypassable MFA fails audit
- **Lateral movement** — Bypass MFA on admin accounts to access management interfaces

## Pro Tips

1. The pre-MFA session test is the highest-yield check — many applications issue a valid session cookie after password auth and rely on a client-side redirect to the MFA page
2. Always test the password reset flow end-to-end — the most common MFA bypass is `forgot password → set new password → login without MFA`
3. Check if MFA state is in the JWT — decode every token the application issues and look for `mfa`, `mfa_verified`, `amr`, `acr` claims
4. For TOTP brute force, the math matters: 6 digits = 10^6 combinations, but TOTP codes rotate every 30 seconds, so you need ~33,333 requests/second to guarantee a hit within one window. Test rate limiting with far fewer requests.
5. Test from the API first — web UIs often have client-side MFA enforcement that the API doesn't
6. WebAuthn/FIDO2 is significantly harder to bypass than TOTP/SMS — note the MFA method in your findings for accurate severity

## Summary

MFA bypass testing targets the implementation, not the cryptographic protocol. The most common bypasses are pre-MFA session access (partial auth), absent rate limiting on OTP entry, recovery flows that disable MFA, and client-side MFA gates. Test every transition in the authentication flow independently. A bypassable MFA is worse than no MFA because it creates false confidence.
