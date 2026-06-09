---
name: fido2_webauthn
description: Testing WebAuthn/FIDO2 registration and authentication ceremonies for origin binding, challenge replay, and fallback weaknesses.
---

# Hardware Key / FIDO2 (WebAuthn)

A FIDO2 hardware key (YubiKey, Titan, passkey authenticator) is a phishing-resistant identifier: it signs a server-issued challenge with a private key that never leaves the device, and the browser binds that signature to the requesting origin. The asset under test is the full WebAuthn ceremony — the Relying Party (RP) server endpoints that issue challenges and verify attestation/assertion objects, plus every weaker authentication path the same account can fall back to. The attacker objective is to defeat that binding: replay or forge a signed assertion, register an attacker-controlled authenticator onto a victim account, downgrade to a weaker factor, or exploit RP server-side verification bugs so the cryptographic guarantee never actually gets enforced.

## Attack Surface

**Ceremony endpoints (the core RP API)**
- Registration begin/finish: issues `PublicKeyCredentialCreationOptions`, then verifies the `attestationObject` + `clientDataJSON`. Common paths: `/webauthn/register/options`, `/attestation/begin`, `/u2f/register`.
- Authentication begin/finish: issues `PublicKeyCredentialRequestOptions`, then verifies the `authenticatorData` + signature. Paths: `/webauthn/login/options`, `/assertion/begin`, `/mfa/verify`.
- Credential management: list/rename/delete registered keys, set as MFA, mark "passwordless".

**Configuration exposed to the client**
- `rp.id` (RP ID), `challenge`, `user.id` (user handle), `pubKeyCredParams`, `attestation` (`none`/`indirect`/`direct`/`enterprise`), `authenticatorSelection` (`userVerification`, `residentKey`, `authenticatorAttachment`), `allowCredentials`/`excludeCredentials`, `timeout`.

**Fallback and recovery paths (usually the real way in)**
- Password-only login, TOTP/SMS/email OTP, recovery codes, "lost my key" account-recovery flows, magic links, legacy U2F endpoints kept alive alongside WebAuthn.
- Step-up vs. login-time enforcement gaps: a session authenticated with password only may reach sensitive actions WebAuthn was meant to gate.

## Recon & Enumeration

```bash
# Discover hosts/apps that speak WebAuthn
subfinder -d target.tld -silent | httpx -silent -title -tech-detect -o hosts.txt
katana -u https://target.tld -jc -d 3 -silent | grep -Ei 'webauthn|fido|u2f|passkey|attestation|assertion|mfa|2fa' | tee webauthn_urls.txt

# Brute-force ceremony endpoints
ffuf -w endpoints.txt -u https://target.tld/FUZZ -mc 200,400,401,403 \
  -w <(printf '%s\n' webauthn/register/options webauthn/login/options attestation/begin \
  assertion/begin u2f/register u2f/sign mfa/verify account/recovery passkey/options)

# Pull the actual options object the RP issues (this is the spec under test)
curl -s -X POST https://target.tld/webauthn/login/options \
  -H 'Content-Type: application/json' -b cookies.txt \
  -d '{"username":"victim@target.tld"}' | tee opts.json
# Inspect challenge entropy, rp.id, userVerification, allowCredentials, timeout

# Front-end WebAuthn config + library fingerprint (SimpleWebAuthn, webauthn-json, fido2-lib, py_webauthn)
katana -u https://target.tld -silent | grep -Ei '\.js$' | httpx -silent -mr 'navigator.credentials|rp\.id|attestationObject|@simplewebauthn'

# Known CVEs in WebAuthn libs / IdP MFA flows + TLS/origin sanity
nuclei -u https://target.tld -tags webauthn,fido,mfa,auth,2fa -s critical,high,medium -j -o nuclei_fido.json
nuclei -u https://target.tld -tags ssl,tls,cors -s high,medium -silent   # RP ID binding depends on TLS + origin

# Source/secret review if RP code is in scope
semgrep --config 'p/jwt' --config 'p/secrets' .
trufflehog filesystem . --only-verified ; gitleaks detect -s . --no-banner
```

Asset-specific tooling to install when you need it:
```bash
pip install fido2 soft-webauthn          # scriptable virtual authenticator (register/assert programmatically)
# Chrome DevTools "WebAuthn" tab or CDP WebAuthn domain → add a virtual authenticator, no hardware needed
# jwt_tool for any JWT/session token the ceremony mints; interactsh-client for blind origin/SSRF callbacks
```

## Methodology

1. **Map every account-access path**, not just WebAuthn. Enumerate password login, each OTP type, recovery codes, "lost key" flow, and legacy U2F. The weakest enabled path is the real attack surface — a perfect WebAuthn impl is moot if password+SMS still logs in.
2. **Capture a full registration and a full authentication ceremony** through a proxy. Save `clientDataJSON`, `attestationObject`/`authenticatorData`, signature, challenge, and the begin/finish request pair.
3. **Decode `clientDataJSON`** (base64url JSON): confirm `type`, `origin`, `challenge`, `crossOrigin`. This is what the RP must verify server-side; test each field.
4. **Probe challenge lifecycle**: entropy, single-use, expiry, and binding to the session/user. Replay an old challenge; reuse a finished one; swap challenges between users.
5. **Test origin and RP ID binding**: alter `origin` in `clientDataJSON`, alter `rp.id`, and test whether the RP accepts assertions minted for a parent/sibling domain.
6. **Build a virtual authenticator** (soft-webauthn / Chrome CDP) and attempt to register it onto a victim account, or replay/forge assertions, since you control the signing key.
7. **Attack the finish/verify step server-side**: signature verification skips, type confusion (`webauthn.get` vs `webauthn.create`), counter handling, user-handle confusion, attestation trust bypass.
8. **Test downgrade/fallback** end to end: can you complete login or step-up without ever touching the registered key.
9. **Probe credential management** for IDOR (delete/rename/add a key to another user's account) and self-service recovery abuse.

## Key Weaknesses / Techniques

- **Challenge replay / weak challenge.** RP reuses or doesn't expire challenges, or generates them with weak randomness (predictable, sequential, or short). Capture an assertion, let the session expire, replay the exact `finish` body. If accepted, the signed assertion is reusable.
  ```bash
  curl -s -X POST https://target.tld/webauthn/login/finish -b cookies.txt \
    -H 'Content-Type: application/json' --data @captured_assertion.json    # replay verbatim
  ```
  Also try: request `login/options` twice and check the `challenge` differs and is high-entropy; submit `finish` with a challenge from a *different* `options` call.
- **Origin not verified.** RP fails to check `clientDataJSON.origin` against an exact allowlist. Re-sign with a virtual authenticator while setting `origin` to `https://evil.target.tld`, `https://target.tld.evil.com`, or a subdomain. If the finish step accepts it, phishing resistance is gone.
- **RP ID overscope / mismatch.** `rp.id` set to an eTLD+1 (e.g. `target.tld`) shared by untrusted subdomains, or accepting an `rp.id` the user-supplied options claimed. A credential registered on a sibling subdomain becomes usable against the sensitive one.
- **`userVerification` not enforced.** Options request `userVerification:"required"` but the RP never checks the UV flag (bit `0x04`) in `authenticatorData`. Submit an assertion with UV unset — a stolen/idle key (no PIN/biometric) silently passes what should be 2-factor.
- **Signature counter ignored.** Cloned/replayed authenticators are caught only if the RP enforces a monotonically increasing counter. Replay with an equal or lower counter; if accepted, clone detection is absent.
- **Type confusion.** RP verifies `clientDataJSON.type` loosely. Submit a `webauthn.create` (registration) blob to the authentication finish endpoint, or vice versa, to bypass per-ceremony checks.
- **User-handle / credential binding confusion.** Submit a valid assertion for *your* credential while naming the victim's `username`/`user.id`; if the RP resolves the account from the request body rather than from the credential's stored user handle, you authenticate as the victim.
- **Attestation trust bypass / forged attestation.** RP requests `attestation:"direct"`/`enterprise` but accepts `none` or an unverified/self attestation. Register a fully software (forged) authenticator where genuine hardware was assumed, defeating device-binding/compliance controls.
- **Registration without re-auth.** `/register/options` reachable with only a session cookie (no fresh step-up). Combined with session fixation/XSS/CSRF, attacker silently enrolls their own key as a persistent backdoor MFA factor.
- **CSRF on ceremony endpoints.** Finish endpoints accept requests without CSRF token / `SameSite` protection, enabling forced registration or forced unenrollment.
- **Fallback downgrade.** WebAuthn offered but password-only or weak OTP still completes the same login or step-up. Verify by simply not presenting an assertion and following the alternate path to the protected resource.

## Validation

- Drive ceremonies with a scriptable authenticator instead of hardware:
  ```python
  from soft_webauthn import SoftWebauthnDevice
  dev = SoftWebauthnDevice(); dev.cred_init(rp_id='target.tld', user_handle=b'victim')
  # produce attestation/assertion objects, mutate origin/challenge/UV flag, submit to finish endpoint
  ```
  Or use Chrome DevTools → WebAuthn → "Add virtual authenticator" and run the live flow; CDP exposes `WebAuthn.addCredential` for forced-registration PoCs.
- For **replay**: show the same assertion body accepted twice (two HTTP 200 / two valid sessions) after challenge expiry.
- For **origin/RP-ID**: show a finish request with a tampered `origin`/`rp.id` yielding a valid authenticated session.
- For **UV/counter**: diff the decoded `authenticatorData` flags/counter against the options policy and show the RP issuing a session anyway.
- For **fallback**: capture an authenticated session/cookie reaching the protected action with WebAuthn never invoked. Stop at proof — read a benign account-scoped resource, do not pivot further.

## False Positives

- A 200 from `*/finish` is not success — confirm an actual authenticated session/token was minted and grants access. Many RPs return 200 then reject downstream.
- Browser/platform enforcement masking an RP bug: the browser refuses cross-origin/`rp.id` mismatches client-side, so a manual `curl` replay is required to prove the *server* doesn't check.
- Challenges that look low-entropy but are HMAC/stateless and bound server-side — verify reuse is actually accepted, not just that the value is short.
- "Missing attestation verification" when policy is intentionally `attestation:"none"` (privacy-preserving passkeys) — that is by design, not a finding.
- OAST/origin callbacks whose source IP is the tester's browser, not the RP backend.
- Counter staying 0 is normal for some platform authenticators/passkeys; only flag if the RP claims to enforce counters and accepts a *decrease*.

## Chaining & Impact

- Forced registration → attacker-owned key as permanent MFA → durable account takeover surviving password resets.
- Origin/RP-ID bypass → phishing-resistant MFA defeated → credential phishing kits regain effectiveness against the org.
- Fallback downgrade → MFA effectively optional → mass account takeover via password reuse / OTP phishing.
- User-handle confusion or assertion replay → direct authentication as a victim → privilege escalation if the victim is an admin.
- Self-service recovery abuse → bypass the key entirely → ATO without any WebAuthn interaction at all.
- IDOR in credential management → unenroll a victim's only key → denial of access, or enroll your own → silent takeover.

## Pro Tips

1. The hardware key is rarely the weak link — the RP's server-side verification and the *other* enabled factors are. Enumerate every fallback before touching the ceremony.
2. Always decode `clientDataJSON` and `authenticatorData` by hand; the RP's job is to validate fields most implementations only parse. Tamper one field per request to isolate which checks are missing.
3. A virtual authenticator (soft-webauthn / Chrome CDP) is the whole test rig — you control the private key, so you can mint, mutate, and replay arbitrary attestation/assertion objects without hardware.
4. Test the begin/finish pair as a stateful unit: mix-and-match a `finish` body with challenges/options from a different begin call, a different user, or a different ceremony type.
5. Check whether `/register/options` requires fresh re-authentication — silent key enrollment is the highest-impact, most-overlooked WebAuthn bug.
6. Confirm `rp.id` scope: a credential valid for `target.tld` covers every subdomain; one shared subdomain XSS can pivot into a passkey usable on the crown-jewel app.
7. Passwordless ("first-factor") deployments raise the stakes — a single missing origin or challenge check is full account takeover, not just an MFA bypass.
