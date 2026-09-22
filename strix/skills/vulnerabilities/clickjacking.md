---
name: clickjacking
description: Clickjacking and UI-redressing testing for missing frame protections on state-changing actions
---

# Clickjacking / UI Redressing

Clickjacking tricks a victim into clicking something they can see but not what they think they're clicking, by overlaying or framing the real page beneath an attacker-controlled UI. It only matters where a click (or a sequence of clicks/drags) causes a real state change — a framed profile picture is noise, a framed "delete account" or "authorize" button is a finding.

## Attack Surface

- Any state-changing action reachable via a simple click/drag with no re-authentication step: account deletion, email/password change, fund transfer, OAuth consent screens, 2FA/MFA enrollment toggles, privacy/sharing settings, "connect app" authorization flows
- Multi-step flows framed across several overlaid iframes (click-sequence hijacking)

## Reconnaissance

**Check frame protections**
```
curl -sI https://target.com/sensitive-action | grep -iE "x-frame-options|content-security-policy"
```
- `X-Frame-Options: DENY` / `SAMEORIGIN` — legacy, still widely relied on
- `Content-Security-Policy: frame-ancestors 'self'` — modern replacement; if CSP is present but omits `frame-ancestors`, and `X-Frame-Options` is absent, the page is framable
- Test **per-endpoint**, not just the login page — frame protections are frequently applied globally to the login/landing page and forgotten on the actual sensitive action endpoints reached post-login

**Confirm framability**
```html
<iframe src="https://target.com/account/delete" width="800" height="600"></iframe>
```
If the frame renders (not blank/refused), the target is framable.

## Key Vulnerabilities

### Classic Overlay Clickjacking

Position a transparent iframe of the real sensitive action over a decoy UI (a "claim your prize" button), aligning the real button's coordinates under the decoy so the victim's click lands on the real, invisible button.

```html
<style>
  iframe { position: absolute; top: 0; left: 0; width: 800px; height: 600px; opacity: 0.0001; z-index: 2; }
  .decoy { position: absolute; top: 300px; left: 400px; z-index: 1; }
</style>
<div class="decoy">Click to win!</div>
<iframe src="https://target.com/account/authorize?app=evil"></iframe>
```
Precisely align the invisible action button under the decoy using devtools on your own PoC page (raise opacity temporarily to align, then drop to near-zero for delivery).

### Double-Clickjacking (Drag-and-Drop Variant)

Newer browsers increasingly block single-click cross-origin clickjacking via same-site cookie defaults and click-jacking heuristics, but drag-and-drop interactions are less consistently protected. The victim is prompted to "drag" an element (e.g., "drag the puzzle piece") across a page; the drag terminates over an invisible framed button/consent action, and the `drop` event fires the click on the underlying frame. Test any flow with a drag gesture over content that could overlay a real iframe.

### Framebusting-Script Bypass

Legacy apps sometimes rely on JS framebusting (`if (top !== self) top.location = self.location`) instead of `X-Frame-Options`/CSP. Bypass techniques:
- `sandbox` attribute without `allow-top-navigation` on the framing iframe — framebusting script can't navigate the top frame, so it silently fails while the frame still renders
- `<iframe sandbox="allow-forms allow-scripts">` neuters `top.location` reassignment (throws a SecurityError) while leaving the frame interactive
- `onbeforeunload` handler in the parent to cancel the busting navigation

### Consent/OAuth Screen Framing

OAuth/OIDC authorization prompts ("Allow App to access your account?") are a high-value clickjacking target — framing the consent screen and tricking the victim into clicking "Allow" grants the attacker's registered app a valid token for the victim's account. Always test the `/authorize` or equivalent consent endpoint specifically, even if the general app has frame protections (consent screens are sometimes hosted on a separate IdP domain with its own, possibly weaker, policy).

## Bypass Techniques

- CSP `frame-ancestors` set but scoped to a subdomain that doesn't match the actual hosting domain (misconfigured wildcard/typo)
- `X-Frame-Options: ALLOW-FROM <uri>` (deprecated, ignored by modern browsers — always framable if this is the *only* protection present)
- Protection present on the HTML document but not on an embedded same-origin resource that itself performs the sensitive action (e.g., an `<iframe>`-loaded widget with its own missing header)

## Chaining Attacks

- Clickjacking + CSRF: use clickjacking where CSRF tokens are present but bound only to session, not to explicit user intent
- Clickjacking + OAuth: hijack app-authorization consent to obtain a valid token for the victim's account
- Double-clickjacking + password manager autofill: trick a drag gesture into triggering a framed autofill/autosubmit on a credential field

## Testing Methodology

1. Enumerate every state-changing endpoint reachable in one click/drag post-authentication
2. For each, check `X-Frame-Options` and CSP `frame-ancestors` directly on that response (not just the app shell)
3. Build a minimal PoC iframe overlay and manually verify the click lands correctly using a real browser session
4. Test drag-based interactions separately — click protections don't necessarily cover them
5. Specifically test OAuth/consent and payment-confirmation screens even when the main app is protected

## Validation

1. Working PoC HTML page demonstrating the overlay/alignment
2. Screenshot or recording showing the decoy UI and the real framed action beneath it
3. Confirm the action actually executes (state change observed server-side), not just that the frame renders

## False Positives

- Framable pages with no state-changing action reachable (read-only content)
- Protections present via `Content-Security-Policy` even if `X-Frame-Options` is absent — modern browsers honor CSP `frame-ancestors` over the legacy header
- Same-origin framing only (app deliberately frames its own pages)

## Impact

- Unauthorized state changes: account deletion, settings changes, fund transfers, unwanted OAuth app authorization
- Session/account takeover via forced re-authentication or MFA-disable clicks

## Pro Tips

1. Always test the actual sensitive-action endpoint's headers, not the login page's
2. Modern browser same-site cookie defaults reduce classic clickjacking impact on cross-site session use — note this in impact framing rather than assuming full exploitability
3. Drag/double-clickjacking is the higher-yield technique against apps hardened against classic overlay clicks
4. OAuth consent screens are consistently under-tested for frame protections — always check them explicitly

## Summary

Clickjacking is a framing/UI-trust bug, not a payload bug — the fix is a header, but the finding's value comes entirely from what state change the click actually triggers. Prioritize irreversible or privilege-granting actions over cosmetic ones.
