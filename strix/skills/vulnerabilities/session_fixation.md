---
name: session-fixation
description: Session fixation testing — verifying a new session identifier is issued (and the old one invalidated) at every authentication-state change, plus local/remote fixation vectors to account takeover
---

# Session Fixation

Session fixation is an authentication flaw: the app accepts a session identifier established *before* authentication and keeps using that *same* identifier *after* the user authenticates. Because the identifier never changes across the privilege boundary, anyone who knew the pre-auth value holds a valid post-auth session — account takeover with no password and no token theft. It inverts hijacking: instead of stealing the victim's session, the attacker plants one they already control and waits for the victim to authenticate it. The single question the whole skill answers: **does the server issue a brand-new session ID on auth, and invalidate the old one server-side?**

## Attack Surface

Fixation lives at **privilege-boundary transitions**, not steady state. Test the session identifier across every one:

- **Login** (canonical), and **registration** that auto-authenticates
- **OAuth / SSO callback** — the `/callback` hop often reuses the pre-auth app session
- **MFA / 2FA step-up** — highest value: if the SID is fixed before the second factor and unchanged after, MFA protects nothing
- **Password reset / change** — must rotate the *current* session and revoke others
- **Session upgrade / re-auth** — "confirm password", elevate to admin, switch role/tenant/org
- **"Remember me" / persistent login** — a long-lived token minted from a fixed pre-auth SID widens the window
- **Any state that grants new authority** — accepting an invite, joining a team, email verification that unlocks features

**Transport to check:** is the SID cookie-only, or does the app also accept it from the **URL/query**, **path** (`;jsessionid=`), or a **request header**? That determines which remote vectors are possible.

## Reconnaissance

- Identify the **real** session cookie among the 4–6 the app ships (`JSESSIONID`, `PHPSESSID`, `connect.sid`, `*.session`) — only one or two actually authorize requests; the rest (CSRF, analytics) are decoys
- Establish **two isolated contexts** (two browsers / private window / two proxy cookie jars) with two accounts you own — a single profile's shared cookie jar produces false results
- Capture every `Set-Cookie` across the full flow: landing → pre-login → `POST /login` → post-login redirect → authenticated page
- Determine whether the app honors a **client-supplied** session value (mints its own vs. trusts yours)

## Key Vulnerabilities

### No regeneration on auth (the core bug)

The four-step diff: capture pre-auth SID → authenticate → capture post-auth SID → compare.
- **Value unchanged** before and after login → vulnerable.
- **New cookie issued, but the old value still authenticates** when replayed → also vulnerable (the server set a new cookie without destroying the old server-side record). *This second case is the one most apps fail and most testers miss — value rotation is not the test; old-value survival is.*

Edge cases that still qualify:
- **Partial rotation** — the auth cookie rotates but a secondary session/identity cookie stays fixed and is enough to ride the session; multi-cookie sessions (session + signature) where only one rotates
- **Happy-path-only rotation** — rotates on form login but not on OAuth callback, "remember me", or MFA completion
- **Rotate-on-first-write** — the framework rotates on first session write, not on the privilege change itself; verify rotation is actually tied to auth
- **Not revoked on password change / logout** — old sessions survive a credential change; logout clears the cookie client-side only while the value still authenticates server-side

### Local vector

Attacker and victim share an origin / the attacker pre-knows the SID: capture a pre-auth SID in context A, set the identical cookie in the victim context B, have B log in, then reload an authenticated page in A. If A is authenticated as the victim → confirmed. (Shared/kiosk machines make this zero-phishing.)

### Remote vector — fixation primitives

The attacker forces an attacker-chosen SID into the victim's browser, then the victim authenticates it:
- **URL / path acceptance** — app reads the SID from `?sid=`/`Set-Cookie=`/`;jsessionid=` and writes it to a cookie (classic, high-impact; often chains through a 302 into the login flow)
- **CRLF / response-splitting** — inject `%0d%0aSet-Cookie:%20SESSION=ATTACKER_SID` via an unsanitized header reflection (see `crlf-test` / `header_injection`)
- **Header injection** — `Host` / `X-Forwarded-Host` reflected into a `Set-Cookie` `Domain`/`Path`, scoping the attacker's cookie to the target
- **Subdomain cookie scoping** — a foothold on `*.target.com` sets `Domain=.target.com` that the apex app then upgrades on login
- **Meta/HTML injection** — `<meta http-equiv="Set-Cookie" ...>` on legacy parsers
- **XSS-assisted** — `document.cookie="SESSION=ATTACKER_SID; path=/"` from stored/reflected XSS turns a low-severity XSS into clean ATO

## Testing Methodology

1. Visit unauthenticated; save all cookies (names, values, `Domain`/`Path`/flags) and identify the real auth cookie
2. Log in with a controlled account; diff cookies before/after
3. **Old-value replay** (decisive): swap the session cookie back to the pre-auth value in Repeater and hit a protected endpoint — authenticated response = old SID still alive = vulnerable
4. Repeat the diff at each transition: OAuth callback, MFA completion, password change, registration auto-login, role/tenant switch, "remember me"
5. Probe non-cookie transport: does the app accept the SID from URL/path/header?
6. Test logout: is the SID destroyed server-side, or just cleared client-side?

Tooling notes: disable Burp's Cookie Jar for the decisive test (its silent auto-update masks fixation) and pin the attacker value via a Session Handling Rule; two `requests.Session()` jars (A grabs pre-auth SID, inject into B, B logs in, A hits `/account` and asserts authenticated) automate the check per transition.

## Validation

- Prove an authenticated action as the **attacker context** using the pre-auth/attacker SID after the victim (a second account you own) logs in
- Screenshot the three states: pre-auth value, post-auth value (unchanged **or** new), and the **old-value replay returning authenticated content** — the replay is what proves it
- For MFA bypass, show the SID identical before the second factor and after completion
- For a remote finding, demonstrate the actual delivery primitive (URL acceptance / CRLF `Set-Cookie` / subdomain cookie / XSS `document.cookie`), not just the missing rotation
- Only ever fixate between accounts you own; describe the victim path rather than executing against third parties

## False Positives

- Tested in one browser/profile — the shared cookie jar carried state; always use two isolated contexts
- A *different* cookie stayed constant (CSRF/analytics) while the real auth cookie rotated — identify the auth cookie first
- New cookie issued **and** the old value truly dead on replay → correct behavior, not a bug
- Stateless/JWT "session" cookie that *is* the identity and changes claims on login — sameness of a non-session cookie is irrelevant; confirm what actually authorizes the request
- Server ignores the client-supplied cookie and mints its own → the pre-auth value was never accepted → no fixation
- Cookie-only, `HttpOnly`/`Secure`, rotation-missing app with **no** remote delivery primitive and no shared-host scenario → still a defect, but assess realistic attacker path before claiming ATO impact

## Chaining

- **XSS → fixation → ATO:** a weak reflected XSS that couldn't otherwise escalate becomes clean takeover via `document.cookie=`
- **CRLF / header injection → remote `Set-Cookie` → ATO:** plant the attacker SID without XSS (see `crlf-test`)
- **Subdomain takeover / cookie injection → apex fixation:** set a `Domain=.target.com` cookie the main app authenticates
- **Fix-before-SSO/MFA → factor bypass:** if the post-callback/post-MFA session isn't rotated, the second factor protects nothing (see `oauth`, `two-factor-auth`)
- **"Remember me" → long-term persistence:** a persistent token derived from a fixed SID extends short-lived access

## Pro Tips

1. The cookie changing is not the test — **old-value survival is.** Always replay the pre-auth value; that single check decides the bug.
2. Identify the real session cookie before anything else; reporting a constant CSRF/analytics cookie as fixation is an instant false positive.
3. Two isolated contexts, always — the #1 source of both false positives and false negatives.
4. MFA-completion and OAuth `/callback` are the common blind spots — apps rotate on form login but forget these hops.
5. Find the delivery vector (URL acceptance, subdomain cookie, CRLF, XSS, shared host) — it's what turns "theoretical" into real impact.
6. Logout that only clears client-side while the value still authenticates is its own invalidation-failure finding and reinforces the fixation report.

## Summary

A secure app mints a fresh, random session ID and destroys the old server-side record at every authentication-state change. Fixation exists wherever it doesn't — most often on the MFA/OAuth/"remember me" hops, and most often as an old value that still authenticates after a new cookie is set. Test with two accounts across every privilege boundary, and prove it with an old-value replay returning authenticated content.
