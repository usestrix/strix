---
name: account-security-flows
description: Account & identity lifecycle flow abuse — password reset/change ATO, account linking, invitation & role assignment, account deletion, phone/email change, logout/session, and ban-feature bypass
---

# Account Security Flows

The features that manage identity, credentials, roles, and multi-account state — password reset, credential change, account linking, invitations/membership, deletion, logout, ban — are where flow-logic bugs live. The vulnerability is rarely a single sink; it is a trust boundary that isn't re-checked: *where* a reset link goes, *what* a token is, *who* an action applies to, *which* role is enforced at accept vs invite time, whether a "confirm your identity" step is real. Test every flow with **two accounts** (owner + attacker) and a proxy, mutating one boundary at a time. For the underlying vuln classes these flows chain, defer to the dedicated skills (`csrf`, `idor`, `race_conditions`, `oauth`, `header_injection`, `two-factor-auth`, `open_redirect`).

## Attack Surface

**Flows**
- Password reset / forgot-password; password change; email change; phone-number change
- Account linking (OAuth/social + local credential)
- Invitation / team-membership / role assignment / accept-invite
- Account deletion; logout / session lifecycle; ban / suspension

**Recurring boundaries to tamper**
- The **email/identity parameter** that binds the flow (attacker-influenceable?)
- The **token/link** (bearer credential: leakable, guessable, non-expiring, non-invalidated?)
- The **Host / X-Forwarded-Host** header that builds an emailed link
- The **role/permission** chosen at one step and enforced (or not) at another
- The **re-auth / current-password / confirmation** step (real, or client-trusted?)
- The **success/status** of the response (server-decided, or manipulable?)

## Reconnaissance

- Enumerate every account-management endpoint (settings, `/reset`, `/invite`, `/link`, `/delete-account`, `/logout`, profile update) with two accounts logged in side by side
- Capture the baseline "legitimate" request/response for each flow before mutating — most findings are "resend with one field changed and observe"
- Diff owner vs non-owner responses; watch for user IDs, tokens, roles, or emails leaking in responses (they seed the IDOR/response-manipulation tests below)
- Note which flows send email (reset, invite, verify) — those carry the Host-header and token-leak surface

## Key Vulnerabilities

### Password Reset / Forgot-Password (ATO)

- **Where the link goes** — Host-header / `X-Forwarded-Host` poisoning (`victim.com@attacker.com` and normalization-table variants) makes the emailed reset link point at your host → capture the victim's token on click. (See `header_injection` for the header-parsing mechanics.) Also IDN-homograph the email → ATO.
- **Email-parameter manipulation / BAC** — parameter pollution (`email=victim&email=attacker`), array (`{"email":["victim","attacker"]}`), CC/BCC injection (`%0d%0acc:attacker`), separators (`,` `%20` `|`), case change (`email` vs `Email`), no-domain / no-TLD, CRLF/null — so the reset for the victim is delivered to the attacker.
- **What the token is** — weak/guessable: remove it, `null`, `00000000`, expired, array of old tokens, 1-char change at start/end, unicode spoof; brute-force short tokens; assess predictability (timestamp / userID / email / name / DOB / sequence). 
- **Token invalidation** — old token still valid after: a new one is issued, use, login, or email/password change; over-long expiry; session not invalidated on reset.
- **Response manipulation → ATO** — submit a wrong/blank token, then rewrite the error response to the noted success status/body; the client proceeds to set a new password.
- **IDOR → ATO** — the set-password request carries a user ID (often leaked/encrypted in a prior response) and no token binding; swap it to change another account's password.
- **Token leak via Referer** — open the reset link, navigate to a third-party resource, and check the `Referer` for the token.
- **Other** — HTML injection on the reset page/email via display name; username enumeration on the reset page; reset-via-username duplicate-account abuse; no-length-password DoS; missing rate limit.

### Change Password / Email / Phone

- **Change password** — missing rate limit on the current-password field (brute it); confirmation field not validated (blank confirm accepted); missing current-password / removable auth header → IDOR ATO (drop `currentPassword` + auth header, set new password for a swapped email); param-injection ATO (inject `password`/`user[password]` into a name/profile update — mass-assignment/BOPLA); old session not expiring after change.
- **Change email / username** — BOPLA: a name-change request that also accepts an `email` field changes the email with no verification; path-overwrite of the username to a reserved route (`/user/login.php`) to bypass access control.
- **Change phone** — replay the onboarding `SetPhoneNumber`/`VerifyPhoneNumber` from an established session; verb-swap (`POST`→`PUT/PATCH`); keep conditional flags (`is_signup:true`, `step:3`); GraphQL field injection into a profile mutation; deprecated-but-live mutations (`AddMobileNumber`); cross-account OTP (verify Account A's OTP with Account B's session); race the verify step.

### Account Linking (OAuth / Social + Local)

- **Response/status manipulation** — the "confirm your password to link" step trusts a client-visible `{"success":true}`/`200`; capture a real success response from your account and replay it on the victim flow with a wrong password.
- **Pre-auth linking ATO** — if a provider-created account lets you attach local credentials later without verifying the original email, pre-create accounts on victim emails.
- **Missing/static OAuth `state`** — account-linking CSRF: send a logged-in victim your intercepted `/oauth/callback?code=...` → your social identity links to *their* account. (Full flow in `oauth`.)
- **IdP email misalignment** — test provider-email ≠ app-email trust; array injection on `provider_user_id` (`["attacker_id","victim_id"]`); race simultaneous multi-links.

### Invitation & Membership / Role Assignment

- **Token as credential** — invite token leaked in the `Resend-Token` response; non-expiring / non-invalidated link → rejoin after removal.
- **Email binding** — IDOR on the email parameter at invite-signup (change it before submit → join under a different identity); signup-without-accepting → **ghost membership** (dashboard shows "pending" while the account has real access).
- **Role escalation** — role chosen at invite/login is client-trusted (`role:"user"`→`"admin"` via match&replace); **race the invite-send** with two parallel single-packet requests (`role:viewer` + `role:admin`) → accept viewer, then open the admin link → escalated; **Ghost Admin** variant (accept admin first, then viewer → UI shows Viewer, backend is Admin — prove with an admin-only API call).
- **BAC across roles** — replay admin requests with a low-priv session's JWT/cookie (member invites admin, viewer edits, member edits org settings / removes members / edits permissions).
- **Second-admin 2FA disable** — an invited second admin disables the first admin's 2FA without a password (see `two-factor-auth`).
- **U+3164 Hangul Filler** — append the invisible width-bearing `U+3164` (bytes `E3 85 A4`) to the invited email: it is a *distinct* string at the uniqueness layer (duplicate-invite bypass → `201`) yet renders identically → a poisoned registration the victim can't later log into with the clean email (permanent lockout DoS).
- **Project-takeover-via-bad-name** — a member sets a display name with HTML/`%00`/latin chars so the victim's "remove member" request errors out and can't complete.

### Account Deletion

- **Missing re-auth** — deletion accepted without the current password; omit `password`/`current_password`, or send it blank/`null`/`true`/`[]`; reused/expired re-auth token accepted.
- **CSRF / CORS** — no anti-CSRF token (or cross-session token reuse), content-type flip; endpoint reflects `Access-Control-Allow-Origin: attacker` with credentials.
- **IDOR / batch** — swap the ID (`DELETE /api/users/{id}`), batch array (`{"delete_ids":[me,victim]}`), leaked-UUID feed, param pollution (`id=me&id=victim`).
- **Residual state** — soft-delete lets login / reset re-activate; orphaned resources (buckets, API keys, pending invites) survive; previously issued API keys still work after deletion.

### Logout & Session Lifecycle

- Server-side session **not invalidated** on logout (replay a captured authed request → `200`); re-inject copied cookies after logout; no concurrent-session termination; OAuth/OIDC tokens not revoked at the IdP.
- Logout **CSRF** (no token, or `GET`-triggerable via `<img>`) → forced logout; missing `SameSite`.
- Back-button cache exposes authenticated pages after logout.

### Ban / Suspension

- **Inbound** — an active user can still invite/assign/transfer-ownership/@mention the banned user (banned user regains a foothold / gets notified).
- **Outbound** — stale session or PAT/API key still works after ban; SSO into peripheral services still authenticates.
- **Unauthenticated** — banned user can still reset password, re-verify email (restoring state), or open support tickets.
- **Data leakage** — the profile API still leaks banned-user PII though the UI 404s; previously configured webhooks/integrations still fire.

## Bypass Methods (cross-cutting)

- **Response/status manipulation** — flip `4xx`/`{"success":false}` to `200`/`{"success":true}` on any confirm/link/verify step
- **Email-parameter manipulation** — pollution / array / CC-BCC / separators / case / no-TLD / CRLF-null (reset, invite, newsletter-style flows)
- **Host / X-Forwarded-Host** poisoning for any emailed link
- **Invisible/normalization unicode** — `U+3164`, `%00`, `%09`, `%20`, case, IDN homograph, to defeat uniqueness/lockout logic
- **Parameter pollution / array wrapping / verb swap / mass-assignment** into a benign update to reach a privileged field
- **Missing-field / null-value** submission to skip a re-auth or confirmation check

## Chaining

- **Reset ATO → full takeover:** host-header or weak-token reset → set victim's password → login
- **Reset disables 2FA → ATO:** if reset clears the factor or skips the prompt (see `two-factor-auth`)
- **Invite role-race → Ghost Admin → org compromise:** escalate to backend-admin, then act via API
- **Pre-auth account linking → ATO:** attach attacker social identity to a victim's app account
- **Ban bypass → persistence:** stale PAT / re-verify email restores a banned attacker's access
- **U+3164 invite → account lockout DoS** or duplicate-membership

## Validation

- **Takeover:** prove you changed/controlled **another** account (two-account PoC), not just a `200`
- **Role escalation / Ghost Admin:** show an admin-only API call **succeeding** as the low role; document UI-vs-backend mismatch explicitly
- **Host-header / Referer leak:** capture the emailed link pointing at your host, or the `Referer` carrying the token, then actually use that token
- **Token weakness:** show the specific failure — old token valid after new-issue/use/login/change
- **U+3164:** show the hex bytes `E3 85 A4` in the request and the `201`; for the DoS, show clean-email login failing after registration
- **Ghost membership:** dashboard says "pending" while the account has real access
- **Deletion / re-auth:** show the destructive action completing with a wrong/absent password
- Confirm server-side effect, not a client-only redirect the backend still enforces

## False Positives

- A `200` on a reset/link/delete request without proof another account was affected
- "No rate limit" that only wastes email/cost and cannot brute a secret (DoS/cost, not ATO)
- Reset token reused within its valid, unexpired window (expected) vs accepted after invalidation
- Logout that does revoke server-side even if a stale client copy briefly renders (check the API, not the page)
- A confirmation step whose result the server re-verifies regardless of the manipulated client response
- Ban where the "still works" path is an unauthenticated public resource, not privileged access

## Pro Tips

1. Run every account flow with two accounts and a proxy from the start — cross-account impact is the whole game
2. Identify the exact re-auth/confirmation step per flow and attack it directly (drop it, blank it, replay a success) — it's the most common single miss
3. For reset, separate the three questions — where the link goes, what the token is, who it applies to — and test each independently
4. Role is chosen at one step and enforced at another; the gap between them is where invite races and Ghost Admin live
5. Invisible-unicode and email-parameter tricks travel across reset, invite, and verify flows — carry the same payloads between them
6. Check what survives a destructive action (deletion, ban): tokens, sessions, webhooks, invites, orphaned resources
7. Generic sinks reached *through* these flows (XSS in a display name, file upload in a review, open redirect in a share link) belong to their own vuln-class skills — pivot there rather than treating them as account-flow bugs

## Summary

Account-lifecycle features fail when a trust boundary in the flow isn't re-established server-side: the link destination, the token, the applied identity, the enforced role, the confirmation step. Walk each flow with two accounts, tamper one boundary at a time, and prove cross-account or role-mismatch impact — never a bare `200`.
