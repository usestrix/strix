---
name: google_workspace
description: Google Workspace tenant testing - tenant sharing, OAuth/marketplace apps, SSO/identity exposure, admin roles, and data exfiltration paths
---

# Google Workspace Security Testing

Google Workspace (formerly G Suite) is the identity and collaboration plane for an organization: Gmail, Drive, Calendar, Groups, the Admin Console, and the Cloud Identity directory all hang off a single tenant keyed by one or more verified DNS domains. The attacker objective is to move from external/low-privilege standing into the tenant's identity layer - by abusing over-broad external sharing, third-party OAuth and Marketplace apps, weak SSO/2SV posture, super-admin role sprawl, and service-account/domain-wide-delegation chains - and ultimately read or exfiltrate org data or impersonate users. This skill covers tenant-level assessment against an authorized engagement; for SSRF-mediated reach to GCP metadata see the ssrf skill, and for raw GCP project audit see prowler/ScoutSuite usage below.

## Attack Surface

**Scope**
- Tenant identity: Cloud Identity / Workspace directory, super-admin and delegated admin roles
- Authentication: login flows, 2-Step Verification (2SV) enrollment, SAML/OIDC SSO to third parties, app passwords, OAuth token grants
- Sharing: Drive/Docs external sharing, "anyone with the link", shared drives, Groups membership and posting policy
- Third-party access: OAuth-authorized apps, Marketplace apps installed domain-wide, service accounts with domain-wide delegation (DWD)
- Mail: SPF/DKIM/DMARC posture, spoofing, mail routing/compliance rules, forwarding/delegation
- API: Admin SDK, Gmail/Drive/Calendar/Directory APIs reachable with a valid token

**External Entry Points (no creds)**
- Domain/tenant discovery via MX and DNS, federation metadata, GWS-specific endpoints
- Public Drive links, public Google Groups, public Calendars, published Sites
- Username/account enumeration and password-spray surface on `accounts.google.com`
- OAuth consent abuse / phishing app registration (assess workspace app-restriction posture)

**Authenticated Entry Points**
- A low-privilege user account (most realistic assumed-breach start)
- A delegated/super admin account (config review)
- A service-account JSON key with `domain-wide-delegation` (impersonation across the tenant)

## Recon & Enumeration

Install the Workspace-specific tooling not already in the sandbox:
```
# GAM / GAMADV-XTD3: scripted Admin SDK + Gmail/Drive client (config-review under admin creds)
bash <(curl -s -S -L https://git.io/install-gam) -l
# GCPLoit / gcp_scanner style audit via gcloud + service-account keys
curl -sSL https://sdk.cloud.google.com | bash && exec -l $SHELL   # installs gcloud
pip install google-api-python-client google-auth oauthlib requests
# Cloud posture scanners (also cover Workspace-adjacent GCP orgs)
pip install prowler && pipx install scoutsuite
```

Unauthenticated domain/tenant footprinting:
```
# Confirm the org uses Google for mail (MX -> google) and find the routing
dnsx -l domains.txt -mx -resp -silent | grep -i 'google\|aspmx'
dig +short MX target.tld | grep -i aspmx.l.google.com

# SPF / DKIM / DMARC posture (spoofability + which third parties can send as the domain)
dig +short TXT target.tld | grep -i 'v=spf1'
dig +short TXT _dmarc.target.tld
dig +short TXT google._domainkey.target.tld

# Is the domain federated (external SSO) or native Google login?
curl -s "https://accounts.google.com/.well-known/openid-configuration" | jq .
# Workspace SSO / SAML metadata if the org publishes an IdP
subfinder -d target.tld -silent | httpx -silent -title -tech-detect | grep -iE 'sso|idp|saml|adfs|okta|ping'

# Surface public Google assets indexed for the domain
nuclei -u "https://sites.google.com" -tags google,exposure -silent   # placeholder; prefer targeted dorks
```

Account/username enumeration and login posture (rate-limited, authorized only):
```
# GHunt: enrich a known Google account (gaia id, public photos, reviews, calendar)
pipx install ghunt && ghunt email user@target.tld
# Validate whether an address is a real Google account before any spray
python3 -c "import requests;print(requests.post('https://accounts.google.com/_/signin/sl/lookup').status_code)"
```

Authenticated directory + config enumeration (with provided admin or user creds):
```
# Under a low-priv user token - what can this identity already see?
gcloud auth login        # or activate-service-account for a DWD key
# Directory dump (admin): users, groups, OUs, admin roles, 2SV state
gam print users fields primaryEmail,suspended,isAdmin,creationTime,lastLoginTime > users.csv
gam print groups members managers settings > groups.csv
gam print admins                                  # who holds super-admin / delegated roles
gam all users print filters                       # mail filters/forwarding pushed by users
gam print tokens                                  # every OAuth third-party token across the org
```

## Methodology

1. **Map the tenant** - From DNS/MX confirm Google is authoritative for mail; enumerate every verified domain and subdomain alias. Identify whether login is native Google or federated to an external IdP (changes the auth attack surface entirely).
2. **Establish standing** - Define your assumed-breach start: external (no creds), low-priv user, delegated admin, or service-account key. Run `gcloud auth list` / `gam info domain` to confirm what the identity already grants.
3. **Assess authentication posture** - Check tenant-wide 2SV enforcement, allowed 2SV methods (SMS vs security key), legacy/app-password availability, session length, and whether `Less secure apps` or basic-auth IMAP/SMTP is still permitted.
4. **Enumerate external sharing** - Inventory Drive files/shared drives shared "anyone with the link" or to external domains; check default sharing policy and shared-drive external membership. Enumerate public Groups and their post/join policy.
5. **Inventory third-party access** - Pull every OAuth token (`gam print tokens`), Marketplace apps installed domain-wide, and service accounts with domain-wide delegation. Map each app's scopes to data it can read (`https://mail.google.com/`, `.../auth/drive`, `.../auth/admin.directory.user`).
6. **Review identity/admin sprawl** - List super-admins and custom admin roles; flag service accounts holding admin roles, dormant admins, and admins without security keys.
7. **Test mail abuse** - Verify SPF/DKIM/DMARC strictness, spoofability, and routing/compliance rules that could exfiltrate or silently BCC mail.
8. **Escalate** - Chain a permissive grant (DWD key, over-scoped OAuth app, super-admin) into cross-user impersonation or org-wide data read, then stop at minimal proof.

## Key Weaknesses / Techniques

### Over-broad external Drive sharing
Default sharing left at "anyone with the link" or external-domain sharing enabled tenant-wide leaks documents to anyone holding/guessing a link.
```
gam config csv_output_row_filter "visibility:regex:anyoneWithLink|anyoneCanFind" redirect csv shares.csv all users print filelist fields id,title,permissions
# External members on a shared drive
gam print shareddrives | gam csv - gam user ~owner show drivefileacl ~id
```
Validate by opening a sampled link from an unauthenticated browser/`httpx` and confirming content renders without auth.

### Domain-wide delegation (DWD) abuse
A service-account JSON key with DWD can impersonate ANY user for its granted scopes - effectively a tenant skeleton key. A leaked key (found via trufflehog/gitleaks in repos, CI, or Drive) plus DWD = full impersonation.
```
trufflehog filesystem ./repo --only-verified | grep -i 'service_account\|private_key'
gitleaks detect -s ./repo -v | grep -i 'gcp\|service-account'
# Confirm a key can impersonate a target user for Gmail read (authorized PoC):
python3 - <<'PY'
from google.oauth2 import service_account
from googleapiclient.discovery import build
SCOPES=['https://www.googleapis.com/auth/gmail.readonly']
c=service_account.Credentials.from_service_account_file('key.json',scopes=SCOPES)
d=c.with_subject('victim@target.tld')          # impersonation via DWD
g=build('gmail','v1',credentials=d)
print(g.users().messages().list(userId='me',maxResults=1).execute())
PY
```

### Over-scoped / malicious OAuth & Marketplace apps
Third-party apps granted high-risk scopes (`mail.google.com`, `auth/drive`, `auth/admin.directory.user`) retain access until revoked, even after a password reset. Domain-wide Marketplace installs apply to every user.
```
gam print tokens | grep -iE 'mail.google.com|/auth/drive|admin.directory'   # high-risk grants
gam print tokens query "clientId=<suspect-app-id>"                          # blast radius of one app
```
Assess whether app installation is restricted to admins or open to all users (open = consent-phishing risk). For an authorized consent test, register an internal OAuth client and confirm whether the tenant's "trust/restrict third-party apps" policy blocks unverified apps.

### Weak / unenforced 2SV and legacy auth
2SV not enforced org-wide, SMS allowed, app passwords enabled, or legacy IMAP/SMTP basic-auth still on - all enable post-spray takeover and MFA bypass.
```
gam print users fields primaryEmail,isEnrolledIn2Sv,isEnforcedIn2Sv | grep -i ',False'   # users without 2SV
gam info domain | grep -iE '2sv|less secure'
```

### Super-admin role sprawl & service-account admins
Excess super-admins, service accounts holding admin roles, or dormant admins widen the blast radius. A single super-admin compromise = tenant takeover (reset any password, grant DWD, disable logging).
```
gam print admins | grep -i 'super'                 # count and identity of super-admins
gam print users query "isAdmin=True" fields primaryEmail,lastLoginTime   # dormant admins
```

### Mail spoofing & exfiltration rules
`v=spf1 ... ~all` (softfail) or `p=none` DMARC permits domain spoofing; tenant-level routing/compliance rules can silently BCC or forward outbound mail.
```
# Spoofability check
swaks --to test@target.tld --from "ceo@target.tld" --server aspmx.l.google.com   # authorized inbound test
gam print routing                                  # org-level mail routing / split-delivery
gam all users print forwards                        # user auto-forwards to external domains
```

### Calendar / Groups information disclosure
Public calendars leak meeting topics and attendee emails; open Groups leak internal mail and allow external posting (phishing into the org).
```
curl -s "https://calendar.google.com/calendar/ical/<id>/public/basic.ics" | head
gam print groups settings | grep -iE 'whoCanJoin:ANYONE|whoCanPostMessage:ANYONE'
```

## Validation

1. For external sharing, fetch a sampled "anyone with link" URL from an unauthenticated client and show real content returned (`httpx -u <link> -title -status-code` returning 200 with org data).
2. For DWD/service-account abuse, demonstrate a single read as an impersonated user (one message subject, one Drive filename) - never bulk-pull, never write.
3. For OAuth-app risk, prove the granted scope by issuing one read call with the app's token and confirm it succeeds; capture the token's `clientId` and scope list.
4. For 2SV/legacy gaps, confirm a single authenticated login succeeds without a second factor (or via app password/legacy IMAP) using a test account you control.
5. For super-admin sprawl, document the exact role bindings (`gam print admins`) rather than asserting; show the account can perform an admin-only read (`gam print users` succeeds).
6. For spoofing, deliver one benign authorized test mail and show it lands without DKIM/DMARC rejection in headers.

## False Positives

- "anyone with the link" files that are intentionally public templates/marketing assets with no sensitive content - inspect before reporting.
- OAuth tokens for Google-first-party apps (Gmail mobile, Chrome sync) or admin-vetted business tools - distinguish from unverified third parties.
- A service-account key existing in a repo that has NO domain-wide delegation and only project-scoped IAM - not a tenant impersonation path; verify DWD is actually configured.
- 2SV showing "not enrolled" for service/role accounts that are SSO-only or disabled - confirm the account can actually interactively authenticate.
- DMARC `p=none` on a parking/non-sending subdomain that no one trusts - low impact vs the primary sending domain.
- Public Group that is a read-only announcement list with moderated posting - `whoCanJoin:ANYONE` alone is not impact if posting is closed.
- Kibana-style "reachable but 401/403" Admin API endpoints - reachability without a valid token is not a finding.

## Chaining & Impact

- Leaked service-account key + DWD -> impersonate any user -> read all mail/Drive org-wide -> persistent silent data exfiltration.
- Open app-install policy -> consent-phishing an over-scoped OAuth app -> Gmail/Drive read for every user who consents -> survives password resets until token revoked.
- Password spray (weak 2SV) -> low-priv user -> harvest internal Groups/Drive shares -> escalate to a delegated admin via reused creds or session theft.
- Super-admin takeover -> reset any password, grant new DWD, disable login audit logs -> full tenant compromise and stealth persistence.
- SPF/DMARC weakness -> spoof exec mail -> internal phishing -> credential/consent capture -> back into the tenant.
- Workspace identity -> federated SSO -> downstream SaaS (Slack/Jira/AWS via SAML) all keyed off the same compromised account = blast radius beyond Google.

## Pro Tips

1. MX records are the fastest tenant fingerprint - `aspmx.l.google.com` confirms Workspace before you touch a login page.
2. `gam print tokens` is the single highest-value command: it reveals every third-party app's foothold and scope across the whole org in one pass.
3. Domain-wide delegation is the crown jewel - a DWD key is more dangerous than most super-admin accounts because it impersonates silently with no password reset trail.
4. Check token *scopes*, not just app names: `mail.google.com` and `auth/drive` are full read/write; `gmail.metadata` is far narrower.
5. Password resets do NOT revoke OAuth tokens or app passwords - always enumerate and recommend revoking those after any account-compromise finding.
6. Service accounts don't show in normal user lists - enumerate them separately and check which hold admin roles or DWD; they're the most-forgotten admins.
7. Audit logs (Admin > Reporting, or `gam report admin/login/drive`) are your validation oracle - a real finding leaves an entry; correlate to prove the action happened server-side.
8. Federation flips the threat model: if SSO is external (Okta/ADFS), the password attack surface moves off Google - pivot recon to the IdP, but DWD and OAuth risks stay on the Workspace side.
9. Prefer one-record PoCs (single message, single file) and immediately stop - bulk reads are both noisy and out of proportion for proof.
