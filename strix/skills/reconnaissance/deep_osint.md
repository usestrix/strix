---
name: deep-osint
description: Deep OSINT methodology for breach-corpus correlation, org-structure mapping, and public-exposure discovery beyond technical asset enumeration
---

# Deep OSINT

Technical recon (`asset_discovery`, `infrastructure_lifecycle`) maps what infrastructure exists. Deep OSINT maps what's exposed *about* the organization and its people through public information — breach data, code history, document metadata, and org structure — which frequently yields the fastest path to a working credential, an exposed secret, or a validated attack-surface hypothesis.

**Scope boundary**: this skill covers *mapping* and *discovery* only. Actual credential stuffing, social-engineering contact, or use of discovered PII beyond confirming a finding is out of scope for standard testing — stop at proof, per program rules and responsible-disclosure norms. Where a program explicitly authorizes social-engineering testing, that's a separate, distinctly-scoped engagement type, not something this skill enables by default.

## Attack Surface

- Public breach corpora correlated against the target's employee email patterns
- GitHub/GitLab organization-wide commit history for accidentally-committed secrets
- Employee/org-chart structure for social-engineering-surface *mapping* (not execution)
- Search-engine-indexed exposed documents and misconfigured storage
- Passive internet-wide scan databases (Shodan, Censys, FOFA) for exposed services tied to the target's ASN/IP ranges

## Key Techniques

### Breach-Corpus Correlation

- Determine the target's email naming convention (`first.last@`, `flast@`) from any publicly known employee email (About/Team page, conference speaker bios, GitHub commit author emails)
- Query breach-aggregation services (e.g., a Have I Been Pwned-style domain search, where the operator holds a valid API key) for the target's domain to identify which employee accounts have appeared in known breaches
- **Do not** attempt to use recovered breach passwords against live target systems — that's credential stuffing, a distinct and separately-scoped activity most programs explicitly prohibit or gate behind specific authorization. The finding here is "N employees have breach-exposed credentials associated with corporate email," reported as a password-reuse risk, not a login attempt

### Org-Structure / Social-Engineering-Surface Mapping

- Enumerate employees via LinkedIn company search, GitHub organization members, and conference/speaker listings to build a picture of team structure — which team owns which product, who's in security/IT (useful for understanding likely internal tooling), who's newly hired (statistically more susceptible to pretexting, though *testing* that susceptibility is out of scope here)
- This mapping is valuable for **technical** follow-up: identifying likely internal tool names from job postings ("experience with $INTERNAL_TOOL a plus"), identifying tech stack from engineer LinkedIn profiles/GitHub activity, and identifying which subdomains/products map to which team for more targeted technical testing
- Explicitly do not proceed to contacting, phishing, or pretexting any identified individual under this skill — that requires separate, explicit program authorization

### Google/Search-Engine Dorking

Patterns for exposed documents, repos, and misconfigured storage indexed by search engines:
```
site:target.com filetype:pdf "confidential"
site:target.com filetype:xlsx OR filetype:csv
site:github.com "target.com" password OR secret OR api_key
site:pastebin.com "target.com"
inurl:target.com intitle:"index of"
site:s3.amazonaws.com "target-company"
site:drive.google.com "target.com" -site:target.com
```
Also check web archive snapshots (Wayback Machine) for documents/pages since removed but still indexed — a since-deleted admin panel path, an old API doc, a leaked internal wiki page.

### GitHub/GitLab Org-Wide Secret Scanning

- Enumerate all repos under the target's GitHub/GitLab org (including forks by employees under personal accounts, which frequently retain company code with less review)
- Scan full commit history — not just the current HEAD — since a secret committed and later "removed" typically remains recoverable from git history:
```
trufflehog git https://github.com/target-org/repo --only-verified
gitleaks detect --source=. --report-format=json
```
- Check employee personal repos (found via the org member list) for company-adjacent code/config accidentally pushed outside the org's review process
- Check for exposed `.git` directories on live web assets (`curl target.com/.git/config`) — full source disclosure even without any GitHub presence

### Passive Internet-Wide Scan Databases

- Query Shodan/Censys/FOFA for the target's known ASN/IP ranges (from earlier `asset_discovery` recon) to surface exposed services these databases have already fingerprinted — often surfaces forgotten/shadow IT infrastructure not found via active scanning due to firewall rules that block the testing source IP but not the scan provider's historical crawl
- Useful query patterns: `org:"Target Company"`, `ssl:"target.com"` (cert-based discovery of infrastructure not in DNS), `http.title:"default"` combined with the target's IP range for misconfigured default-credential services
- These require the operator's own API keys/subscriptions for the respective services — never use another party's credentials or exceed the query terms of service

## Chaining Attacks

- Breach-corpus correlation + password-reuse hypothesis: strengthens (not proves) an MFA-bypass or weak-password finding elsewhere by showing exposed-credential prevalence
- Exposed `.git` directory + secret scanning: full source disclosure feeding directly into source-aware SAST review
- Org-chart mapping + tech-stack inference: sharpens which `hunt-*`/framework-specific skills to prioritize for the actual technical testing

## Testing Methodology

1. Establish the target's email naming convention and domain(s) in scope
2. Run breach-corpus domain search; report exposure counts and patterns, not individual credentials
3. Enumerate GitHub/GitLab org and personal-repo spillover; run full-history secret scanning
4. Run search-engine dork patterns for exposed documents/storage/panels
5. Query passive scan databases for the target's IP ranges
6. Map org structure for technical-surface inference only; do not proceed to contact

## Validation

1. Exposed secrets: confirm the secret is live/valid before reporting (an expired/rotated key is a lower-severity finding, still worth noting)
2. Breach exposure: report aggregate counts/patterns; avoid publishing individual employee data beyond what's needed to prove the finding
3. Exposed documents/storage: confirm actual sensitive content, not just an indexed filename

## False Positives

- Secrets present in history but already rotated/revoked (still report as a hygiene finding, lower severity)
- Breach data present but for a clearly unrelated domain/company (name collision)
- Publicly-intended documents indexed as "exposed" (marketing PDFs, public reports)

## Impact

- Direct credential/secret exposure enabling account or infrastructure compromise
- Password-reuse risk quantification supporting broader authentication-hardening findings
- Full source-code disclosure via exposed `.git` or spillover repos

## Pro Tips

1. Full git history, not just HEAD — "removed" secrets are still there
2. Employee personal-account spillover repos are consistently under-reviewed compared to the official org
3. Passive scan databases (Shodan/Censys) surface infrastructure active scanning misses due to firewall allowlisting of those providers' crawlers
4. Keep the org-structure mapping output technical (tech stack, team-to-asset mapping) — that's what turns OSINT into faster, better-targeted technical testing, which is the actual point of this skill

## Summary

Deep OSINT turns public information exhaust — breaches, commit history, indexed documents, org structure — into faster and better-targeted technical findings. It maps and correlates; it does not itself execute credential or social-engineering attacks.
