---
name: subdomain-takeover
description: Subdomain takeover testing for dangling DNS records and unclaimed cloud resources
---

# Subdomain Takeover

Subdomain takeover lets an attacker serve content from a trusted subdomain by claiming resources referenced by dangling DNS (CNAME/A/ALIAS/NS) or mis-bound provider configurations. Consequences include phishing on a trusted origin, cookie and CORS pivot, OAuth redirect abuse, and CDN cache poisoning.

## Attack Surface

- Dangling CNAME/A/ALIAS to third-party services (hosting, storage, serverless, CDN)
- Orphaned NS delegations (child zones with abandoned/expired nameservers)
- Decommissioned SaaS integrations (support, docs, marketing, forms) referenced via CNAME
- CDN "alternate domain" mappings (CloudFront/Fastly/Azure CDN) lacking ownership verification
- Storage and static hosting endpoints (S3/Blob/GCS buckets, GitHub/GitLab Pages)

## Reconnaissance

### Enumeration Pipeline

- Subdomain inventory: combine CT (crt.sh APIs), passive DNS sources, in-house asset lists, IaC/terraform outputs
- Resolver sweep: use IPv4/IPv6-aware resolvers; track NXDOMAIN vs SERVFAIL vs provider-branded 4xx/5xx
- Record graph: build a CNAME graph and collapse chains to identify external endpoints

### DNS Indicators

- CNAME targets ending in provider domains: `github.io`, `amazonaws.com`, `cloudfront.net`, `azurewebsites.net`, `blob.core.windows.net`, `fastly.net`, `vercel.app`, `netlify.app`, `herokudns.com`, `trafficmanager.net`, `azureedge.net`, `akamaized.net`
- Orphaned NS: subzone delegated to nameservers on a domain that has expired or no longer hosts authoritative servers
- MX to third-party mail providers with decommissioned domains
- TXT/verification artifacts (`asuid`, `_dnsauth`, `_github-pages-challenge`) suggesting previous external bindings

### HTTP Fingerprints

Service-specific unclaimed messages (examples):
- **GitHub Pages**: "There isn't a GitHub Pages site here."
- **Fastly**: "Fastly error: unknown domain"
- **Heroku**: "No such app" or "There's nothing here, yet."
- **S3 static site**: "NoSuchBucket" / "The specified bucket does not exist"
- **CloudFront**: 403/400 with "The request could not be satisfied"
- **Azure App Service**: default 404 for azurewebsites.net unless custom-domain verified
- **Shopify**: "Sorry, this shop is currently unavailable"

TLS clues: certificate CN/SAN referencing provider default host instead of the custom subdomain

## Key Vulnerabilities

### Claim Third-Party Resource

- Create the resource with the exact required name:
  - Storage/hosting: S3 bucket "sub.example.com" (website endpoint)
  - Pages hosting: create repo/site and add the custom domain
  - Serverless/app hosting: create app/site matching the target hostname

### CDN Alternate Domains

- Add the victim subdomain as an alternate domain on your CDN distribution if the provider does not enforce domain ownership checks
- Upload a TLS cert or use managed cert issuance

### NS Delegation Takeover

- If a child zone is delegated to nameservers under an expired domain, register that domain and host authoritative NS
- Publish records to control all hosts under the delegated subzone

### Mail Surface

- If MX points to a decommissioned provider, takeover could enable email receipt for that subdomain

## Advanced Techniques

### Blind and Cache Channels

- CDN edge behavior: 404/421 vs 403 differentials reveal whether an alt name is partially configured
- Cache poisoning: once taken over, exploit cache keys to persist malicious responses

### CT and TLS

- Use CT logs to detect unexpected certificate issuance for your subdomain
- For PoC, issue a DV cert post-takeover (within scope) to produce verifiable evidence

### OAuth and Trust Chains

- If the subdomain is whitelisted as an OAuth redirect/callback or in CSP/script-src, takeover elevates to account takeover or script injection

### Verification Gaps

- Look for providers that accept domain binding prior to TXT verification
- Race windows: re-claim resource names immediately after victim deletion

### Wildcards and Fallbacks

- Wildcard CNAMEs to providers may expose unbounded subdomains
- Fallback origins: CDNs configured with multiple origins may expose unknown-domain responses

## Special Contexts

### Storage and Static

- S3/GCS/Azure Blob static sites: bucket naming constraints dictate whether a bucket can match hostname
- Website vs API endpoints differ in claimability and fingerprints

### Serverless and Hosting

- GitHub/GitLab Pages, Netlify, Vercel, Azure Static Web Apps: domain binding flows vary
- Most require TXT now, but historical projects may not

### CDN and Edge

- CloudFront/Fastly/Azure CDN/Akamai: alternate domain verification differs
- Some products historically allowed alt-domain claims without proof

### DNS Delegations

- Child-zone NS delegations outrank parent records
- Control of delegated NS yields full control of all hosts below that label

## Testing Methodology

1. **Enumerate subdomains** - Aggregate CT logs, passive DNS, and org inventory
2. **Resolve DNS** - All RR types: A/AAAA, CNAME, NS, MX, TXT; keep CNAME chains
3. **HTTP/TLS probe** - Capture status, body, error text, Server headers, certificate SANs
4. **Fingerprint providers** - Map known "unclaimed/missing resource" signatures
5. **Attempt claim** (with authorization) - Create missing resource with exact required name
6. **Validate control** - Serve minimal unique payload; confirm over HTTPS

## Validation

1. Before: record DNS chain, HTTP response (status/body length/fingerprint), and TLS details
2. After claim: serve unique content and verify over HTTPS at the target subdomain
3. Optional: issue a DV certificate (legal scope) and reference CT entry as evidence
4. Demonstrate impact chains (CSP/script-src trust, OAuth redirect acceptance, cookie Domain scoping)

## False Positives

- "Unknown domain" pages that are not claimable due to enforced TXT/ownership checks
- Provider-branded default pages for valid, owned resources (not a takeover)
- Soft 404s from your own infrastructure or catch-all vhosts

## Impact

- Content injection under trusted subdomain: phishing, malware delivery, brand damage
- Cookie and CORS pivot: if parent site sets Domain-scoped cookies or allows subdomain origins
- OAuth/SSO abuse via whitelisted redirect URIs
- Email delivery manipulation for subdomain

## Pro Tips

1. Build a pipeline: enumerate (subfinder/amass) → resolve (dnsx) → probe (httpx) → fingerprint (nuclei/custom) → verify claims
2. Maintain a current fingerprint corpus; provider messages change frequently
3. Prefer minimal PoCs: static "ownership proof" page and, where allowed, DV cert issuance
4. Monitor CT for unexpected certs on your subdomains
5. Eliminate dangling DNS in decommission workflows first
6. For NS delegations, treat any expired nameserver domain as critical
7. Use CAA to limit certificate issuance while you triage

## Summary

Subdomain safety is lifecycle safety: if DNS points at anything, you must own and verify the thing on every provider and product path. Remove or verify—there is no safe middle.
