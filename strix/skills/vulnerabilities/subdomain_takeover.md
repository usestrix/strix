# SUBDOMAIN TAKEOVER

## Critical

Subdomain takeover lets an attacker serve content from a trusted subdomain by claiming resources referenced by dangling DNS (CNAME/A/ALIAS/NS) or mis-bound provider configurations. Consequences include phishing on a trusted origin, cookie and CORS pivot, OAuth redirect abuse, and CDN cache poisoning.

## Scope

- Dangling CNAME/A/ALIAS to third-party services (hosting, storage, serverless, CDN)
- Orphaned NS delegations (child zones with abandoned/expired nameservers)
- Decommissioned SaaS integrations (support, docs, marketing, forms) referenced via CNAME
- CDN “alternate domain” mappings (CloudFront/Fastly/Azure CDN) lacking ownership verification
- Storage and static hosting endpoints (S3/Blob/GCS buckets, GitHub/GitLab Pages)

## Methodology

1. Enumerate subdomains comprehensively (web, API, mobile, legacy): aggregate CT logs, passive DNS, and org inventory. De-duplicate and normalize.
2. Resolve DNS for all RR types: A/AAAA, CNAME, NS, MX, TXT. Keep CNAME chains; record terminal CNAME targets and provider hints.
3. HTTP/TLS probe: capture status, body, length, canonical error text, Server/alt-svc headers, certificate SANs, and CDN headers (Via, X-Served-By).
4. Fingerprint providers: map known “unclaimed/missing resource” signatures to candidate services. Maintain a living dictionary.
5. Attempt claim (only with authorization): create the missing resource on the provider with the exact required name; bind the custom domain if the provider allows.
6. Validate control: serve a minimal unique payload; confirm over HTTPS; optionally obtain a DV certificate (CT log evidence) within legal scope.

## Discovery Techniques

### Enumeration Pipeline

- Subdomain inventory: combine CT (crt.sh APIs), passive DNS sources, in-house asset lists, IaC/terraform outputs, mobile app assets, and historical DNS
- Resolver sweep: use IPv4/IPv6-aware resolvers; track NXDOMAIN vs SERVFAIL vs provider-branded 4xx/5xx responses
- Record graph: build a CNAME graph and collapse chains to identify external endpoints (e.g., myapp.example.com → foo.azurewebsites.net)

### Dns Indicators

- CNAME targets ending in provider domains: github.io, amazonaws.com, cloudfront.net, azurewebsites.net, blob.core.windows.net, fastly.net, vercel.app, netlify.app, herokudns.com, trafficmanager.net, azureedge.net, akamaized.net
- Orphaned NS: subzone delegated to nameservers on a domain that has expired or no longer hosts authoritative servers; or to inexistent NS hosts
- MX to third-party mail providers with decommissioned domains (risk: mail subdomain control or delivery manipulation)
- TXT/verification artifacts (asuid, _dnsauth, _github-pages-challenge) suggesting previous external bindings

### Http Fingerprints

- Service-specific unclaimed messages (examples, not exhaustive):
  - GitHub Pages: “There isn’t a GitHub Pages site here.”
  - Fastly: “Fastly error: unknown domain”
  - Heroku: “No such app” or “There’s nothing here, yet.”
  - S3 static site: “NoSuchBucket” / “The specified bucket does not exist”
  - CloudFront (alt domain not configured): 403/400 with “The request could not be satisfied” and no matching distribution
  - Azure App Service: default 404 for azurewebsites.net unless custom-domain verified (look for asuid TXT requirement)
  - Shopify: “Sorry, this shop is currently unavailable”
- TLS clues: certificate CN/SAN referencing provider default host instead of the custom subdomain indicates potential mis-binding

## Exploitation Techniques

### Claim Third Party Resource

- Create the resource with the exact required name:
  - Storage/hosting: S3 bucket “sub.example.com” (website endpoint) or bucket named after the CNAME target if provider dictates
  - Pages hosting: create repo/site and add the custom domain (when provider does not enforce prior domain verification)
  - Serverless/app hosting: create app/site matching the target hostname, then add custom domain mapping
- Bind the custom domain: some providers require TXT verification (modern hardened path), others historically allowed binding without proof

### Cdn Alternate Domains

- Add the victim subdomain as an alternate domain on your CDN distribution if the provider does not enforce domain ownership checks
- Upload a TLS cert via provider or use managed cert issuance if allowed; confirm 200 on the subdomain with your content

### Ns Delegation Takeover

- If a child zone (e.g., zone.example.com) is delegated to nameservers under an expired domain (ns1.abandoned.tld), register abandoned.tld and host authoritative NS; publish records to control all hosts under the delegated subzone
- Validate with SOA/NS queries and serve a verification token; then add A/CNAME/MX/TXT as needed

### Mail Surface

- If MX points to a decommissioned provider that allowed inbox creation without domain re-verification (historically), a takeover could enable email receipt for that subdomain; modern providers generally require explicit TXT ownership

## Advanced Techniques

### Blind And Cache Channels

- CDN edge behavior: 404/421 vs 403 differentials reveal whether an alt name is partially configured; probe with Host header manipulation
- Cache poisoning: once taken over, exploit cache keys and Vary headers to persist malicious responses at the edge

### Ct And Tls

- Use CT logs to detect unexpected certificate issuance for your subdomain; for PoC, issue a DV cert post-takeover (within scope) to produce verifiable evidence

### Oauth And Trust Chains

- If the subdomain is whitelisted as an OAuth redirect/callback or in CSP/script-src, a takeover elevates impact to account takeover or script injection on trusted origins

### Provider Edges

- Many providers hardened domain binding (TXT verification) but legacy projects or specific products remain weak; verify per-product behavior (CDN vs app hosting vs storage)
- Multi-tenant providers sometimes accept custom domains at the edge even when backend resource is missing; leverage timing and registration windows

## Bypass Techniques

### Verification Gaps

- Look for providers that accept domain binding prior to TXT verification, or where verification is optional for trial/legacy tiers
- Race windows: re-claim resource names immediately after victim deletion while DNS still points to provider

### Wildcards And Fallbacks

- Wildcard CNAMEs to providers may expose unbounded subdomains; test random hosts to identify service-wide unclaimed behavior
- Fallback origins: CDNs configured with multiple origins may expose unknown-domain responses from a default origin that is claimable

## Special Contexts

### Storage And Static

- S3/GCS/Azure Blob static sites: bucket naming constraints dictate whether a bucket can match hostname; website vs API endpoints differ in claimability and fingerprints

### Serverless And Hosting

- GitHub/GitLab Pages, Netlify, Vercel, Azure Static Web Apps: domain binding flows vary; most require TXT now, but historical projects or specific paths may not

### Cdn And Edge

- CloudFront/Fastly/Azure CDN/Akamai: alternate domain verification differs; some products historically allowed alt-domain claims without proof

### Dns Delegations

- Child-zone NS delegations outrank parent records; control of delegated NS yields full control of all hosts below that label

## Validation

1. Before: record DNS chain, HTTP response (status/body length/fingerprint), and TLS details.
2. After claim: serve unique content and verify over HTTPS at the target subdomain.
3. Optional: issue a DV certificate (legal scope) and reference CT entry as durable evidence.
4. Demonstrate impact chains (CSP/script-src trust, OAuth redirect acceptance, cookie Domain scoping) with minimal PoCs.

## False Positives

- “Unknown domain” pages that are not claimable due to enforced TXT/ownership checks.
- Provider-branded default pages for valid, owned resources (not a takeover) versus “unclaimed resource” states
- Soft 404s from your own infrastructure or catch-all vhosts

## Impact

- Content injection under trusted subdomain: phishing, malware delivery, brand damage
- Cookie and CORS pivot: if parent site sets Domain-scoped cookies or allows subdomain origins in CORS/Trusted Types/CSP
- OAuth/SSO abuse via whitelisted redirect URIs
- Email delivery manipulation for subdomain (MX/DMARC/SPF interactions in edge cases)

## Pro Tips

1. Build a pipeline: enumerate (subfinder/amass) → resolve (dnsx) → probe (httpx) → fingerprint (nuclei/custom) → verify claims.
2. Maintain a current fingerprint corpus; provider messages change frequently—prefer regex families over exact strings.
3. Prefer minimal PoCs: static “ownership proof” page and, where allowed, DV cert issuance for auditability.
4. Monitor CT for unexpected certs on your subdomains; alert and investigate.
5. Eliminate dangling DNS in decommission workflows first; deletion of the app/service must remove or block the DNS target.
6. For NS delegations, treat any expired nameserver domain as critical; reassign or remove delegation immediately.
7. Use CAA to limit certificate issuance while you triage; it reduces the blast radius for taken-over hosts.

## Remember

Subdomain safety is lifecycle safety: if DNS points at anything, you must own and verify the thing on every provider and product path. Remove or verify—there is no safe middle.
