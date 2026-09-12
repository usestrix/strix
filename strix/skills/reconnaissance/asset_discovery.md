---
name: asset-discovery
description: Passive asset and attack-surface discovery via certificate transparency, TLS SAN pivoting, passive DNS, and ASN/IP enumeration to find hosts beyond subdomain brute force
---

# Asset Discovery

Most engagements start from a small seed (one domain, one org name) but the real attack surface is far larger: forgotten hosts, staging/internal-named services, acquisitions, and infrastructure that never appears in a wordlist. Build a broad, deduplicated inventory using passive intelligence — certificate transparency, TLS certificate metadata, passive DNS, and ASN/IP data — then collapse it into a probed, classified attack surface. The aim is coverage and pivoting: every certificate, DNS record, and IP is a lead to more assets.

Only use this skill when all subdomains and related assets of the target are in scope — broad discovery pulls in hosts far beyond the seed.

## Attack Surface

- Hosts discoverable via issued certificates (CT logs) but absent from DNS brute force
- Internal/staging/pre-prod hostnames leaked in certificate SAN lists
- Sibling and acquisition domains sharing certificates, ASNs, or IP ranges with the seed
- Wildcard and short-lived certs revealing naming conventions (`*.internal.example.com`, `k8s-*`, `argocd.*`)
- ASN-owned IP ranges hosting services with no DNS name at all
- Virtual hosts co-located on shared IPs (multiple apps behind one address)
- Non-HTTP services on discovered hosts (databases, brokers, admin ports)

## High-Value Sources

### Certificate Transparency (CT)

CT logs record nearly every publicly-trusted certificate. Query by domain (matches SAN/CN) and by organization name.

- **crt.sh** (free, no key):
  - By domain incl. subdomains: `curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sed 's/^\*\.//' | sort -u`
  - By organization: `https://crt.sh/?O=Example+Inc&output=json`
- **Censys / Shodan / Fofa** (API keys): search certs by `parsed.names`, `parsed.subject.organization`, or a specific `fingerprint_sha256`, then pivot to every host serving that cert.
- Cross-check multiple indexes (`certspotter`, Google CT, `chaos`) — no single log is complete.
- **Wildcards** (`*.corp.example.com`) reveal internal naming schemes even when individual hosts resolve privately; use them to seed targeted guesses (`grafana.corp`, `ci.corp`, `vault.corp`).

### TLS Certificate SAN/CN

- **SAN expansion**: one cert often lists many hostnames (marketing + api + admin + internal) — extract every SAN, not just the queried name.
- **Shared-cert pivot**: the same cert fingerprint served on multiple IPs ties disparate assets to one owner.
- **Issuer/org pivot**: certs sharing `subject.organization`/`organizationalUnit` frequently belong to the same target.
- **Active read** catches names never submitted to public CT: `echo | openssl s_client -connect HOST:443 -servername HOST 2>/dev/null | openssl x509 -noout -text | grep -A1 'Subject Alternative Name'`
- **Internal leak signal**: SANs like `localhost`, `*.internal`, `*.svc.cluster.local`, `*.local`, or RFC1918-style names on a public cert expose internal naming and sometimes internal services fronted publicly.

### Passive DNS

- Forward-resolve every name (A/AAAA/CNAME); keep CNAME chains — they reveal third-party providers and CDNs.
- **Reverse DNS (PTR)** on discovered IPs surfaces co-located hostnames.
- **Historical/passive DNS** (SecurityTrails, VirusTotal, `chaos`, passivedns providers) recovers names that no longer resolve but may still front live infra.

### ASN & IP Ranges

- Map a known IP to its ASN and netblock: `whois -h whois.cymru.com " -v <IP>"` or a BGP/ASN lookup.
- If the org runs its own ASN, enumerate all announced prefixes and treat them as candidate assets.
- For cloud-hosted targets the IP belongs to the provider, not the org — pivot via cert/vhost instead of netblock.

## Recommended Tooling

These tools are available in the sandbox and are pipeline-friendly with JSON output:

- **`subfinder`** — passive subdomain aggregation across many sources incl. CT: `subfinder -d example.com -all -recursive -silent -oJ -o subs.jsonl`
- **`httpx`** — live probing plus cert/SAN grab in one pass: `httpx -l hosts.txt -tls-grab -json` (see methodology).
- **`naabu`** — port sweep for non-HTTP services: `naabu -list hosts.txt -top-ports 100 -verify -silent`
- **`curl` + `jq`** — direct **crt.sh** JSON queries for CT (no key needed) and other index APIs.
- **`openssl s_client`** — active read of a live host's cert to extract SANs/CN.
- **`dig`** / **`nslookup`** — forward/reverse (PTR) resolution and CNAME chains.
- **`whois`** — ASN/netblock lookups (e.g. `whois -h whois.cymru.com`).

Cross-source results — CT + passive DNS + `subfinder` together beat any single source. If you need a tool that is not installed, install it into the sandbox at runtime.

## Key Techniques

### Iterative Seed Expansion

Every new name, PTR result, CNAME target, and cert SAN becomes a fresh seed. Loop CT → SAN extraction → passive DNS → ASN/range expansion until the asset set stops growing.

### Cert-Fingerprint Pivoting

Search Censys/Shodan by a cert's `fingerprint_sha256` to find every other host presenting the same certificate — the strongest cross-asset link for tying acquisitions and shadow infra to the target.

### Naming-Convention Inference

Wildcard SANs and observed hostnames expose the org's naming scheme; generate targeted candidates from it (`<service>.<env>.example.com`) rather than blind brute force.

### IP-First Discovery

For ASN-owned ranges, sweep IPs directly with `naabu`/`httpx` and read served certs (`httpx -tls-grab`, or `openssl s_client`) to find services that have no DNS name at all.

## Advanced Techniques

- **Active SAN harvesting** across whole ranges with `httpx -tls-grab` (or `openssl s_client`) recovers internal hostnames never logged to public CT.
- **Favicon and response hashing** (`httpx -favicon`, hash pivots in Shodan) clusters instances of the same app across unrelated hostnames.
- **Vhost differentials**: probe a single IP with multiple `Host:` values to unmask co-located apps behind one address.
- **Historical CT/DNS diffing** highlights recently issued certs and newly appearing hosts — high-signal for fresh or misconfigured deployments.

## Consolidation & Probing

1. **Dedupe** names and IPs into one inventory; record source(s) per asset for confidence.
2. **Live probe** with `httpx`, capturing status/title/tech/server and cert SANs in one pass — each grabbed SAN feeds back as a new seed:
   `httpx -l hosts.txt -sc -title -server -td -tls-grab -json -o assets.jsonl`
3. **Classify** assets by function from title/tech/path signals: app, API, marketing, auth, CI/CD, observability, storage, admin, VCS, mail. Cluster by role, not by a specific product.
4. **Port sweep** interesting hosts with `naabu` for non-HTTP services (DBs, caches, brokers, mgmt ports).
5. **Prioritize** by exposure and value, then hand each finding to the right specialist skill:
   - Exposed dashboards / debug / observability / metadata leaks → `information_disclosure`
   - Login/admin panels with default or weak creds → `weak_password_detection`
   - Dangling DNS / unclaimed provider resources → `subdomain_takeover`
   - Cloud consoles/metadata surfaces → `aws` / `gcp` / `kubernetes`

## Testing Methodology

1. **Seed** - domains, org/legal names, known IPs, email domains, code-host org
2. **Certificate transparency** - pull all logged certs per seed domain and org name (crt.sh, Censys/Shodan)
3. **SAN/CN extraction** - parse every Subject CN and SAN with `httpx -tls-grab` (or `openssl s_client`); each new name is a new seed
4. **Passive DNS** - resolve forward and reverse with `dig`; harvest historical records
5. **ASN/IP mapping** - `whois` the netblock/ASN to expand owned ranges, then sweep for live hosts
6. **Active TLS pivot** - `httpx -tls-grab` on live IPs/ports to grab SANs missing from public CT
7. **Consolidate & probe** - dedupe, `httpx` probe, classify, and route to specialists

## Validation

1. Confirm each discovered asset actually resolves and serves content (live `httpx` result, not just a passive hit)
2. Attribute assets to the target via matching cert org, shared cert fingerprint, or DNS under a seed domain
3. Deduplicate vhost aliases and CDN edges down to distinct origins so the surface is not inflated
4. Record provenance (which source produced each asset) for reproducibility

## False Positives

- CDN/edge hostnames and provider default names that are not org-owned
- Shared-hosting neighbors on the same IP (vhost co-tenancy, not the target's asset)
- Stale historical DNS entries pointing at reassigned infrastructure
- Wildcard-cert-implied hostnames that never actually resolve or serve content

## Impact

- Expanded attack surface: forgotten, staging, and internal-named hosts brute force misses
- Discovery of misconfigured or unauthenticated services fronted by leaked internal hostnames
- Attribution of shadow infra, acquisitions, and sibling domains to the target
- A prioritized, classified inventory that feeds every downstream specialist skill

## Pro Tips

1. Loop the pipeline — every SAN, PTR, and CNAME target is a new seed until the set converges.
2. crt.sh is the cheapest high-yield source (no key); Censys/Shodan add cert-fingerprint and vhost pivoting when keys exist.
3. Always cert-grab live hosts with `httpx -tls-grab` (or `openssl s_client`) — active SANs catch internal hostnames never sent to public CT.
4. Internal-looking SANs (`*.internal`, `*.svc.cluster.local`, staging names) are the highest-signal leads.
5. Wildcard SANs reveal naming conventions — seed targeted guesses instead of blind brute force.
6. Cluster by function, not product name, so the workflow generalizes to any exposed service.
7. Keep JSON output throughout so stages chain cleanly (`subfinder` → `dig` → `httpx` → `naabu`).

## Summary

Broad passive discovery — CT + TLS SAN pivoting + passive DNS + ASN/IP mapping, looped until convergence — finds the assets brute force misses, especially internal-named and forgotten services leaked through certificates. Build the inventory with `subfinder`, `httpx`, `naabu`, and CT/DNS/cert queries, probe and classify it generically, then route each interesting asset to the specialist skill for its class.
