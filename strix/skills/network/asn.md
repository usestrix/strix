---
name: asn
description: ASN-driven recon — expand an Autonomous System Number to prefixes, enumerate live hosts and services, and map the attack surface of an organization's owned IP space.
---

# ASN (Autonomous System Number)

An ASN is a globally unique identifier (e.g. `AS15169`) assigned to an entity that controls one or more IP prefixes and announces routes via BGP. In an authorized engagement, an ASN is a scope anchor: it lets you discover the full set of network blocks an organization owns, then expand outward to live hosts, exposed services, and forgotten infrastructure that DNS-based recon alone misses. The objective is to convert one identifier into a validated, in-scope host/service inventory, then find the weakest exposed surface across that inventory. ASN ownership is fuzzy — confirm each prefix belongs to the target before touching it.

## Attack Surface

- **Announced prefixes** — IPv4/IPv6 CIDR blocks routed by the ASN; the raw address space you are authorized to assess.
- **Edge/perimeter services** — anything listening on a public IP: web (80/443/8080/8443), SSH (22), RDP (3389), VPN (500/4500/1194/443), mail (25/465/587/993), DNS (53), databases accidentally exposed (3306/5432/6379/27017/9200).
- **Forgotten / shadow assets** — staging boxes, old appliances (VPN concentrators, firewalls, IP cameras, printers, iDRAC/iLO/IPMI on 623/443), default-credential admin panels.
- **Cloud vs on-prem mix** — an org's own ASN usually means colo/datacenter/on-prem; cloud assets live in the provider's ASN (AWS AS16509, GCP AS15169, Azure AS8075) and must be attributed by tenancy, not ASN ownership.
- **Reverse DNS / PTR space** — hostnames bound to IPs reveal naming conventions, environments (`vpn-`, `dev-`, `mail-`), and tech.
- **TLS certificates** — SANs on every HTTPS host link IPs back to domains and sibling infrastructure.

## Recon & Enumeration

Most tools below are already in the Kali sandbox. Install the few that are not.

```bash
# --- ASN -> prefixes ---------------------------------------------------------
# Whois the ASN and pull route objects
whois -h whois.radb.net -- '-i origin AS15169' | awk '/^route/ {print $2}' | sort -u
whois AS15169                                   # org, contacts, abuse handle

# ProjectDiscovery asnmap (install if missing): ASN/org/IP/domain -> CIDRs
go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
asnmap -a AS15169 -silent                       # prefixes for an ASN
asnmap -d target.tld -silent                    # ASN(s) behind a domain
echo target.tld | asnmap -silent | tee prefixes.txt

# Cross-check with BGP data sources (no key needed)
curl -s "https://api.bgpview.io/asn/15169/prefixes" | jq -r '.data.ipv4_prefixes[].prefix'
curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS15169" \
  | jq -r '.data.prefixes[].prefix'

# Find sibling ASNs / org footprint by org name
curl -s "https://api.bgpview.io/search?query_term=ExampleCorp" | jq -r '.data.asns[].asn'

# --- attribute & confirm ownership BEFORE scanning ---------------------------
# Reverse DNS sweep to sanity-check that PTRs reference the target
mapcidr -cidr prefixes.txt -silent | dnsx -ptr -resp-only -silent   # install: go install .../dnsx, .../mapcidr

# --- prefixes -> live hosts --------------------------------------------------
mapcidr -cl prefixes.txt -silent > all_ips.txt            # expand CIDRs to IPs
naabu -list all_ips.txt -top-ports 1000 -rate 1000 -silent -o open_ports.txt
# Or nmap host discovery on big space (no port scan, fast)
nmap -sn -iL prefixes.txt -oA hosts_alive --min-rate 2000

# --- services & versions -----------------------------------------------------
nmap -sV -sC -Pn -iL live_hosts.txt --top-ports 200 -oA services --min-rate 1500
naabu -list live_hosts.txt -p - -rate 2000 -silent | nmap -sV -iL - -oA full

# --- web layer ---------------------------------------------------------------
cut -d: -f1 open_ports.txt | sort -u | httpx -silent -title -tech-detect \
  -status-code -tls-grab -cdn -o web.txt
# TLS SAN harvesting -> new in-scope domains
cat live_hosts.txt | httpx -silent -tls-grab -json | jq -r '.tls.subject_an[]?' | sort -u

# --- vuln + content ----------------------------------------------------------
nuclei -l web.txt -as -s critical,high -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -j -o nuclei.jsonl
wafw00f -i web.txt                               # WAF/edge fingerprint
katana -list web.txt -d 2 -jc -silent -o urls.txt
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -u https://HOST/FUZZ -mc 200,301,302,401,403 -t 40   # per interesting host
```

## Methodology

1. **Establish authorization & scope.** Confirm the engagement covers the ASN and that prefixes you discover are actually owned by the target (lease vs ownership matters). Maintain a scope allowlist; drop any prefix you cannot attribute.
2. **Resolve the ASN.** From a domain, `asnmap -d target.tld`; from an org name, `bgpview.io/search`. Note sibling ASNs — orgs often have several (acquisitions, regions).
3. **Expand to prefixes.** Union of `asnmap`, RIPEstat announced-prefixes, and BGPView. De-dupe IPv4 and IPv6 separately. Don't forget IPv6 — it is routinely under-monitored.
4. **Attribute prefixes.** PTR sweep + whois per block. Flag cloud-provider ASNs as out-of-scope-by-ownership and reconcile against the rules of engagement.
5. **Host discovery.** Expand CIDRs with `mapcidr`, then `naabu`/`nmap -sn` to find live hosts. Rate-limit; large `/16`s are noisy.
6. **Service enumeration.** Port-scan live hosts, then `-sV -sC` for versions and default scripts. Capture banners for offline triage.
7. **Web & TLS layer.** `httpx` for titles/tech/TLS; mine SAN fields for additional domains, loop those back through DNS/subfinder recon.
8. **Targeted vuln assessment.** Drive `nuclei -as`, then dig into appliances, admin panels, and outdated services found in steps 6–7.
9. **Prioritize & validate.** Rank by exploitability and exposure (unauth admin > default creds > known CVE on edge > info leak). Build PoCs for top findings.

## Key Weaknesses / Techniques

- **Exposed management/admin interfaces.** iLO/iDRAC/IPMI (623/udp, 443), ESXi (443/902), printers, switches, NAS, VPN admin. Often default or weak creds.
  ```bash
  nuclei -l web.txt -tags exposure,panel,default-login -s high,critical -silent
  nmap -p623 -sU --script ipmi-version,ipmi-cipher-zero -iL live_hosts.txt   # IPMI cipher-0 auth bypass
  ```
- **Database / cache exposed to the internet.** Redis, Mongo, Elasticsearch, Memcached, Postgres/MySQL bound to public IPs.
  ```bash
  nmap -p6379,27017,9200,11211,5432,3306 --script "*-info,*-databases,*-unauth" -iL live_hosts.txt
  redis-cli -h HOST ping            # PONG with no AUTH = unauthenticated access
  curl -s http://HOST:9200/_cat/indices    # open Elasticsearch
  ```
- **Outdated edge software / known CVEs.** Citrix, Fortinet, Pulse/Ivanti, Exchange, F5 — perimeter gear is high value. Match `nmap -sV` banners to CVEs and confirm with version-specific nuclei templates.
- **Default & weak credentials** on SSH/RDP/web panels found across the block. Spray conservatively and only with authorized scope; one shared default often unlocks many hosts on the same ASN.
- **Stale TLS / expired certs / wildcard reuse.** Reveal forgotten hosts and shared key material.
  ```bash
  cat live_hosts.txt | httpx -tls-grab -json -silent \
    | jq -r 'select(.tls.not_after < (now|todate)) | .host'   # expired certs
  ```
- **rDNS / banner intelligence.** PTRs and SSH/HTTP banners leak naming schemes and software, narrowing where to focus.
- **Routing / origin spoofability** (deeper): an ASN that accepts unfiltered route announcements or lacks RPKI ROAs is exposed to prefix hijack — report as a configuration weakness, do not announce routes.

## Validation

- **Liveness + ownership:** for each reported host, show the IP falls in a prefix announced by the in-scope ASN (`asnmap`/RIPEstat output) and that PTR/whois/TLS SAN ties it to the target. A finding on a misattributed IP is invalid.
- **Service exposure:** capture the raw banner/response proving the service is reachable from the public internet, e.g. `nmap -sV` output, `redis-cli ... ping` → `PONG`, or `curl` returning data without auth.
- **Vuln confirmation:** reproduce the nuclei/manual finding with a minimal, non-destructive PoC (a single request that returns version data, an unauthenticated index listing, or a read-only command). Save request/response pairs.
- **Reachability sanity:** re-run from a clean network path to rule out a transient route or your own caching; confirm the same IP and port respond.

## False Positives

- **Misattributed prefixes** — IP space leased to a third party, CDN/cloud ranges, or a sibling org outside scope. Always confirm ownership before claiming a finding.
- **Cloud/CDN front IPs** — `httpx -cdn` flags Cloudflare/Akamai/Fastly; the "host" is shared edge infrastructure, not the target's box. Findings there are usually the provider's, not the client's.
- **Filtered vs closed** — `naabu`/`nmap` over rate-limited paths report phantom open ports; re-scan slower and confirm with a real handshake.
- **Stale BGP/DNS data** — prefixes withdrawn since last route-collector update; verify the prefix is currently announced.
- **Honeypots/tarpits** — hosts that answer every port. If `nmap` shows hundreds of open ports with identical banners, treat as decoy.
- **Shared hosting** — one IP, many unrelated vhosts; the vuln may belong to a co-tenant. Validate by Host header / SNI.

## Chaining & Impact

- ASN → prefixes → **exposed Redis/Mongo with no auth** → data exfiltration or, via Redis, write SSH keys / cron for RCE on the host.
- ASN → **unauth IPMI/iDRAC/iLO** → out-of-band server control → boot to attacker media → full host compromise, persistence below the OS.
- ASN → **outdated VPN/firewall (Fortinet/Ivanti/Citrix) CVE** → pre-auth foothold → pivot into the internal network the appliance protects.
- ASN → **TLS SAN harvesting** → new apex domains → subdomain recon → app-layer vulns (then hand off to the relevant app skill, e.g. ssrf/graphql).
- ASN → **default-cred admin panel on a shadow host** → lateral movement to peers sharing the same management VLAN / credentials.
- Single weak host on the ASN frequently shares credentials, images, or trust with the rest of the block — one foothold tends to generalize.

## Pro Tips

1. Treat ASN ownership as a hypothesis, not a fact. Confirm every prefix via PTR + whois + TLS before scanning; mis-scope is the fastest way to test out-of-scope systems.
2. Always include IPv6 prefixes — defenders monitor and firewall them far less than IPv4.
3. Orgs own multiple ASNs. Pivot from org name in BGPView and check acquisitions; the juicy host is often on the forgotten secondary ASN.
4. Cloud assets are NOT in the org's ASN. Don't expect AWS/Azure boxes here; attribute those by account/tenant, not by route origin.
5. Mine TLS SAN fields aggressively — one HTTPS host on the block can reveal a dozen new in-scope domains for the next recon loop.
6. Rate-limit on production address space. A `/16` blasted at full speed trips IDS and can disrupt live services; keep `naabu -rate` and `nmap --min-rate` modest and run during agreed windows.
7. PTR naming conventions are a map: `vpn-`, `dev-`, `staging-`, `mgmt-`, `bastion-` tell you exactly where to look first.
8. Re-resolve prefixes at the start of each engagement day; BGP announcements change and assets appear/disappear.
9. Feed `httpx -json` and `nmap -oX` into a single inventory; dedupe by IP+port so re-scans stay incremental and explainable.
