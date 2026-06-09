---
name: domain
description: Methodology for mapping DNS, subdomains, and every web surface under an apex domain to find exploitable entry points.
---

# Domain (Apex / URL)

A domain asset is the root of an organization's externally reachable footprint: an apex name (`example.com`), its DNS records, every subdomain, and the web/API/service surfaces those names resolve to. The objective is to build a complete, current map of that footprint — discover hosts the owner forgot, fingerprint the tech behind each, and convert that map into validated entry points (takeovers, exposed admin panels, leaked secrets, injectable parameters). Breadth first, then depth on the highest-signal hosts.

## Attack Surface

- **DNS layer** — A/AAAA/CNAME/MX/NS/TXT/SRV/CAA records, zone transfers, wildcard records, dangling CNAMEs pointing at deprovisioned cloud resources (subdomain takeover).
- **Subdomains** — staging/dev/uat hosts, legacy apps, internal tools accidentally public, vendor-hosted names (`status.`, `mail.`, `vpn.`, `git.`, `jira.`, `*.s3`, `cdn.`).
- **Web surfaces per host** — virtual hosts, ports beyond 80/443, reverse-proxied apps, API gateways, default/error pages revealing stack, directory listings.
- **Edge & infra** — CDN/WAF in front (Cloudflare, Akamai, Fastly), origin-IP leakage, load balancers, S3/GCS/Azure buckets bound to vanity names.
- **Crawlable content** — JS bundles (endpoints, API keys, internal hostnames), sitemaps, robots.txt, source maps, `.git`/`.env`/backup files left in webroot.
- **Trust artifacts** — TLS SAN entries, CT logs, SPF/DKIM/DMARC posture, exposed metadata in HTTP headers.

## Recon & Enumeration

Set scope once and reuse: `export APEX=example.com`.

**Passive subdomain discovery (no traffic to target):**
```
subfinder -d $APEX -all -recursive -silent -o subs_passive.txt
# CT logs as a cross-check
curl -s "https://crt.sh/?q=%25.$APEX&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> subs_passive.txt
```

**Active DNS resolution & brute force (dnsx is in the sandbox; install dnsrecon if needed: `pipx install dnsrecon`):**
```
sort -u subs_passive.txt > subs.txt
dnsx -l subs.txt -a -aaaa -cname -resp -silent -o resolved.txt
# brute force with a wordlist + resolved validation
dnsx -d $APEX -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -silent -o subs_brute.txt
# zone transfer & record sweep
dnsrecon -d $APEX -a            # AXFR attempt + standard records
dig +short NS $APEX; dig +short TXT $APEX; dig +short MX $APEX; dig +short CAA $APEX
```

**Port discovery (naabu then nmap on what's open):**
```
naabu -list <(awk '{print $1}' resolved.txt | sort -u) -top-ports 1000 -silent -o ports.txt
nmap -iL <(cut -d: -f1 ports.txt | sort -u) -p $(cut -d: -f2 ports.txt | paste -sd,) -sV -sC --open -oA nmap_svc
```

**Probe live web surfaces & fingerprint:**
```
httpx -l subs.txt -sc -title -tech-detect -server -location -ip -cname -web-server \
  -follow-redirects -json -o httpx.jsonl
# extract live URLs for downstream tools
jq -r 'select(.status_code) | .url' httpx.jsonl | sort -u > live_urls.txt
wafw00f -i live_urls.txt -o wafw00f.json     # identify WAF/CDN in front
```

**Crawl, content discovery, and secret hunting:**
```
katana -list live_urls.txt -d 3 -jc -kf all -aff -silent -o crawl.txt   # -jc parses JS for endpoints
ffuf -u https://FUZZ_HOST/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -H "Host: target" -mc 200,204,301,302,401,403 -ac -o ffuf.json   # run per host
# pull JS, scan for secrets/keys/internal hosts
trufflehog filesystem ./js_dump --only-verified --json > secrets.json
gitleaks detect --source ./repo_or_webroot -f json -r gitleaks.json   # if source/backup recovered
```

**Vulnerability sweep across the whole live set:**
```
nuclei -l live_urls.txt -as -s critical,high -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -j -o nuclei.jsonl
nuclei -l subs.txt -t dns/ -tags takeover -silent -o takeover.txt   # dangling CNAME / takeover templates
```

## Methodology

1. **Lock scope.** Confirm the apex and any explicitly in-scope wildcards. Keep `$APEX` and an out-of-scope exclude list to filter every output.
2. **Passive first.** Run `subfinder` + crt.sh/CT logs and DNS record pulls before sending volume — builds the map without tipping defenses.
3. **Resolve & validate.** Run `dnsx` over the union of passive + brute results; keep only names that resolve. Note CNAMEs pointing to third-party services (takeover candidates).
4. **Map ports.** `naabu` for breadth, `nmap -sV -sC` for depth on open ports. Flag non-web services (databases, RDP, SMB, Redis, Elasticsearch) for separate handling.
5. **Probe & fingerprint web.** `httpx` for status/title/tech/CNAME/IP; `wafw00f` to know what edge sits in front. Cluster hosts by tech stack and by whether they sit behind a WAF.
6. **Prioritize.** Rank hosts: non-prod (dev/staging/uat), unauthenticated admin/tooling, distinct/old tech stacks, error pages leaking stack, hosts NOT behind the WAF.
7. **Crawl & content-discover.** `katana` (with `-jc`) plus `ffuf` per high-value host. Harvest JS for endpoints, API bases, and internal hostnames.
8. **Hunt low-hanging exposures.** `.git/`, `.env`, `/.svn/`, backup archives, source maps, directory listings, Swagger/`/openapi.json`, `/actuator`, `/server-status`.
9. **Scan.** `nuclei -as` for known CVEs/misconfigs; takeover templates over the full subdomain list.
10. **Validate & escalate.** Manually confirm each candidate (next sections). Chain DNS/edge findings into application access.

## Key Weaknesses / Techniques

- **Subdomain takeover.** A subdomain CNAMEs to a deprovisioned third-party (S3, GitHub Pages, Heroku, Azure, Fastly) returning the provider's "no such bucket/app" page. Validate the CNAME target and fingerprint the error:
  ```
  dig CNAME sub.$APEX +short
  nuclei -u https://sub.$APEX -t dns/ -tags takeover
  ```
  Confirm by registering the claimable resource (only with authorization) and serving a benign marker file.
- **Zone transfer (AXFR).** Misconfigured NS leaks the full zone:
  ```
  for ns in $(dig +short NS $APEX); do dig AXFR $APEX @$ns; done
  ```
- **Origin-IP leakage behind CDN/WAF.** WAF only protects the edge; hitting the origin IP directly bypasses it. Find origin via historical DNS, SAN/CT mismatches, or a vhost that resolves outside the CDN, then:
  ```
  curl -sk -H "Host: $APEX" https://<origin-ip>/ -o /dev/null -w "%{http_code}\n"
  ```
- **Exposed VCS / config / backups.** `.git/HEAD`, `.env`, `config.php.bak`, `db.sql` in webroot. Recover and scan:
  ```
  curl -s https://host/.git/HEAD          # 200 + "ref: refs/..." => exposed repo
  git-dumper https://host/.git/ ./repo    # pipx install git-dumper
  trufflehog filesystem ./repo --only-verified
  ```
- **Secrets in JS bundles.** API keys, signing secrets, internal API hosts. Pull all JS from `katana`, grep for `api_key`, `Authorization`, `s3.amazonaws.com`, internal `.local`/`.internal` hosts.
- **Virtual-host confusion / default pages.** Same IP, different `Host:` headers expose unlinked apps. Fuzz the `Host` header against discovered IPs.
- **Injectable parameters surfaced by crawl.** Feed crawled URLs with params into `sqlmap`:
  ```
  sqlmap -m <(grep '=' crawl.txt) --batch --random-agent --level 2 --risk 1
  ```
- **Email-spoofing posture.** Weak/missing SPF/DMARC enables phishing from the domain:
  ```
  dig +short TXT $APEX | grep spf; dig +short TXT _dmarc.$APEX
  ```
- **Container/dependency exposure** (if images or SBOMs recovered): `trivy image <ref>` and `syft <ref> -o json | grype` for known-vuln components.

## Validation

- **Takeover:** show the dangling CNAME, the provider error fingerprint, and (authorized) a controlled claim serving a unique benign file at `https://sub.$APEX/<random>.txt`. Screenshot both the pre-claim error and post-claim marker.
- **Origin bypass:** demonstrate identical app response from the raw origin IP that a WAF-blocked payload returns differently at the edge (same `Host` header, payload blocked at edge but served at origin).
- **Exposed repo/secrets:** reconstruct a file from `.git`, then verify a leaked credential with a minimal authenticated call (e.g., `aws sts get-caller-identity`) — capture identity, do not act further.
- **Injection/CVE:** reproduce with a single deterministic request; for blind classes use `interactsh-client` and embed the unique `*.oast.fun` host in the payload, then correlate the inbound hit.
- Re-run each PoC a second time to confirm stability and record the exact request/response.

## False Positives

- **Wildcard DNS** makes every brute-forced name "resolve." Detect with a random label (`dig $(openssl rand -hex 6).$APEX`); if it answers, filter brute results by unique content/IP, not mere resolution.
- **Takeover false alarms:** CNAME to a service that returns a generic 404 but is NOT actually claimable (provider verifies ownership), or the resource still exists. Confirm claimability before reporting.
- **CDN shared IPs:** an "origin" IP that is just another CDN edge — verify it serves the app without the CDN headers, not a generic edge response.
- **Out-of-scope hosts:** crt.sh and CT logs return sibling brands and parked domains; filter to in-scope apex/wildcards.
- **Nuclei version/CVE matches** based on banners alone — confirm the vulnerable code path is reachable, not just a fingerprinted version string.
- **Dev placeholder pages** ("under construction") are not exposures unless they leak config or admin functionality.

## Chaining & Impact

- Forgotten staging subdomain (no WAF, debug on) → exposed `.env` → DB creds → data access.
- Dangling CNAME → subdomain takeover → host content on a trusted name → phishing / cookie theft (if cookies are scoped to the apex, session hijack across the real app).
- Origin-IP discovery → WAF bypass → previously-blocked SQLi/RCE now reachable.
- Leaked AWS key in JS → `aws sts get-caller-identity` → bucket enumeration → broader cloud foothold (hand off to cloud methodology).
- Weak DMARC + lookalike subdomain → high-credibility phishing against employees.
- Exposed `/actuator`, `/server-status`, or Swagger → internal endpoint map → authenticated API abuse.

## Pro Tips

1. Diff your subdomain map across runs — newly appearing dev/staging hosts during a release window are the softest targets.
2. The host that is NOT behind the WAF is the real target; cluster `httpx` output by CNAME/IP to spot the one origin sitting outside Cloudflare/Akamai.
3. Always `dig CNAME` every subdomain — takeovers hide in third-party CNAMEs, and they are quick, high-impact, low-noise wins.
4. JS bundles are an endpoint goldmine; `katana -jc` plus a grep for hostnames often reveals internal APIs no crawler would otherwise find.
5. Resolve brute-force candidates with `dnsx` before any active scan — never port-scan or fuzz names that do not resolve.
6. Verify scope with a wildcard probe first; reporting wildcard noise as live hosts destroys credibility.
7. Re-check CT logs (crt.sh) late in the engagement — new certs issued during testing expose freshly deployed hosts.
8. Throttle (`-rl`, `-c`) when a WAF is detected; aggressive enumeration gets the source IP blocked and poisons the rest of the assessment.
