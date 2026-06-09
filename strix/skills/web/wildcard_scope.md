---
name: wildcard_scope
description: Wildcard network-scope methodology — enumerate every subdomain, fingerprint each host, and triage the full attack surface
---

# Wildcard Scope (*.target.tld)

A wildcard scope authorizes testing of every host under a domain (e.g. `*.target.tld`), not a single application. The attacker's objective is breadth-then-depth: discover the complete set of live names and IPs, fingerprint each one, and find the weakest surface — a forgotten staging box, an unclaimed CNAME, an exposed admin panel, or a leaked secret — because in a wildcard scope the win is rarely the flagship app. Coverage is the edge: the host you do not enumerate is the host you do not test.

## Attack Surface

**Names**
- Apex + all subdomains: `www`, `api`, `app`, `admin`, `staging`, `dev`, `uat`, `internal`, `vpn`, `git`, `jenkins`, `grafana`, `mail`, `cdn`, `assets`
- Wildcard DNS records (`*.target.tld → x.x.x.x`) that mask which names truly exist
- Multi-level names: `api.staging.target.tld`, `s3.internal.dev.target.tld`
- Vanity/partner CNAMEs pointing at third-party SaaS (a frequent takeover source)

**Hosts behind names**
- Many virtual hosts on one IP (SNI/Host-header routed); enumerate per-name, not per-IP only
- Non-web ports: SSH, RDP, databases, mail, Redis/Memcached, message brokers, admin daemons
- Origin servers hiding behind a CDN/WAF (the real attack surface)

**Asset types you will collect**
- Web apps and APIs (REST/GraphQL/gRPC-web)
- Dangling DNS pointing at deprovisioned cloud resources (S3, Azure, GitHub Pages, Heroku, Fastly)
- Dev/CI/observability tooling exposed to the internet
- Object storage buckets and CDN origins named after the org
- Source-leak surfaces: exposed `.git`, `.env`, backups, `swagger.json`, `.map` files

## Recon & Enumeration

Most tools below ship in the Kali sandbox. Install missing ones as noted.

**Passive subdomain discovery (no traffic to target)**
```
subfinder -d target.tld -all -recursive -o subs_passive.txt
# Certificate transparency adds names passive sources miss:
curl -s 'https://crt.sh/?q=%25.target.tld&output=json' | jq -r '.[].name_value' | sed 's/\*\.//' | sort -u >> subs_passive.txt
amass enum -passive -d target.tld -o subs_amass.txt   # apt install amass
```

**Active resolution + bruteforce**
```
# dnsx: resolve, drop dead names, expand wildcard noise (-wd does wildcard filtering)
dnsx -l subs_passive.txt -r 1.1.1.1,8.8.8.8 -a -resp -wd target.tld -o resolved.txt
# Bruteforce permutations against a wordlist:
dnsx -d target.tld -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -wd target.tld -o subs_brute.txt
# Permute known names (env/region prefixes):
gotator -sub subs_passive.txt -perm /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt -depth 1 | dnsx -silent -wd target.tld
dnsrecon -d target.tld -t std,brt -D /usr/share/seclists/Discovery/DNS/namelist.txt   # apt install dnsrecon
```

**Wildcard detection (critical first step)**
```
# Resolve a guaranteed-bogus name. If it answers, a wildcard record exists and naive bruteforce is meaningless:
dnsx -d zzzznonexistent-$(date +%s).target.tld -a -resp
```
If the random name resolves, rely on dnsx `-wd` filtering and content-diffing rather than DNS existence.

**Liveness + fingerprinting**
```
cat resolved.txt subs_brute.txt | sort -u > all_hosts.txt
httpx -l all_hosts.txt -sc -title -td -server -ip -cname -location \
  -tls-grab -favicon -jarm -json -o httpx.json
# tech detection (-td), favicon hash (-favicon) and JARM cluster origins/CDNs.
```

**Port + service sweep (per host)**
```
naabu -l all_hosts.txt -top-ports 1000 -rate 1000 -o ports.txt
# Service/version detail on the open ports naabu found:
nmap -sV -sC -Pn -iL <(cut -d: -f1 ports.txt | sort -u) -oA nmap_services
```

**Per-surface deep recon**
```
katana -list live_web.txt -jc -kf all -d 3 -o crawl.txt          # crawl + parse JS for endpoints
ffuf -u https://HOST/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,204,301,302,401,403 -o ffuf_HOST.json
nuclei -l live_web.txt -as -s critical,high -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -j -o nuclei.jsonl
nuclei -l all_hosts.txt -tags takeover -j -o takeover.jsonl       # subdomain-takeover templates
wafw00f -i live_web.txt -o wafw00f.txt
```

**Source/secret exposure (per live web host)**
```
trufflehog filesystem ./crawl_dumps --only-verified
gitleaks dir ./crawl_dumps -v
# Public repos for the org leak subdomains, creds, internal hostnames:
trufflehog github --org=TARGET_ORG --only-verified
```

## Methodology

1. **Confirm authorization & scope shape.** Record the exact wildcard(s), excluded names, allowed ports, rate limits, and OAST policy. Wildcard does not imply third-party SaaS endpoints are in scope.
2. **Detect wildcard DNS** with a random bogus name before any bruteforce, so you do not chase phantom hosts.
3. **Passive enumeration first** (subfinder + crt.sh + amass passive) — zero-touch coverage and a baseline name set.
4. **Active resolution & bruteforce** (dnsx + gotator permutations) with wildcard filtering; merge into one deduped `all_hosts.txt`.
5. **Liveness & fingerprint** every name with httpx (status, title, tech, TLS SAN, CNAME, favicon, JARM). Use TLS SANs and CNAMEs to discover *more* names — feed them back to step 4 (iterate until no new names).
6. **Port-sweep** with naabu, then `nmap -sV -sC` the open ports to fingerprint non-web services.
7. **Triage and rank.** Tag every host: prod / staging / dev / CI / observability / SaaS-CNAME / parked. Prioritize dev/staging/CI and unusual tech first — they hold the soft targets.
8. **Subdomain takeover sweep** across ALL names (including dead/NXDOMAIN CNAMEs) — see Key Weaknesses.
9. **Per-host deep dive** on ranked targets: crawl (katana), content-discovery (ffuf), nuclei `-as`, and pivot into the relevant app/vuln skill (SSRF, auth, injection).
10. **Find the origin** behind CDN/WAF (favicon/JARM cluster, historical DNS, SAN overlap) and re-test it directly — origins often skip the WAF's protections.
11. **Secret + source exposure** pass on crawled assets and the org's public repos.
12. **Consolidate**: dedupe findings across hosts, keep the highest-impact instance per vuln class, and document the full host inventory as scope evidence.

## Key Weaknesses / Techniques

**Subdomain takeover (the signature wildcard finding)**
- A CNAME points at a deprovisioned third-party resource you can re-register.
```
nuclei -l all_hosts.txt -tags takeover -j -o takeover.jsonl
subzy run --targets all_hosts.txt --hide_fails    # go install github.com/PentestPad/subzy@latest
```
- Verify the fingerprint manually: `dig +short CNAME sub.target.tld` then `curl -sI https://sub.target.tld`. S3 shows `NoSuchBucket`, GitHub Pages `There isn't a GitHub Pages site here`, Azure `404 Web Site not found`. Claim only the resource the org abandoned (e.g. create the same-named S3 bucket/Heroku app) and serve a benign proof file — never host hostile content.

**Forgotten dev/staging hosts**
- `dev.`/`staging.`/`uat.` often run debug mode, default creds, no WAF, verbose errors, or pre-prod data. Diff their tech/headers against prod; check `/debug`, `/actuator`, `/.env`, `/swagger-ui`, `/graphql`.

**Origin IP disclosure (CDN/WAF bypass)**
- Cluster httpx favicon-hash and JARM to spot the non-CDN origin; cross-check historical DNS and TLS SAN overlap. Then request the app directly by IP with the right Host header:
```
curl -sk https://ORIGIN_IP/ -H 'Host: app.target.tld' -I
```
- A reachable origin frequently lacks the rate-limits/WAF rules that protect the fronted name.

**Exposed source & secrets**
```
curl -s https://HOST/.git/HEAD                       # "ref: refs/heads/..." == exposed repo
git-dumper https://HOST/.git/ ./dump && trufflehog filesystem ./dump --only-verified
for f in .env .env.bak config.php.bak backup.zip .DS_Store; do curl -s -o /dev/null -w "%{http_code} $f\n" "https://HOST/$f"; done
```

**Per-host vuln classes** (pivot to the dedicated skill once a surface is identified)
- Fetchers/importers → SSRF; login/reset flows → auth bypass; search/filter params → SQLi (`sqlmap`), XSS, SSTI; APIs → IDOR/BOLA, GraphQL introspection; JWTs → `jwt_tool`.
- Default-cred and known-CVE checks on observability/CI hosts (Grafana, Jenkins, Kibana, GitLab) via nuclei `-as`.

## Validation

1. **Inventory is reproducible.** Keep the deduped host list with resolver, timestamp, and source per name so coverage is auditable.
2. **Takeover PoC:** show the dangling CNAME (`dig`), the third-party error fingerprint (`curl -I`), then claim the resource and serve a unique benign token at the exact path. Screenshot/log both the pre-claim 404 and post-claim 200 of your token.
3. **Origin bypass PoC:** demonstrate the app responding on the origin IP with the production Host header, and that a protection present on the fronted name (e.g. WAF block, rate-limit) is absent on the origin.
4. **Exposed source/secret:** download the artifact, show it parses (`git log`, valid `.env` keys), and — only if safe and authorized — confirm one credential authenticates against a non-destructive endpoint.
5. **Per-host findings:** confirm with the validation steps in the matching vuln skill (real server-side effect, not a reflected mock).
6. Use `interactsh-client` for any blind/OAST confirmation; verify the callback source IP is the *target* host, not your tester box.

## False Positives

- **Wildcard DNS mirage:** every random name "resolves" because `*.target.tld` exists — these are not real hosts. Always run the bogus-name check and use dnsx `-wd`.
- **Shared-IP virtual hosts:** an open port on a shared CDN/cloud IP is not necessarily this org's service — confirm via Host header and TLS SAN before reporting.
- **Live CNAME, healthy backend:** a CNAME to a third party is only a takeover if the backend resource is unclaimable AND shows the deprovisioned fingerprint. A working SaaS page is not a takeover.
- **Parked/marketing pages:** default vendor landing pages and "coming soon" hosts are usually no-impact.
- **`403`/`401` from a directory bruteforce** often means "exists but protected," not access — verify before claiming exposure.
- **Out-of-scope SaaS:** `target.zendesk.com`-style names live on a third-party domain, not `*.target.tld` — confirm against the authorized scope.
- **Stale historical names** from CT logs/passive sources that no longer resolve — drop anything dnsx cannot resolve unless takeover-relevant (NXDOMAIN CNAME).

## Chaining & Impact

- Subdomain takeover → host malicious content on a trusted name → steal sessions/credentials via same-site cookies, bypass CSP/CORS allowlists, or phish under the brand.
- Forgotten staging with debug/default creds → admin access → pivot into shared databases or internal networks reused across environments.
- Exposed `.git`/`.env` → source + secrets → cloud keys / DB creds → data access or further lateral movement.
- Origin IP discovery → WAF bypass → previously-blocked SQLi/RCE now reachable on the unprotected backend.
- Internal/VPN/CI host exposure → credential capture → into the corporate network.
- The compounding effect: enumerating ALL names turns one weak host into a foothold for the entire estate — breadth is what makes wildcard scope dangerous.

## Pro Tips

1. Enumeration is iterative, not one-shot: TLS SANs, CNAME chains, and crawled JS constantly reveal new names — loop dnsx/httpx until the set stops growing.
2. Run the bogus-name wildcard check before bruteforce; skipping it wastes hours on phantom hosts and pollutes the inventory.
3. Favicon hash + JARM cluster hosts by real backend — fast way to group an estate and spot the origin hiding behind a CDN.
4. The valuable host is rarely the flagship: chase `dev`/`staging`/`uat`/`old`/`legacy`/`test` and odd tech stacks first.
5. CT logs (crt.sh) surface internal names that never appear in passive feeds — including ones that resolve only on internal DNS, useful as leads.
6. Always also test the apex and `www`; teams harden the obvious name and forget the rest.
7. Keep rate limits explicit (naabu `-rate`, nuclei `-rl/-c/-bs`) — a wildcard sweep across thousands of names can self-DoS or get you blocked.
8. Re-scan periodically: wildcard estates change as teams spin up and tear down infra; a clean scan last month may have a fresh takeover today.
9. Dead CNAMEs (NXDOMAIN) are not noise — they are prime takeover candidates; keep them in the inventory, not the trash.
