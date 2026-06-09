---
name: subdomain
description: End-to-end assessment of a single subdomain host (kind url) — DNS posture, exposed services, web app surface, and escalation paths.
---

# Subdomain

A subdomain is one labeled host under a parent zone (`app.example.com`) that resolves to one or more services. Treat it as a self-contained attack surface: its DNS record graph, the ports/services behind the resolved IP(s), the web stack it serves, and the trust it inherits from the parent domain (shared cookies, CSP allowlists, OAuth redirect URIs, SSO). The objective is to assess this specific host and its services — fingerprint everything it exposes, find the weakest reachable service, and validate concrete impact on it, including paths that pivot back to the parent or sibling hosts.

## Attack Surface

- **DNS record graph** — A/AAAA, CNAME chains, NS delegations, MX, TXT/SPF/DMARC, CAA, and historical/passive records that hint at retired services.
- **Network services** — every open TCP/UDP port on the resolved IP(s): web (80/443/8080/8443), admin/dev panels, DBs, caches, message brokers, SSH, RDP, mail.
- **Virtual hosts** — the IP may serve many vhosts; the subdomain may route to a default/origin vhost or a forgotten one via Host-header confusion.
- **Web application** — routes, APIs, auth flows, file uploads, parameters, JS bundles, source maps, exposed `.git`/`.env`/backups.
- **Inherited trust** — wildcard or parent-scoped cookies (`Domain=.example.com`), CSP/`script-src` allowlists, CORS `*.example.com` rules, OAuth/SSO callback allowlists.
- **TLS/cert metadata** — SAN entries leak sibling hosts; cert mismatch/expiry reveals dangling or default origins.
- **CDN/WAF edge** — origin-IP exposure that bypasses the edge entirely.

## Recon & Enumeration

Most tools below ship in the Kali sandbox. Install the few that may be missing where noted.

```bash
H=app.example.com

# 1) DNS posture — resolve all record types, follow CNAME chains
dnsx -d $H -a -aaaa -cname -ns -mx -txt -caa -resp -silent
dnsrecon -d $H -t std            # apt-get install -y dnsrecon if missing
dig +nocmd $H any +multiline +noall +answer
dig +short $H | tee /tmp/ips.txt  # collect resolved IPs

# 2) Passive history & sibling discovery (SAN often reveals neighbors)
subfinder -d $(echo $H | cut -d. -f2-) -all -silent | grep -i "\.$(echo $H|cut -d. -f2-)$"
echo $H | tlsx -san -cn -silent  # cert SANs = more hosts to assess
curl -s "https://crt.sh/?q=%25.$(echo $H|cut -d. -f2-)&output=json" | jq -r '.[].name_value' | sort -u

# 3) Port/service scan of the resolved IP(s)
naabu -host $H -top-ports 1000 -rate 1000 -silent -o /tmp/ports.txt
nmap -sV -sC -Pn -p $(cut -d: -f2 /tmp/ports.txt | paste -sd, -) $(head -1 /tmp/ips.txt) -oN /tmp/nmap.txt

# 4) HTTP fingerprint — status, tech, title, TLS, CDN/WAF, redirects
echo $H | httpx -title -tech-detect -status-code -tls-grab -cdn -location \
  -server -ip -follow-redirects -json -o /tmp/httpx.json
wafw00f https://$H

# 5) Content & API discovery
katana -u https://$H -jc -kf all -d 3 -silent -o /tmp/urls.txt
ffuf -u https://$H/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raydirectory.txt \
  -mc 200,204,301,302,401,403 -ac -of csv -o /tmp/ffuf.csv
ffuf -u https://$H/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc all -ac

# 6) Vuln scan — automatic tech-mapped, scoped
nuclei -u https://$H -as -s critical,high,medium -rl 50 -c 20 -timeout 10 -retries 1 -j -o /tmp/nuclei.jsonl
nuclei -u https://$H -tags takeover,exposure,misconfig,default-login -silent

# 7) Secret/source exposure
trufflehog filesystem /tmp/site_dump --only-verified   # after downloading JS/source
nuclei -u https://$H -tags exposure,config,backup -silent  # .git/.env/backups
```

Asset-specific installs if needed: `dnsx`/`subfinder`/`tlsx`/`httpx`/`katana`/`naabu` via `go install github.com/projectdiscovery/<tool>/...@latest`; `dnsrecon` via `apt-get install -y dnsrecon`; `gowitness` for screenshots via `go install github.com/sensepost/gowitness@latest`.

## Methodology

1. **Resolve and map DNS** — capture A/AAAA, CNAME chain, NS, MX, TXT; note third-party CNAME targets and the final IP(s). NXDOMAIN vs SERVFAIL vs branded 4xx distinguishes dead from delegated.
2. **Check for dangling records** — a CNAME/A pointing at an unclaimed provider resource (S3, CloudFront, Pages, Azure App, Heroku, etc.) is a takeover candidate; cross-reference the dedicated `subdomain-takeover` methodology.
3. **Port and service scan** the resolved IP — enumerate every open port, version, and default script output. Forgotten services (old admin panels, exposed DBs, monitoring) live on non-web ports.
4. **Fingerprint the web stack** — server, framework, CMS, JS libraries, headers, TLS config, and whether a CDN/WAF fronts it.
5. **Find the origin** — if behind a CDN, test SAN IPs, historical DNS, and `Host: $H` against candidate IPs to reach the unprotected origin.
6. **Map content and APIs** — crawl with katana, brute directories/endpoints with ffuf, harvest URLs/params from JS bundles and source maps.
7. **Probe vhost routing** — try `Host`-header overrides and absolute-URI requests to reach default/internal vhosts on the same IP.
8. **Run targeted vuln checks** — nuclei automatic scan plus exposure/takeover/default-login tags; then manual testing of the highest-value endpoints found.
9. **Assess inherited trust** — cookie `Domain` scope, CSP/CORS allowlists, OAuth redirect acceptance; determine whether compromising this host pivots to the parent.
10. **Validate and chain** — turn the best finding into a reproducible PoC and map its blast radius.

## Key Weaknesses / Techniques

- **Dangling DNS / subdomain takeover** — CNAME to an unclaimed resource. Confirm the provider "missing resource" fingerprint, then (with authorization) claim and serve unique proof. See `subdomain-takeover`.
  - `echo $H | httpx -status-code -body -silent | grep -iE "no such app|NoSuchBucket|There isn't a GitHub Pages site"`
- **Exposed non-web services** — DB/cache/broker bound to public IP.
  - `nmap -Pn -sV -p6379,9200,27017,3306,5432,11211,5601,9000 $(head -1 /tmp/ips.txt) --script="*-info,*-empty-password"`
- **Origin-IP exposure (CDN bypass)** — reach the backend directly, defeating WAF/rate limits.
  - `curl -sk --resolve $H:443:<origin_ip> https://$H/ -H "Host: $H" -o /dev/null -w "%{http_code}\n"`
- **Default/forgotten vhost via Host header** — same IP, different routing.
  - `curl -sk https://$H/ -H "Host: internal-admin.example.com"` and `curl -sk https://$H/ -H "Host: localhost"`
- **Source/secret exposure** — `.git`, `.env`, `.DS_Store`, backups, source maps, exposed CI/CD configs.
  - `curl -s https://$H/.git/config` ; `curl -s https://$H/.env` ; harvest `*.js.map` then `trufflehog filesystem ./dump --only-verified`
- **Default credentials / exposed admin panels** — Grafana, Jenkins, Kibana, phpMyAdmin, Actuator.
  - `nuclei -u https://$H -tags default-login,panel,exposure -silent`
  - `curl -s https://$H/actuator/env` ; `curl -s https://$H/actuator/heapdump -o heap.bin`
- **Web app classes** — injection, IDOR, SSRF, auth bypass on discovered endpoints.
  - `sqlmap -u "https://$H/item?id=1" --batch --risk 2 --level 3 --random-agent`
  - `jwt_tool <token> -M at -t https://$H/api/me` for JWT flaws on authenticated routes
- **TLS misconfig** — expired/mismatched certs, weak ciphers, SAN leaking internal hosts.
  - `echo $H | tlsx -expired -self-signed -mismatched -cipher -silent`
- **Inherited-trust abuse** — parent-scoped cookies readable from a takeover, CSP allowlisting this host so injected JS runs in the parent's context, OAuth callback accepting this host.

## Validation

1. **DNS/service finding** — record the pre-state (resolve output, port banner, HTTP status/body/headers) and a reproducible command that triggers it; for takeover, serve a unique token page over HTTPS and show it rendering at `$H`.
2. **Exposed service** — read one harmless, clearly non-public artifact (e.g., empty-auth Redis `INFO`, ES `_cat/indices`, Actuator `/env`) and capture the raw response; do not modify data.
3. **Web vuln** — produce a minimal PoC: the exact request, the differential proving exploitation (reflected marker, extracted row, 200 on an unauthorized object), and steps to reproduce.
4. **Origin bypass** — show identical app response via `--resolve` to the origin IP while the edge blocks/rate-limits, proving the WAF is out of path.
5. **Trust pivot** — demonstrate the cookie/CSP/OAuth acceptance with a request/response pair, not just configuration inference.

## False Positives

- **Branded "missing resource" pages that are not claimable** — provider now enforces TXT/ownership; not a takeover.
- **Wildcard DNS / catch-all vhost** — every label resolves and returns the same app; "discovered" hosts are not distinct assets.
- **CDN/WAF interstitials** — 403/406/429 from the edge are not app vulnerabilities; confirm against the origin.
- **Shared-IP banners from nmap** — services seen on the IP may belong to a neighboring tenant/vhost, not this host; verify the service answers for `$H` specifically.
- **Reflected OAST/SSRF hits sourced from your own box** — confirm the callback IP is the server, not the scanner.
- **Expired-cert / weak-cipher findings on a redirect-only `80`→`443`** — low impact; verify the weak endpoint actually serves data.
- **Nuclei `info`/`low` informational matches** — fingerprints, not findings.

## Chaining & Impact

- **Takeover → parent compromise** — serve content on a trusted subdomain → read `Domain=.example.com` cookies, satisfy CSP `script-src *.example.com` to inject into the parent, or pass an OAuth redirect allowlist → account takeover.
- **Exposed service → data/RCE** — public Redis/Elasticsearch/Mongo → data theft or, via Redis module/cron or FCGI, code execution → shell on the host.
- **Origin bypass → unfiltered exploitation** — reach the backend directly to run injection/auth attacks the WAF would have blocked.
- **Secret exposure → cloud pivot** — `.env`/source-map/`.git` leaks an API key or cloud credential → control-plane access (buckets, secrets), then lateral movement.
- **Forgotten vhost → internal app** — Host-header routing to a staging/admin app with weaker auth → privileged functionality.
- **Default-login panel → CI/CD** — Jenkins/Grafana/Actuator → pipeline access, deploy keys, and the rest of the estate.

## Pro Tips

1. Always assess the resolved IP, not just the URL — the most serious findings on a subdomain are frequently non-web services nobody remembered binding publicly.
2. Cert SANs and CT logs are free recon: one host's certificate often enumerates the whole sibling set worth assessing next.
3. Distinguish edge from origin early; testing the CDN tells you about the CDN, not the app. `--resolve` to candidate origin IPs to confirm.
4. A subdomain's real value is inherited trust — check cookie `Domain`, CSP, CORS, and OAuth allowlists before deciding a finding is "just" on a side host.
5. Old/passive DNS and historical IPs reveal retired services that are still listening; query passive sources, not only the live record.
6. Wildcard zones inflate enumeration — verify a host is distinct (unique content/cert/headers) before spending time on it.
7. Keep nuclei scoped with `-as` plus targeted tags (`takeover,exposure,default-login,misconfig`); broad unscoped runs bury the real signal.
8. When a CNAME points at a third party, check the dedicated takeover methodology before assuming it is benign — verification gaps and race windows are common.
