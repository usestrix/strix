---
name: technology_fingerprinting
description: Technology and WAF fingerprinting covering headers, cookies, error pages, favicon hashes, CDN detection, and version-to-CVE mapping
---

# Technology Fingerprinting

Fingerprinting identifies the stack - language, framework, web server, CDN, WAF, CMS, and versions - so testing can skip to the right skills and CVE databases instead of guessing. It is the first active step on any target and should happen alongside asset discovery. Every fingerprint is a hypothesis: corroborate across multiple signals before selecting exploit paths.

## Attack Surface (Signals)

**Headers**

- `Server`, `X-Powered-By`, `X-Generator`, `X-AspNet-Version`, `X-Runtime` (Rails), `X-Drupal-Cache`, `X-Varnish`, `Via`, `X-Served-By`
- CDN/WAF markers: `CF-Ray`/`CF-Cache-Status` (Cloudflare), `X-Akamai-*`, `X-Cache` (Fastly), `X-Amz-Cf-Id` (CloudFront), `X-Sucuri-ID`, `X-CDN`, `X-WAF`
- Security headers present/absent: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`

**Cookies**

- Session markers: `PHPSESSID` (PHP), `JSESSIONID` (Java), `connect.sid` (Express), `laravel_session`/`XSRF-TOKEN` (Laravel), `_rails`/`_session` (Rails), `ASP.NET_SessionId` (ASP.NET), `csrftoken` (Django), `wp-settings-*` (WordPress), `NID`/`SID` (Google)

**Body/page markers**

- `wp-content`, `wp-includes` (WordPress); Drupal `sites/`; Joomla `/media/system`; Django admin CSS; Rails `assets/`; Next.js `/_next/`; Nuxt `/_nuxt/`; Vite `/assets/`; webpack `__webpack_require__`; Spring whitelabel; ASP.NET error pages; Vue/React root divs + script bundles
- Framework meta tags, generator comments, version strings in HTML comments, source maps (`/*.js.map`), `powered-by` footers

**Behavior**

- Error pages: 404/500 styling and paths (Rails, Django, Flask, Spring whitelabel, ASP.NET yellow screen)
- Redirect patterns and cookie attributes; HTTP method behavior; `OPTIONS`/`Allow` headers
- Static path conventions (`/static/`, `/assets/`, `/media/`, `/uploads/`)

**TLS/cert**

- Issuer, SANs, certificate age (CDN vs origin), TLS version/cipher support (see `asset_discovery` for SAN pivots)

**Favicon**

- Hash the favicon and pivot: `httpx -favicon` produces a hash that identifies the app/CMS across hosts (also a Shodan/Censys query key)

## Reconnaissance

1. **Quick sweep** with httpx tech detection (pre-installed):
   ```
   httpx -l hosts.txt -sc -title -server -td -cname -ip -json -o finger.jsonl
   ```
   `-td` runs technology detection (headers, cookies, body markers)
2. **WAF detection** (pre-installed):
   ```
   wafw00f https://target -o waf.json
   ```
   Corroborate with headers (`CF-Ray`, `X-Sucuri-ID`, `X-CDN: Incapsula`)
3. **Targeted probes** per suspected stack: `/actuator` (Spring), `/wp-json` (WordPress), `/graphql`, `/api`, `/.well-known/openid-configuration` (OIDC), `/version`, `/server-status`
4. **Version pinning**: changelog/readme files, `package.json`/`composer.json`/`Gemfile` when exposed, error-page versions, update endpoints (`/wp-json`, `/admin/version`), asset digests (Rails/Webpack)
5. **Source-aware**: read lockfiles, `package.json`, `requirements.txt`, Dockerfile, CI configs, and framework config for exact versions

## Key Techniques

### Header Triangulation

Read the full header chain: `Server` may be masked by a CDN, but `Via`/`X-Served-By`/`CF-Ray` reveal the edge, and the origin's `Server`/`X-Powered-By` show through on errors or direct-IP requests. Compare responses with/without the CDN (direct origin IP via DNS history/cert search) to fingerprint the real stack.

### Error-Page Fingerprinting

- Trigger 404/500/405 deliberately; each framework has a signature page
- Rails: plain "Routing Error"/exception pages with `Rails.root`; Django: debug page with settings when `DEBUG=True`; Spring: whitelabel; Flask: `Werkzeug` debugger; ASP.NET: yellow screen + stack frames
- Look for version strings in page footers or `<meta name="generator">`

### Favicon Hashing

```
httpx -u https://target -favicon
```

The favicon hash identifies CMS/framework instances (e.g., WordPress, Grafana, Jenkins, Jira) and supports Shodan/Censys pivots to find sibling instances.

### Cookie/Behavior Fingerprinting

Login-page cookies and redirect flows are reliable even when headers are stripped: Django sets `csrftoken` on GET; Laravel sets `XSRF-TOKEN`; ASP.NET sets `ASP.NET_SessionId`; Rails sets `_session`; Java apps set `JSESSIONID` with path attributes. Test `/login`/`/admin`/`/api` responses for cookie sets.

### Version-to-CVE Mapping

Once versions are pinned:

- Check `nuclei` tech/CVE templates: `nuclei -u https://target -tags tech,cve -s high,critical -ni -silent`
- Search the CVE databases (web_search) for `<framework> <version> CVE`
- Use `searchsploit`/`vulnx` (pre-installed) for offline matches
- Only exploit after confirming the exact version and a working path

## Testing Methodology

1. httpx tech sweep across all hosts
2. wafw00f + header analysis (edge vs origin)
3. Targeted framework probes (actuator, wp-json, graphql, well-known)
4. Version pinning from files/pages/errors
5. CVE mapping and handoff to the matching skill
6. Record evidence: header sets, cookie sets, page markers, error shapes

## Validation

1. Confirm each fingerprint with at least two independent signals (header + cookie + page marker)
2. Pin versions from the most reliable source (lockfile/readme/update endpoint) when CVEs depend on it
3. Verify the origin stack by direct-IP or error-page responses when the edge masks headers
4. Route each confirmed stack to its skill: `django`/`fastapi`/`express`/`spring`/`wordpress`/`keycloak`/`grafana_prometheus`, etc.

## False Positives

- CDN headers (Cloudflare/Akamai) mistaken for the app stack - the edge is not the origin
- Generic `Server: nginx` masking the real app (fingerprint via cookies/pages)
- JS framework in the browser (React/Vue) confused with the server stack (Next.js/Nuxt SSR vs static SPA)
- Fake/honeypot headers (`X-Powered-By` deliberately set to mislead)
- Version strings from `readme.html`/changelogs that lag the deployed patch level
- WAF false positives/negatives (wafw00f is heuristic; verify with blocking behavior)

## Impact

- Correct skill/CVE selection: faster, higher-signal testing
- Version-pinned CVE exploitation when unpatched
- Origin discovery past CDNs for direct testing
- WAF awareness for payload crafting and rate limiting

## Pro Tips

1. Triangulate: headers + cookies + page markers + error shapes together beat any single signal
2. Direct-IP requests (with the right `Host`) often expose the origin stack the CDN masks
3. `httpx -td` and `wafw00f` are pre-installed - run them on every host list before deep testing
4. Pin versions before CVE hunting; "framework X" is not enough, "framework X 2.1.3" is
5. Keep a fingerprint table per host: edge, origin, framework, language, version, WAF, CMS
6. Route fingerprints to the dedicated skills (`django`, `spring`, `wordpress`, etc.) for payload depth

## Summary

Fingerprinting is signal triangulation: headers, cookies, page markers, error shapes, favicon hashes, and version files - confirmed across independent signals, edge vs origin separated, and pinned to versions before CVE mapping. Run it on every host list first, and let it route testing to the right specialist skills.
