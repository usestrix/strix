---
name: wordpress
description: WordPress security testing covering wpscan workflows, user enumeration, xmlrpc abuse, plugin/theme CVEs, REST API gaps, and upload bypasses
---

# WordPress

WordPress powers a huge share of the web, and its attack surface is mostly third-party: plugins and themes with a long history of CVEs, plus a few core surfaces that never change (`xmlrpc.php`, the REST API, `wp-login.php`). A WordPress finding is usually "plugin X version Y is vulnerable to CVE-Z" - so fingerprinting versions and enumerating installed plugins is the core of the job. The `wpscan` CLI automates most of it.

## Attack Surface

- Core: `/wp-login.php`, `/wp-admin/`, `/wp-json/`, `/xmlrpc.php`, `/wp-content/`, `/wp-includes/`, `/readme.html`, `/license.txt`, `/wp-cron.php`
- Users: `/?author=1` redirects, `/wp-json/wp/v2/users`, author archives, REST user endpoints
- Plugins/themes: version disclosure via `readme.txt`, `style.css`, changelogs; CVE matching against the plugin/theme version
- Uploads: `/wp-content/uploads/` (directories, timestamps, path guessing), media library, plugin upload flaws
- REST API: `/wp-json/wp/v2/*` - users, posts, settings, media, and custom plugin endpoints often missing authz checks
- `xmlrpc.php`: `system.listMethods`, `wp.getUsersBlogs` (credential brute force), `pingback.ping` (SSRF/port scan/amplification)
- Multi-site, sitemaps, `wp-config.php` backups, `.git`/`.svn` leftovers, `phpinfo()` files, database dumps

## Reconnaissance

1. **Install/update wpscan** in the sandbox: `gem install wpscan` (or Kali `apt install wpscan`) - note it needs an API token for the best CVE database, but runs without one
2. **Baseline fingerprint**:
   ```
   wpscan --url https://target --disable-tls-checks --enumerate u,vp,vt,dbe --api-token <token> -o wpscan.json --format json
   ```
   Components: `u` users, `vp` vulnerable plugins, `vt` vulnerable themes, `dbe` db exports/backups
3. **Manual core checks**:
   ```
   curl -s https://target/readme.html | head -5          # version
   curl -s https://target/wp-json/ | jq '.name,.description'
   curl -s https://target/wp-json/wp/v2/users | jq '.[].slug'
   curl -sI https://target/?author=1 | grep -i location   # author enumeration
   ```
4. **Plugin/theme fingerprint without wpscan**: request `/wp-content/plugins/<slug>/readme.txt`, `/wp-content/themes/<slug>/style.css`, and changelog files; grep for `Stable tag:`/`Version:`
5. **Check xmlrpc**: `curl -s https://target/xmlrpc.php -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'`

## Key Vulnerabilities

### User Enumeration

- `/?author=1` (302 Location reveals `/author/<slug>/`)
- `/wp-json/wp/v2/users` returns usernames when the REST endpoint is open
- Login error differential (`Invalid username` vs `The password you entered for the username`)
- `xmlrpc.php` `wp.getUsersBlogs` with a single password tries all usernames (amplified brute force)

### XMLRPC Abuse

- **Brute force amplification**: `system.multicall` batches hundreds of `wp.getUsersBlogs` password guesses in one HTTP request
- **Pingback SSRF/port scan**: `pingback.ping` makes the server fetch attacker-chosen URLs - OAST confirmation of SSRF and internal port probing (see `ssrf`)
- **DoS**: unauthenticated `pingback.ping` to a victim URL amplifies requests (classic DDoS vector)

### Plugin/Theme CVEs

This is where most criticals live: arbitrary file upload, SQLi, LFI, RCE, auth bypass, stored XSS, and plugin-specific chains. Workflow:

1. Identify exact plugin/theme + version (readme/style/changelog)
2. Match against wpscan's database, `searchsploit`, or web search (`<plugin> <version> exploit`)
3. Verify the vulnerable endpoint/path manually before reporting

Keep an inventory table: plugin/theme, version, CVE, affected endpoint, verified Y/N.

### REST API Authorization Gaps

Custom plugin REST routes frequently skip `permissions_callback`:

```
GET /wp-json/<custom-namespace>/v1/...
```

Probe every namespace in `/wp-json/` with and without auth; check for IDOR on object IDs, missing capability checks, and privilege escalation via `wp/v2/users` writes when allowed.

### Upload Bypasses

- Extension whitelist gaps: `.php5`, `.phtml`, `.pht`, double extensions, case tricks
- MIME spoofing with a valid image header + PHP payload
- Plugin/theme upload via admin that skips signature verification
- Path traversal in upload filename -> arbitrary file write (plugin-dependent)
- Guessable upload paths (`/wp-content/uploads/YYYY/MM/<file>`) for stored payloads

### wp-config / Backup Exposure

- `wp-config.php.bak`, `.old`, `.swp`, `~`, `#` files
- Database dumps (`backup.sql`, `dump.sql`) and plugin backup archives in web root
- `.git`/`.svn` metadata when the site is deployed from a repo (see `content_discovery`)

### Weak Credentials

- Default/weak admin passwords; `xmlrpc.php` multicall makes brute force fast and noisy - prefer targeted wordlists (see `weak_password_detection`)
- Exposed `wp-login.php` without rate limiting or 2FA

## Advanced Techniques

- **REST + XSS chain**: stored XSS in a post/comment via REST write with weak capability checks -> admin session theft
- **SSRF via pingback**: use `pingback.ping` with OAST to prove server-side fetch, then pivot to internal metadata (see `ssrf`)
- **Plugin chain**: combine an LFI/arbitrary-file-read plugin with a log/upload write to reach RCE
- **MU-plugins / drop-ins**: check `wp-content/mu-plugins/`, `db.php`, `object-cache.php` for persistence or custom code with vulns
- **Cron abuse**: `/wp-cron.php` endpoints and plugin scheduled jobs with unserialized args

## Testing Methodology

1. Fingerprint core version + theme/plugin inventory (wpscan + manual readme/style checks)
2. Enumerate users via author ID, REST, and login differentials
3. Probe xmlrpc methods; test multicall brute force and pingback SSRF (OAST)
4. Map REST namespaces and test authz per endpoint
5. Version-match plugins/themes to CVEs and verify the vulnerable path
6. Test uploads and backup/config exposure
7. Validate and report with an inventory table

## Validation

1. User enum: show the enumeration vector with concrete output (author redirect, REST JSON, login error)
2. Plugin CVE: reproduce the vulnerable endpoint behavior (e.g., LFI reads `/etc/passwd`, SQLi returns data) - version alone is not proof
3. XMLRPC: show `system.multicall` batching or a pingback OAST hit from the server IP
4. Upload: demonstrate a non-executable proof (e.g., `.txt` marker written via a real bypass) or read-back of a payload file
5. REST authz: two-account/baseline diff on the unauthorized operation

## False Positives

- wpscan "vulnerable" plugins where the exploit path is patched or the version string is stale (verify manually)
- `/wp-json/wp/v2/users` returning only display names with no login slugs (limited enum value)
- xmlrpc enabled but pingback disabled (methods list shows `pingback.ping` absent)
- Upload "bypass" that stores the file inertly (no execution/read-back)
- `readme.html` version vs actual patched core (plugins/themes often lag)

## Impact

- Site takeover via plugin RCE, admin credential theft, or upload-to-webshell
- Data breach via SQLi/db dumps
- SSRF pivot into the hosting network via pingback
- Defacement/malware injection (the most common WordPress incident outcome)

## Pro Tips

1. Build the plugin/theme inventory before anything else - version-matched CVEs are the highest-yield path
2. `readme.txt` `Stable tag:` and theme `style.css` `Version:` are the fastest manual fingerprints
3. Test `xmlrpc.php` early: multicall brute force and pingback SSRF are both one request away
4. Enumerate REST namespaces - custom plugin endpoints are where authz checks go missing
5. Pair with `weak_password_detection`, `ssrf`, `insecure_file_uploads`, and `content_discovery` skills

## Summary

WordPress testing is inventory-driven: enumerate users, plugins, themes, and REST namespaces; version-match plugins to CVEs and verify; then abuse xmlrpc, uploads, and backups. wpscan automates the sweep; manual verification makes the findings real.
