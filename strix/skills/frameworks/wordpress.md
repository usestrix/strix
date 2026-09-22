---
name: wordpress
description: WordPress security testing covering plugin/theme CVE enumeration, wp-json REST API abuse, XML-RPC brute-force/SSRF, and core misconfiguration
---

# WordPress

WordPress powers roughly a third of the web, and in bug-bounty scope the vast majority of its attack surface is third-party plugins and themes, not WordPress core. Core is well-audited; a random 50k-install plugin usually isn't. Fingerprint everything installed, then chase disclosed CVEs before looking for anything novel.

## Attack Surface

**Core**
- `wp-login.php`, `wp-admin/`, XML-RPC (`xmlrpc.php`), REST API (`/wp-json/`)
- `wp-config.php` (DB creds, auth keys/salts — never reachable directly, but backup files/editors sometimes expose it)
- Cron (`wp-cron.php`, unauthenticated and can be abused for DoS via repeated triggering)

**Plugins/themes (the real surface)**
- `/wp-content/plugins/<slug>/`, `/wp-content/themes/<slug>/` — version disclosure via `readme.txt`, `style.css` headers, or asset query-string versions (`?ver=1.2.3`)
- AJAX handlers (`wp-admin/admin-ajax.php?action=<plugin_action>`) — both `wp_ajax_*` (authenticated) and `wp_ajax_nopriv_*` (unauthenticated) hooks, the single most common plugin vuln surface
- REST routes registered by plugins under `/wp-json/<namespace>/v1/...` — frequently missing `permission_callback` (defaults to public if omitted)
- File upload handlers (form builders, page builders, membership plugins)

## Reconnaissance

**Fingerprint installed plugins/themes**
```
GET /wp-json/                        # lists registered REST namespaces -> plugin identification
GET /wp-content/plugins/<slug>/readme.txt   # "Stable tag:" = installed version
GET /wp-content/themes/<slug>/style.css     # theme name + version in header comment
```
Also check enqueued asset URLs in page source (`?ver=X.Y.Z` query strings reveal plugin/theme versions even when `readme.txt` is blocked) and passively brute-force common plugin slugs against `/wp-content/plugins/<slug>/readme.txt` from a wordlist (SecLists `wordpress-plugins.fuzz.txt`).

**User enumeration**
```
GET /wp-json/wp/v2/users              # often unauthenticated, dumps usernames/display names/IDs
GET /?author=1                        # redirects to /author/<username>/ on valid IDs — enumerate sequentially
GET /wp-login.php  (POST bad password against a guessed username -> "invalid username" vs "incorrect password" response difference)
```

**XML-RPC probing**
```
POST /xmlrpc.php
<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>
```
If enabled: `wp.getUsersBlogs` supports **credential brute-forcing behind a single request** (batch multiple username/password pairs via `system.multicall` — bypasses simple rate-limiting that only counts requests, not attempts), and `pingback.ping` is a classic **SSRF primitive** (`GET`-equivalent to internal hosts, with response-time/error-message oracle).

## Key Vulnerabilities

### Plugin/theme CVE chains (highest-yield path)
Fingerprint every installed plugin+version, then check each against the WPScan vulnerability database and WordPress.org's own changelog for silently-patched security fixes (many plugin authors don't file CVEs). Vulnerable plugin classes seen repeatedly: SQLi in custom AJAX handlers reading `$_REQUEST` directly, arbitrary file upload in form/media plugins missing extension/mime validation, and unauthenticated privilege-escalation via REST routes that accept a `role` or `user_id` parameter without checking `current_user_can()`.

### Unauthenticated AJAX/REST endpoints
```
POST /wp-admin/admin-ajax.php
action=<plugin_action>&<params>
```
Any `add_action('wp_ajax_nopriv_<action>', ...)` hook is reachable pre-auth by design — the vulnerability is in what the handler trusts. Test every discovered `nopriv` action for IDOR (object IDs), SQLi (unsanitized `$wpdb->query()` with request data), and file operations (path traversal in file-serving/export actions).

### REST API missing permission_callback
`register_rest_route()` calls that omit `permission_callback` (or set it to `__return_true`) expose the route publicly even if the developer intended authenticated-only access — this is one of the most common plugin-CVE root causes post-2021 (WordPress started warning about it in logs but doesn't enforce it). Enumerate `/wp-json/` namespaces and probe write/update routes (`PUT`/`POST`/`DELETE`) without auth headers first.

### File upload / arbitrary file write
Media, import/export, and page-builder plugins frequently accept uploads with blocklist (not allowlist) extension filtering — test double extensions (`shell.php.jpg`), null-byte-adjacent tricks on older PHP, `.phtml`/`.php5`/`.phar` variants, and `.htaccess` upload if the upload directory allows it (rewrite `.jpg` requests to execute as PHP).

### Backup/debug artifact exposure
```
GET /wp-config.php.bak
GET /wp-config.php~
GET /.wp-config.php.swp
GET /wp-content/debug.log        # if WP_DEBUG_LOG is on, often world-readable and leaks paths/queries/errors
```

## Testing Methodology

1. **Fingerprint sweep** — core version (`/wp-json/`, generator meta tag if not stripped), every plugin/theme slug + version via `readme.txt`/`style.css`/asset query strings.
2. **CVE match** — cross-reference each fingerprinted plugin+version against WPScan's vulnerability database; prioritize unauthenticated/high-severity matches.
3. **User enumeration** — `/wp-json/wp/v2/users`, `?author=N`, login-form response differences.
4. **AJAX/REST surface mapping** — grep exposed JS for `wp_ajax` action names and `/wp-json/` namespace calls, then probe each unauthenticated.
5. **XML-RPC** — check if enabled at all first (`system.listMethods`); if yes, test `system.multicall` brute-force amplification and `pingback.ping` SSRF.
6. **Backup/debug artifact sweep** — the `.bak`/`~`/`.swp` list above plus `debug.log`.

## Validation

1. CVE-based findings: confirmed version match against the CVE's affected range, plus a working PoC request/response — not just version disclosure.
2. AJAX/REST IDOR: side-by-side requests as two different users/sessions showing cross-account data access.
3. File upload RCE: uploaded file served back and executed (command output or callback), not just "upload succeeded."
4. XML-RPC SSRF: `pingback.ping` response-time or error-message differential against an internal vs external target URL, or OAST callback if outbound is reachable.

## False Positives

- Plugin/theme version fingerprint matches a CVE range, but the specific vulnerable code path was removed in a point release not reflected in the `Stable tag:` (rare, but check the actual diff/changelog when in doubt).
- `wp_ajax_nopriv_*` action exists but performs no privileged/sensitive operation — not every nopriv hook is a finding by itself.
- XML-RPC enabled but `system.multicall` and `pingback.ping` both explicitly disabled via a security plugin (common with Wordfence/iThemes Security installed).

## Impact

- Full site compromise via plugin RCE (file upload, unauth AJAX SQLi-to-RCE chains, deserialization in poorly-audited plugins).
- Privilege escalation to Administrator via REST routes missing `permission_callback`.
- Credential brute-force amplification via XML-RPC `system.multicall` bypassing naive rate limits.
- Internal network SSRF via `pingback.ping`.

## Pro Tips

1. The plugin/theme, not core, is almost always where the bug is — spend recon time on accurate version fingerprinting, not core exploitation.
2. `?ver=` query strings on enqueued JS/CSS assets are a fingerprinting channel that survives `readme.txt` being blocked or stripped.
3. `system.multicall` over XML-RPC turns a rate-limited login form into a single-request batch brute-force — always check if XML-RPC is enabled before accepting "rate limiting is fine" on the login form alone.
4. A REST route missing `permission_callback` is often silent in the UI (the plugin "works fine") because the developer only tested the authenticated path — probe every discovered route without credentials regardless of what the plugin's own docs claim about auth requirements.

## Summary

WordPress testing is fingerprint-then-chase-CVE: identify every plugin/theme and exact version, match against known vulnerabilities, and prioritize unauthenticated AJAX/REST endpoints and file-upload paths — that's where the overwhelming majority of real-world WordPress bounty findings live, not in WordPress core itself.
