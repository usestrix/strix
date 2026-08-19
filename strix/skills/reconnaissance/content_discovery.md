---
name: content_discovery
description: Hidden endpoint and content discovery covering directory brute force, backup/config files, .git/.env exposure, JS mining, parameter discovery, and 403 bypasses
---

# Content Discovery

Content discovery finds what the crawl misses: admin panels, backup files, `.env`/`.git` leftovers, API docs, debug endpoints, and parameters the app never links to. It is the difference between testing the visible app and testing the real attack surface. Structure the work as a pipeline - passive first, then directory brute force, then parameter discovery, then access-control bypass - and keep results deduplicated and verified.

## Attack Surface

- Hidden routes: `/admin`, `/api`, `/internal`, `/debug`, `/dev`, `/v1/`, `/swagger`
- Backup/config files: `.env`, `.env.backup`, `config.php.bak`, `database.yml.old`, `wp-config.php~`, `*.swp`, `*.save`, `*.zip`, `*.tar.gz`, `dump.sql`
- VCS metadata: `/.git/HEAD`, `/.git/config`, `/.svn/entries`, `.hg`, `.bzr`
- Server metadata: `robots.txt`, `sitemap.xml`, `security.txt`, `server-status`, `server-info`, `phpinfo.php`, `crossdomain.xml`, `clientaccesspolicy.xml`
- API docs: `openapi.json`, `swagger.json`, `swagger-ui.html`, `api-docs`, `/redoc`, `/docs`
- JS bundles and source maps: endpoints, parameters, API keys, internal hostnames
- Parameters: hidden/undocumented params that change behavior (see `arjun`, `ffuf`)
- Virtual hosts: co-located apps behind one IP (see `asset_discovery`)

## Reconnaissance

1. **Passive first**: robots.txt, sitemap.xml, `security.txt`, HTML comments, meta tags, JS bundle URLs, DNS/CNAME clues, cert SANs (see `asset_discovery`)
2. **Crawl for seeds**: katana/gospider for links, forms, and API calls; note every URL with parameters
3. **Mine JS**: JS-Snooper (`/home/pentester/tools/JS-Snooper/js_snooper.sh`) and `jsniper.sh` extract endpoints and secrets from bundles; also grep raw JS for `/api/`, `fetch(`, `axios.`, `ws://`, `window.` config
4. **Source-aware**: whitebox - read routes/URL configs (Flask `url_map`, Express routes, Rails routes, Spring `@RequestMapping`, Next.js `app/` dir) and mirror them as the discovery baseline
5. **Wordlists**: `/usr/share/wordlists/` (Kali: install `wordlists`/`seclists` via apt if absent); common sets: `dirb/common.txt`, `dirbuster/directory-list-2.3-medium.txt`, Seclists `Discovery/Web-Content/raft-*`, `api/objects.txt`, `Common-PHP-Filenames.txt`, backup-extensions lists

## Key Techniques

### Directory / File Brute Force

`dirsearch` (pre-installed) is the workhorse:

```
dirsearch -u https://target -e php,html,txt,bak,old,env,json -t 20 --max-rate 50 \
  -x 404 --format=json -o dirsearch.json
```

For precision, `ffuf` (pre-installed):

```
ffuf -u https://target/FUZZ -w wordlist.txt -mc 200,204,301,302,307,401,403 -o ffuf.json
ffuf -u https://target/FUZZ -w raft-medium-words.txt -e .php,.bak,.old,.env,.json,.html -mc all -fc 404
```

### Backup and Config Patterns

- Same-name extensions: `index.php.bak`, `.old`, `~`, `#`, `.swp`, `.sav`, `.orig`, `.dist`
- Case/leet variants: `.env` vs `.ENV`, `Config.php.bak`, `db.sql` vs `backup.sql`
- Versioned files: `file.php.1`, `file-2024.sql`
- VCS: `/.git/HEAD` -> `/.git/config`; if readable, dump the repo (see below)
- `.DS_Store` parsing for directory listings (Python `ds_store` library or `strings`)

### `.git` / `.svn` Exposure

```
curl -s https://target/.git/HEAD
curl -s https://target/.git/config
```

If `.git/HEAD` returns `ref: refs/heads/main`, the object database may be downloadable with `git-dumper` (e.g., `pipx install git-dumper`, then `git-dumper https://target/.git/ outdir`) - full source disclosure. `.svn/entries`/`wc.db` similarly leaks paths and revisions.

### Parameter Discovery

`arjun` (pre-installed) discovers parameters from a large dictionary by measuring response changes:

```
arjun -u https://target/api/search -m GET -oJ -o arjun.json
```

Then fuzz interesting parameters with `ffuf`:

```
ffuf -u 'https://target/api/search?FUZZ=test' -w param-words.txt -mc all -fc 404 -fs <baseline>
```

Test discovered parameters for authz/injection with the class-specific skills (IDOR, SQLi, mass assignment, etc.).

### HTTP Method and Access-Control Bypass

- `OPTIONS`/`TRACE`/`PUT`/`DELETE` on discovered paths (405 vs 403 reveals method handling)
- 403 bypasses: `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Host`, path variants (`/admin` vs `/./admin`, `//admin`, `/Admin`, `/admin/`, `/admin%2f`, `%2e%2e/admin`, `..;/admin`, `;/admin`, Unicode/encoded case), method override headers
- Verify a bypass returns the real resource content, not just a different status code

### Virtual Host Discovery

```
ffuf -u https://IP -H "Host: FUZZ.example.com" -w vhost-words.txt -fs <baseline-size>
```

## Testing Methodology

1. Passive harvest (robots/sitemap/comments/JS)
2. Directory brute force with a medium wordlist + extension set (dirsearch)
3. Backup/config/VCS probes (`/.env`, `/.git/HEAD`, backup patterns)
4. JS mining for endpoints/params/secrets
5. Parameter discovery (arjun + ffuf)
6. 403/access-control bypass on denied paths
7. Verify each find (real content, not a soft-200) and deduplicate

## Validation

1. Each discovered resource returns distinguishable content (status + body evidence), not an SPA fallback
2. `.git` dump: show the restored source tree or key files
3. Parameter: show a behavior change caused by the parameter (error, feature toggle, auth difference)
4. Bypass: show the 403 -> 200 transition with the exact request
5. Record the tool, wordlist, and command for reproducibility

## False Positives

- SPA/Next.js-style soft-200s: every path returns the index page - filter by body size/content hash, not status
- WAF soft blocks returning 403/429 for everything after a few requests
- Default server pages (Apache `/icons/`, Nginx welcome page) counted as finds
- `/robots.txt` disallow entries that don't resolve to real paths
- Redirect-to-login 302s that hide auth requirements (still note them, but not "accessible")
- Wordlist hits on framework defaults (`/assets`, `/static`, `/vendor`) with no unique content

## Impact

- Admin/debug/API surface exposure for further testing
- Source code and secrets via `.git`/backup/config files
- Undocumented parameters enabling authz/injection findings
- Full attack-surface map feeding every specialist skill

## Pro Tips

1. Filter by content length/hash in `ffuf` (`-fs`) and exclude 404s in `dirsearch` (`-x`) - noise kills signal fast
2. Run `.git`, `.env`, and backup probes before the full brute force - one hit ends the engagement
3. Pair wordlists with extensions: default wordlists rarely contain `.bak`/`.env` hits on their own
4. Mine JS early: endpoints and parameters from bundles are usually higher-value than dictionary hits
5. Always verify 403 bypasses return real content; status-code-only changes are not findings
6. Combine with `technology_fingerprinting` to pick the right wordlists (PHP vs Node vs Java paths)

## Summary

Content discovery is a pipeline: passive harvest, directory brute force, backup/VCS probes, JS mining, parameter discovery, and access-control bypass - verified and deduplicated at the end. The finds feed every later testing phase, so run it early and keep evidence per discovery.
