---
name: js-analysis
description: JavaScript file harvesting and static analysis to extract API endpoints, parameters, secrets, dangerous sinks, and source maps for downstream specialist agents
---

# JavaScript Analysis

Recon-and-analysis specialist for the JavaScript attack surface. Collect every JS file the application loads (including lazy-loaded chunks and dynamically imported modules), run regex/AST extraction over them, and emit a structured artifact other specialist agents (IDOR, SSRF, XSS, Auth) can consume.

This agent does NOT exploit. It produces a high-fidelity inventory.

## Output Contract

Write a single `js_analysis.md` artifact to the workspace with these sections. Other agents read this — keep it deterministic.

```
# JS Analysis — <target>

## Inventory
- <url> — <size> — <type: main|chunk|lazy|vendor|sourcemap>

## API Endpoints
- METHOD /path — source: <jsfile>:<line> — context: <one-line snippet>

## Parameters Observed
- <param> — endpoints: [<list>] — values seen: [<sample>]

## Secrets / Keys
- <kind> — <redacted match> — source: <jsfile>:<line>

## Dangerous Sinks
- <sink: eval|innerHTML|document.write|postMessage|location.href|dangerouslySetInnerHTML|new Function|setTimeout(string)|setInterval(string)|window[var]> — source: <jsfile>:<line> — taint: <reachable from user input? yes/no/unknown>

## Auth & Session Surfaces
- localStorage/sessionStorage keys, cookie names, JWT decode sites, refresh-token endpoints

## Routes / Client Pages
- <route> — source: <jsfile>:<line>

## Source Maps
- <jsfile>.map — recovered: yes/no — original sources count: <N>

## Notes for Downstream Agents
- IDOR agent: <pointer to most likely vulnerable endpoints>
- SSRF agent: <list of URL-builder helpers found>
- XSS agent: <list of innerHTML/dangerouslySetInnerHTML sinks>
- Auth agent: <list of JWT/refresh/cookie touchpoints>
```

## Phase 1 — Collection

Two-pass collection. Static fetch + dynamic browser to catch lazy chunks.

**Pass A — Static crawl**

1. Use `katana` / `gau` / `waybackurls` on the target to harvest historical and live URLs.
2. Filter for `.js`, `.mjs`, `.cjs`, `.map` extensions and JS-Content-Type responses.
3. Use `httpx` to confirm 200 status, capture final URL after redirects, record size + sha256.
4. Save each file to `js_corpus/<host>/<sha256>.js` and keep a manifest `js_corpus/manifest.tsv`:
   `url\tstatus\tsize\tsha256\tcontent_type\tsource`

**Pass B — Browser-driven lazy capture**

Many SPAs only fetch chunks after user interaction. Use the browser tool:

1. Open the app, log in if needed, hit every route in the inventory.
2. Trigger interactions that lazy-load: dropdowns, modals, tab switches, route navigation, search, file uploads, settings, admin panel.
3. Capture all network requests where `Content-Type` matches `*javascript*` or `*ecmascript*`.
4. Compare against Pass A — anything new is a lazy/dynamic chunk. Add to manifest with `source=dynamic`.

**Source maps**

For each `<file>.js`, request `<file>.js.map`. If present:
- Parse `sources[]` array — recover original file tree (often leaks internal package names, paths, auth helpers).
- Note any reference to internal hostnames, microservice names, AWS account IDs.
- Save recovered originals to `js_corpus/<host>/sourcemap/<original_path>`.

## Phase 2 — Endpoint & Parameter Extraction

Run these regex passes over every JS file. Tag each hit with `<file>:<line>`.

**HTTP method + path strings**

```regex
(?:fetch|axios\.(?:get|post|put|delete|patch|request)|\$\.(?:get|post|ajax)|XMLHttpRequest|\.open)\s*\(\s*['"`]([^'"`]+)['"`]
```

```regex
(?:url|endpoint|path|route)\s*[:=]\s*['"`](/[A-Za-z0-9_\-/.?&=:%{}]+)['"`]
```

```regex
['"`](/(?:api|v\d+|graphql|gql|rest|rpc|internal|admin|auth|user|users|account|me)[/A-Za-z0-9_\-./?&=:%{}]*)['"`]
```

**Inline template literals (routes with `${id}` etc.)**

```regex
`(/[A-Za-z0-9_\-/.?&=:%]*\$\{[^}]+\}[A-Za-z0-9_\-/.?&=:%]*)`
```

Normalize `${var}` → `{var}` in the output.

**Query / body parameter names**

```regex
(?:params|data|body|searchParams|form)\s*[:=]\s*\{([^}]{1,300})\}
```

Extract keys from the matched object literal.

**GraphQL operations**

```regex
(?:gql|graphql)\s*`\s*(query|mutation|subscription)\s+(\w+)
```

Save full operation bodies; they describe the entire backend object graph.

## Phase 3 — Secret Extraction

Run high-precision regex, then triage. False positives waste downstream agents' time.

```
AWS access key     AKIA[0-9A-Z]{16}
AWS secret         (?i)aws(.{0,20})?(?-i)['"`][0-9a-zA-Z/+]{40}['"`]
Google API key     AIza[0-9A-Za-z\-_]{35}
Stripe live        sk_live_[0-9a-zA-Z]{24,}
Stripe publishable pk_live_[0-9a-zA-Z]{24,}
SendGrid           SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}
Slack webhook      https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+
Slack token        xox[abprs]-[0-9a-zA-Z\-]+
GitHub PAT         ghp_[A-Za-z0-9]{36}
GitHub fine-grain  github_pat_[A-Za-z0-9_]{82}
JWT                eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+
Private key        -----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----
Firebase config    apiKey.{0,3}:.{0,3}["']AIza[0-9A-Za-z\-_]{35}["']
Sentry DSN         https://[0-9a-f]{32}@[a-z0-9.\-]+/[0-9]+
Mapbox token       pk\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+
Algolia            (?:algolia).{0,30}["'][0-9a-f]{32}["']
```

For every match: redact middle bytes when writing to artifact (`AKIA****REDACTED****ABCD`), but record full value in a separate `secrets.tsv` for the operator only. **Never** exfiltrate or test secrets against live infra without explicit approval.

## Phase 4 — Dangerous Sink Detection

These are the sinks downstream XSS / DOM-XSS / RCE / open-redirect agents need pointers to:

| Sink | Regex | Bug class |
|---|---|---|
| `eval(` | `\beval\s*\(` | RCE / DOM-XSS |
| `new Function(` | `new\s+Function\s*\(` | RCE / DOM-XSS |
| `setTimeout(string)` | `setTimeout\s*\(\s*['"`]` | RCE |
| `setInterval(string)` | `setInterval\s*\(\s*['"`]` | RCE |
| `innerHTML =` | `\.innerHTML\s*=` | DOM-XSS |
| `outerHTML =` | `\.outerHTML\s*=` | DOM-XSS |
| `document.write(` | `document\.write(?:ln)?\s*\(` | DOM-XSS |
| `dangerouslySetInnerHTML` | `dangerouslySetInnerHTML\s*=\s*\{` | DOM-XSS (React) |
| `v-html=` | `v-html\s*=` | DOM-XSS (Vue) |
| `[innerHTML]=` | `\[innerHTML\]\s*=` | DOM-XSS (Angular) |
| `location =` | `(?:window\.)?location(?:\.href)?\s*=` | Open-redirect |
| `location.replace(` | `location\.replace\s*\(` | Open-redirect |
| `postMessage(` | `\.postMessage\s*\(` | postMessage flaws |
| `addEventListener('message'` | `addEventListener\s*\(\s*['"]message['"]` | postMessage flaws |
| `JSON.parse(localStorage` | `JSON\.parse\s*\(\s*(?:localStorage\|sessionStorage)` | Prototype pollution / data tamper |
| `Object.assign({},` | `Object\.assign\s*\(` | Prototype pollution |
| `_.merge(` / `_.mergeWith(` | `_\.(?:merge\|mergeWith\|defaultsDeep)\s*\(` | Prototype pollution |
| `_.set(` | `_\.set\s*\(` | Prototype pollution |
| `window[…]` | `window\s*\[[^\]]+\]\s*\(` | Property-name injection |

For each hit, capture **3 lines of context** (the sink line + 1 before + 1 after) so the downstream agent can judge taint quickly without re-reading the whole bundle.

**Quick taint heuristic**: if the same file references `location.search`, `location.hash`, `URLSearchParams`, `document.referrer`, `window.name`, `postMessage event.data`, or reads from a URL-bound state library (React Router `useParams`/`useSearchParams`, Vue `$route`, Angular `ActivatedRoute`), mark sinks in that file as `taint: likely`. Otherwise `unknown`.

## Phase 5 — Auth & Session Inventory

Other agents (Auth, IDOR) need this fast:

- All `localStorage.setItem` / `getItem` keys
- All `sessionStorage.setItem` / `getItem` keys
- All `document.cookie =` assignments
- All `Authorization: Bearer` template literals → identifies token shape (JWT vs opaque)
- All `jwt_decode(` / `jose.decodeJwt(` call sites — confirms tokens are JWT, gives you a free decode site
- Refresh / silent-renew endpoints (search for `refresh`, `silentRenew`, `token/renew`)
- CSRF token retrieval (search for `csrf`, `xsrf`, `X-CSRF`, `X-XSRF-Token`)
- OAuth client IDs and redirect URIs (search for `client_id`, `redirect_uri`, `response_type`)

## Phase 6 — Hand-off Notes

End the artifact with explicit pointers other agents need. Be specific — name endpoints, not vibes:

```
## Notes for Downstream Agents
- IDOR agent: GET /api/v2/orders/{id}, GET /api/users/{id}/invoices, GET /api/files/{uuid} all
  built from path params with no server-side ownership claim visible in JS. Highest-ROI targets.
- SSRF agent: `buildProxyUrl(host)` in vendor.abc123.js:4421 concatenates user-controlled `host`
  into outbound fetch. Worth probing /api/proxy?target=
- XSS agent: dangerouslySetInnerHTML in CommentRenderer (chunk-9f2.js:188) — taint: likely.
  Comment field is server-rendered; check if HTML is sanitized server-side.
- Auth agent: refresh endpoint is POST /api/auth/silent — accepts refresh_token in body, no
  device binding observed in client. Possible token replay surface.
```

## Tools

- `katana`, `gau`, `waybackurls` — URL harvest
- `httpx` — fetch + metadata
- `agent_browser` — lazy chunk capture (Pass B)
- `semgrep` — for higher-fidelity AST passes if regex misses (rulesets: `r/javascript.audit.xss`, `r/javascript.lang.security`)
- Python regex driver (write a one-shot script per pass; keep outputs deterministic)

## Rules

- **Never** post extracted secrets to third-party services (no virustotal-uploading bundles, no online beautifiers).
- Beautify locally only (`js-beautify`, `prettier`).
- Source-map originals can contain proprietary code — do not exfiltrate, keep local to the workspace.
- Do not run extracted JS. Static analysis only at this stage.
- Mark every finding `taint: unknown` if you cannot trace it back to a user-controllable source — let the downstream agent decide.
- One artifact per target. Overwrite, do not append; downstream agents always read the latest.
