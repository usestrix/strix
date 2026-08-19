---
name: express
description: Security testing playbook for Express/Node.js applications covering prototype pollution, template injection, middleware order, and CORS/session flaws
---

# Express / Node.js

Express is the most common Node.js web framework. Its power is middleware composition - and its weakness is the same: one missing `next()`, one permissive body parser, one user-controlled option passed to a renderer, and an authorization check is skipped or a prototype is polluted. Most Express apps also use EJS/Handlebars/Pug, `qs`, `multer`, and cookie/session middleware, each with its own attack surface.

## Attack Surface

- Route handlers and middleware order: auth middleware that runs after a handler, or a handler that skips `next()`
- Query/body parsing: `qs` deep parsing, extended URL-encoded bodies, JSON with `__proto__`/`constructor`
- Templating: EJS, Handlebars, Pug, Nunjucks - especially `render` with user-controlled options
- Static files: `express.static` misconfiguration, `sendFile`/`download` with user input, `res.sendFile`
- Sessions/cookies: `express-session`, signed cookies with weak `secret`, cookie flags
- Auth: `express-jwt`, passport, custom middleware that trusts `X-User-*` headers
- File uploads via `multer`: filename/path injection, extension checks, symlink tricks
- Outbound calls: `fetch`/`axios`/`request` with user URLs (SSRF), `child_process` (command injection)
- Package ecosystem: prototype-pollution-prone merge/assign helpers (`lodash.merge`, `_.set`, `deep-extend`, `flat`)

## Reconnaissance

1. **Source map first** (whitebox): read `package.json` for dependencies and versions; list routes; check middleware registration order; grep for sinks: `exec`, `eval`, `child_process`, `fetch(` with user input, `merge`, `set(`/`assign`, `render(`, `sendFile(`
2. **Blackbox**: fingerprint Express via `X-Powered-By: Express` (often stripped), 404/error shapes, cookie names (`connect.sid`), and behavior of malformed JSON (`SyntaxError: Unexpected token` in responses)
3. **Enumerate routes** from JS bundles, source maps (`/*.js.map`), `swagger.json`, and crawl results
4. **Test body parsers**: send `application/json` with `{"__proto__":{...}}`, extended form bodies with nested keys, and duplicate/conflicting content-types

## Key Vulnerabilities

### Prototype Pollution

`qs` with `extended: true` parses `?__proto__[polluted]=1` or `?constructor[prototype][polluted]=1` into object keys; JSON bodies with `__proto__`/`constructor.prototype` keys hit `JSON.parse` + merge helpers:

```
GET /?__proto__[isAdmin]=true
POST /api/update {"__proto__": {"isAdmin": true}}
POST /api/update {"constructor": {"prototype": {"polluted": true}}}
```

Impact depends on what the app reads from the prototype: auth flags, `env`/`NODE_OPTIONS`, template options, or RCE chains (e.g., polluting `child_process` options or EJS render options). Check the `prototype_pollution` skill for the full chain.

### Template Injection (EJS / Handlebars)

EJS with user-controlled options is a classic RCE:

```
render('index', { ...req.query })
settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('id');s
```

Handlebars SSTI (`{{#with "s" as |string|}}...`) and Pug options injection (`?pretty` + `options` abuse) are also known paths. See the `ssti` skill for payloads.

### Middleware-Order Authorization Gaps

- Auth middleware attached after public routes or to a router that a nested route bypasses
- `app.use` vs `app.get` ordering: a route registered before `app.use(auth)` skips auth
- Error-handling middleware swallowing auth failures and rendering the page anyway
- Headers trusted from upstream: `X-Forwarded-For`/`X-Real-IP` used for IP allowlists; `X-User-Id`/`X-Role` accepted from clients

### Path Traversal / File Disclosure

- `res.sendFile(userInput)` and `res.download(userInput)` with `../` or absolute paths
- `express.static` with a broad root and missing deny rules; `%2e%2e%2f`, `..%2f`, double encoding, backslashes on Windows-behind-proxy setups
- Source map files, `.env`, `package.json`, and backup files served by misconfigured static roots

### CORS and Sessions

- Wildcard ACAO with `credentials: true`, or origin reflection (see `cors_misconfiguration`)
- `express-session` with `resave`/unset cookie flags, missing `httpOnly`/`secure`, weak `secret` (brute-forceable when signed cookies are used)
- `express-jwt` with `algorithms: ['HS256']` accepting HS256-signed tokens when the public key is available (see `authentication_jwt`)

### SSRF and Command Injection

- `fetch(userUrl)`, `axios.get(userUrl)`, `request(userUrl)` in proxying/importing/avatar features -> SSRF (see `ssrf`)
- `child_process.exec('...' + userInput)` or `execFile` with a shell wrapper -> command injection (see `command_injection`)

### Mass Assignment via Spread

`db.update({ ...req.body })` or `Object.assign(target, req.body)` lets clients set fields the form never exposed (`role`, `isAdmin`, `balance`). See `mass_assignment`.

## Advanced Techniques

- **`qs` depth abuse**: enable deep keys and nested arrays to bypass naive validation or reach different code paths (`?filter[0][gte]=1`)
- **Content-type smuggling**: `application/x-www-form-urlencoded` + JSON body tricks; `text/plain` parsed as JSON by permissive middleware
- **Race on async middleware**: handlers that `await` auth asynchronously and continue before the check completes (see `race_conditions`)
- **npm supply chain**: `retire`/`trivy` on `package-lock.json`/`yarn.lock` for known vulnerable deps; `govulncheck`/`vulnx` for Go-adjacent paths
- **ReDoS**: user-controlled regexes or `String.match` with crafted input on complex patterns

## Testing Methodology

1. Map routes + middleware order (whitebox) or fingerprint + crawl (blackbox)
2. Test body/query parsers for prototype pollution at every input surface
3. Check template render options and static file paths for injection/traversal
4. Audit auth middleware order and trusted headers
5. Test CORS, session cookies, and JWT algorithm confusion
6. Fuzz SSRF/command sinks with the dedicated skills
7. Validate every finding with a concrete request/response pair

## Validation

1. Prototype pollution: show a global object property polluted and, where possible, an observable effect (auth bypass, RCE)
2. Authz gap: same request with and without the middleware/token -> unauthorized success
3. Template injection: execute a benign marker (`process.version`) and show output
4. Path traversal: read a real file (`package.json`/`.env`) with the exact traversal payload

## False Positives

- `__proto__` accepted into the body but never read by app logic (pollution without impact)
- `X-Powered-By` stripped/absent - Express fingerprinting needs behavior, not headers alone
- Wildcard CORS without credentials serving public data
- `sendFile` rejecting `..` traversal (normalization) while echoing the path in the error
- Middleware "gap" that a later auth check still covers

## Impact

- RCE via template injection, command injection, or deserialization chains
- Account/data compromise via prototype-polluted auth flags or mass assignment
- File disclosure of source and secrets via traversal
- Data exfiltration via SSRF and CORS flaws

## Pro Tips

1. Read `package.json` first when source is available - vulnerable versions (`qs <1.x`, old `lodash`, `ejs`) shortcut whole classes
2. Test prototype pollution before auth logic: `?__proto__[isAdmin]=true` is the fastest check on many apps
3. Middleware order is the #1 Express auth bug - verify auth runs before *every* route it should protect
4. Check static roots for source maps and `.env`; they are the highest-signal finds on Express apps
5. Combine with `prototype_pollution`, `ssti`, `mass_assignment`, `ssrf`, and `command_injection` skills for payload depth

## Summary

Express apps fail at composition: middleware order, permissive parsers, user-controlled template options, and trusted headers. Map the route/middleware tree, probe parsers for prototype pollution, test render/static sinks, and validate authz at every route - then chain to impact with the class-specific skills.
