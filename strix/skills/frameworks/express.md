---
name: express
description: Security testing playbook for Express.js covering middleware ordering, route auth gaps, prototype pollution, and session/CSRF weaknesses
---

# Express.js

Security testing for Express and common middleware stacks (body-parser, cors, helmet, express-session, passport). Focus on middleware ordering, missing route-level auth, unsafe deserialization of user input into objects, and inconsistent enforcement across routers.

## Attack Surface

**Core Components**
- Middleware stack order: `app.use()` global vs `router.use()` scoped
- Routers: `express.Router()` mounted at prefixes (`/api`, `/admin`, `/v1`)
- Route handlers: `app.get/post/put/delete`, async handlers, error middleware
- Static serving: `express.static`, `sendFile`, custom download handlers

**Common Middleware**
- `body-parser` / `express.json` / `express.urlencoded` / `express.raw`
- `cors`, `helmet`, `compression`, `morgan`
- `express-session`, `cookie-parser`, `passport`, `express-jwt`
- `multer` / `busboy` for uploads
- `express-validator`, `celebrate`, `joi` validation (often partial)

**Data & Templates**
- Template engines: EJS, Pug, Handlebars, Nunjucks
- MongoDB via Mongoose, SQL via Sequelize/Prisma/Knex
- `req.query`, `req.params`, `req.body`, `req.cookies`, `req.headers`

## High-Value Targets

- `/api/*` routers mounted without global auth middleware
- Admin routers at `/admin`, `/internal`, `/management`
- File upload/download routes using `multer`
- Webhook/callback endpoints (`/webhook`, `/callback`, `/notify`)
- Session-based auth without CSRF on state-changing routes
- `process.env` values leaked via error handlers or `/debug` routes
- GraphQL or Socket.io mounted as sub-apps with weaker auth

## Reconnaissance

**Route Discovery**
```
# Common API prefixes
/api /api/v1 /api/v2 /v1 /v2 /graphql /socket.io

# Error-based route hints
GET /api/users/999999
POST /api/admin with {}
```

**Fingerprinting**
```
X-Powered-By: Express
Set-Cookie: connect.sid=...
```

Inspect `package.json` / `node_modules` in white-box scans for: `passport`, `jsonwebtoken`, `express-session`, `cors`, `lodash`, `serialize`, `ejs`.

**Middleware Mapping (white-box)**

Trace `app.use()` order — auth middleware placed after routes it should protect is a common bug. Routers mounted before `express.json()` may parse bodies differently.

## Key Vulnerabilities

### Authentication & Authorization

**Middleware Gaps**
- Global auth on `/api` but `/api/internal` router mounted without guard
- `router.use(auth)` on collection routes but `GET /:id` missing per-object checks
- JWT verified in middleware but `req.user` fields trusted without role re-check on admin routes

**Passport / JWT**
- `passport-jwt` extracts token but strategy doesn't validate `aud`/`iss`
- `secretOrKey` from env with weak/default value
- API keys in query string logged by proxies

### Prototype Pollution

Express apps frequently merge `req.body` / `req.query` into options objects via `lodash.merge`, `Object.assign` loops, or query parsers.

```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"role": "admin"}}}
```

See `prototype_pollution` skill for gadget chains and validation. Test every JSON body endpoint and nested query parameters.

### NoSQL Injection (Mongoose)

```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"$where": "this.password.match(/.*/)"}
```

Operator injection via `req.query.filter` passed directly to `Model.find(req.query)`.

### Server-Side Template Injection

EJS/Pug/Handlebars with user-controlled template names or unescaped output:
```javascript
// Vulnerable patterns
res.render(userInput)
ejs.render(userControlledTemplate)
```

Test `<%= 7*7 %>`, `${7*7}`, `{{7*7}}` depending on engine.

### CSRF

Express has no built-in CSRF protection.
- `express-session` + cookie auth on POST/PUT/DELETE without a maintained synchronizer-token or double-submit CSRF implementation
- `SameSite=None` cookies without proper origin checks
- CORS `credentials: true` with reflected origins

### CORS Misconfiguration

```javascript
// Dangerous patterns
cors({ origin: true, credentials: true })  // reflects any origin
cors({ origin: '*' }) with credentials
```

Test cross-origin requests with victim cookies to sensitive endpoints.

### Path Traversal & LFI

```javascript
res.sendFile(req.query.path)
res.download('../' + req.params.file)
express.static with symlink following
```

### SSRF

`axios`/`node-fetch`/`request` fetching user-supplied URLs in webhooks, preview, import features. Test loopback, metadata IPs, redirect chains.

### File Upload (Multer)

- Extension/MIME checked client-side only
- `destination` callback using unsanitized `file.originalname`
- Uploaded files served from `/uploads` with `Content-Disposition: inline`

### Rate Limiting Bypass

- `express-rate-limit` applied globally but skipped on `/api/login` brute-force paths
- `X-Forwarded-For` spoofing when `trust proxy` enabled without network boundary

### Error & Information Disclosure

- Stack traces in production (`NODE_ENV` not `production`)
- Verbose 404 messages revealing route existence
- `express-status-monitor`, `/metrics` exposed without auth

## Bypass Techniques

- Content-Type switching: `application/json` vs `application/x-www-form-urlencoded` hitting different parsers
- HTTP method override headers where proxies honor `X-HTTP-Method-Override`
- Trailing slash and case variants: `/API/users` vs `/api/users`
- Parameter pollution: duplicate keys in query and body
- Race conditions on session/token issuance (parallel login + privilege change)

## Testing Methodology

1. **Map routers** — Enumerate mounted paths, versioned APIs, static mounts
2. **Auth matrix** — Unauth/user/admin for each route and HTTP method
3. **Middleware order** — Confirm auth runs before handlers on every mount point
4. **Object ownership** — Swap IDs across two sessions on all CRUD endpoints
5. **Prototype pollution probe** — Canary key on all JSON-merge endpoints
6. **CSRF** — Cross-origin POST with session cookie on state-changing routes
7. **Sub-app parity** — Same auth on Socket.io/GraphQL mounts as REST

## Validation

1. Side-by-side requests showing missing auth or IDOR (owner vs non-owner)
2. CSRF PoC for session-authenticated state change
3. Prototype pollution behavioral proof with unique canary property
4. Template/NoSQL/SSRF with deterministic oracle (output, OAST, timing)
5. Document exact middleware/router where enforcement failed

## False Positives

- `router.use(authenticate)` applied before all child routes consistently
- `Object.create(null)` used for options merging throughout codebase
- CSRF token validated on all unsafe session-authenticated methods
- CORS origin whitelist is explicit array, not reflection
- `helmet` + `noSniff` + `Content-Disposition: attachment` on uploads

## Impact

- Full account takeover via session/JWT weaknesses or prototype pollution
- Data breach via NoSQL injection or IDOR across API routers
- RCE via SSTI or deserialization (`node-serialize`, unsafe `eval`)
- Admin access via unprotected `/admin` router or role field pollution

## Pro Tips

1. Check every `express.Router()` mount — auth middleware on parent `app` may not cover sibling routers
2. `app.use('/api', router)` vs `app.use(router)` — scope mistakes are frequent
3. Async error handlers without `express-async-errors` may skip error middleware silently
4. Test `app._router.stack` in local dev to dump registered routes (white-box)
5. Combine with `prototype_pollution` and `insecure_deserialization` skills for Node chains

## Summary

Express security is middleware-order dependent. Auth must wrap every router and transport; user input must never merge unsafely into object prototypes. Test mounted sub-apps and async routes with the same rigor as top-level handlers.
