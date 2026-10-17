---
name: client-side-path-traversal
description: Client-side path traversal (CSPT) testing in SPAs — React Router, Vue Router, Angular router, Next.js client navigation — where a route/query/hash parameter flows into a fetch/XHR/axios URL, a client router navigation, or a BFF proxy path
---

# Client-Side Path Traversal

Client-Side Path Traversal (CSPT) is a traversal where the attacker-controlled source is a browser-visible part of the URL (a path segment, query value, or hash) and the sink is a request the page builds or shapes — a `fetch`/XHR/axios call, a client-router navigation, or a server-side/BFF fetch whose path the client supplies. There is no filesystem and no local file read: the `../`, `%2f`, `%2e`, or backslash survives decoding/normalization and rewrites the *request path* the browser (or the BFF on its behalf) ultimately issues. Treat it as a request-redirection primitive inside the app, not as server-side path traversal; the impact comes from where the redirected request lands and what it does.

## Exploitability Bar

CSPT is a finding only when ALL THREE hold:

1. **Controlled source survives.** A browser-controlled source — a URL path segment, query value, or hash — is decoded/normalized so that path syntax (`../`, `%2f`, `%2e`, backslash, double-encoded forms) still carries into the next stage instead of being stripped or re-encoded.
2. **Reaches a request sink.** That value reaches a request-construction sink in the page: `fetch`/XHR/axios/another HTTP client, OR a client-router navigation, OR a server-side/BFF fetch whose path the client controls.
3. **Produces real impact.** The resulting request has a security-relevant effect: a state change (CSRF-like), a response rendered/executed in an unsafe sink (XSS), a server-side fetch reaching an internal/privileged target (SSRF), an authorization/permission bypass, or disclosure of another user's or tenant's data.

**False-positive rule:** a router or framework that merely decodes `../` with NO request sink, or a sink whose redirected request has NO security-relevant effect, is a FALSE POSITIVE — do not report it. This mirrors the repo-wide closure discipline (`confirmed` / `ruled_out` / `open_proof_gap`) and the `counterevidence` pass: no proven sink and impact means `open_proof_gap`, not a finding.

## Source -> Sink -> Impact

Trace the whole pipeline before claiming anything:

```text
browser URL -> router parser -> route/query/hash accessor -> app URL construction -> fetch/XHR/router -> final normalized request
```

Each decode or re-encode along that chain is a decision point: confirm the traversal is still present in the request that actually leaves the page.

Sink taxonomy and the impact it maps to:

- **State-changing API call** (`POST`/`PUT`/`PATCH`/`DELETE` built from the source) -> CSRF-like unintended action on a different resource.
- **Response rendered/executed in the DOM** (traversed response body into `innerHTML`, template, `eval`, script/JSON-driven render) -> XSS.
- **Server-side / BFF fetch** keyed on a client-supplied path segment -> SSRF toward internal/metadata/privileged targets.
- **Authorization/permission check keyed on the path** (resource id, tenant slug, role segment) -> authz bypass or cross-tenant disclosure of another user's/tenant's data.

One source can reach several sinks; classify by the strongest proven impact, not the easiest to trigger.

Minimal shape of the primitive — a profile viewer whose id comes from the route:

```text
app route:   /users/<id>
app builds:  fetch(`/api/users/${id}`)
attacker id: ../../admin/settings   (or ..%2f..%2fadmin%2fsettings)
final req:   GET /api/admin/settings   <- traversal survived into the sink
```

Whether this is a finding depends entirely on what `/api/admin/settings` does for the current principal — map that before reporting.

## Discovery -- black-box (runtime)

Instrument in a controlled browser session to capture the FINAL request shape (method + origin + path only — never bodies, credentials, or query strings):

```javascript
const realFetch = window.fetch;
window.fetch = (...args) => {
  const input = args[0];
  const raw = typeof input === 'string' ? input : input.url;
  const u = new URL(raw, location.href);
  const method = args[1]?.method || input?.method || 'GET';
  console.log('fetch', {method, origin: u.origin, path: u.pathname});
  return realFetch(...args);
};
const realOpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function (method, url, ...rest) {
  const u = new URL(url, location.href);
  console.log('xhr', {method, origin: u.origin, path: u.pathname});
  return realOpen.call(this, method, url, ...rest);
};
```

Restore `window.fetch = realFetch` and the XHR prototype after validation. This adapts the wrapper in `browser_security`; load that skill for the full browser-state model and router-decoding notes. The wrapper captures `fetch` and XHR only — a pure client-router navigation sink (`history.pushState`, `router.push`) issues no HTTP request from this hook, so watch those in Caido's outbound capture or wrap the history/router API separately.

Then vary the route/query/hash independently with `%2f`, `%2e`, `%5c`, raw dot-segments (`../`, `..%2f`), and double-encoded forms (`%252f`, `%252e`). For each source, read the logged final path and determine exactly where the sequence decodes, is removed, or re-encodes. Path parameters, query values, and fragments are commonly transformed differently — test each on its own. agent-browser (see `tooling/agent_browser`) runs in the sandbox with Caido capturing the final request, so compare the console log against the captured outbound request.

## Discovery -- white-box (source)

Find a route/query/hash value flowing into a request URL. Grep or `ast-grep` per framework:

- **React:** `useParams`, `useSearchParams`, `useLocation`, `useRouter` whose result is interpolated into `fetch(`, `axios`, `.get(`/`.post(`.
  ```bash
  rg -n "useParams|useSearchParams|useLocation|useRouter" --glob '*.{ts,tsx,js,jsx}' -A4 | rg "fetch\(|axios|\.(get|post|put|patch|delete)\("
  ```
- **Vue:** `useRoute`, `route.params`, `route.query`, `$route` feeding an HTTP client (`fetch`, `axios`, `$http`).
- **Angular:** `ActivatedRoute`, `paramMap`, `snapshot.params`/`snapshot.queryParams` feeding `HttpClient.get/post`.
- **Svelte/SvelteKit:** `$page.params`, `$page.url.searchParams`, and `load({ params, url })` whose value is interpolated into `fetch(`/`axios`, or routed through a `+server.ts`/`+page.server.ts` handler that forwards the client-supplied segment.
- **Generic:** string-interpolated URL construction — `` `${base}/${param}` ``, `url + param`, `new URL(param, base)`, path `.join`/concat — where `param` is any router-derived value.

Call out BFF and Next.js route handlers (`app/**/route.ts`, `pages/api/*`) that forward a client-supplied path into a server `fetch`; those turn CSPT into SSRF. See `nextjs` for RSC/BFF path forwarding. The same framework API can decode differently in client components, server components, and route handlers — do not assume one behavior.

## Escalation by sink

Prove the impact-class-specific fact before calling it exploitable:

- **CSRF-like:** show the redirected request hit a *different*, state-changing endpoint and the state change occurred (not merely a 404/redirect). Include a benign-path control.
- **XSS:** show the traversed response body reached an unsafe render sink AND executed (script ran / handler fired) — a reflected string that never executes is not XSS.
- **SSRF:** show the server-side/BFF fetch reached an internal or metadata target (e.g. a controlled internal canary or `169.254.169.254`) and returned or acted on that response; a same-origin public redirect is not SSRF.
- **Authz bypass / cross-tenant:** show the request returned or mutated a resource the current principal must not access (another user/tenant id), with a paired same-principal control that is denied or scoped correctly.

## Validation

1. Capture the final network request (method + origin + path) AND the security-relevant response or action it caused.
2. Run a paired control: a benign path next to the traversed path, same session and state, so the difference is attributable to the traversal and not to unrelated behavior.
3. Provide a minimal PoC — the smallest source value that redirects the request and the single observed effect. Do not paste large payload catalogs.
4. Close under the repo discipline: a proven source+sink+impact is `confirmed`; a decode with no reachable sink, or a sink with no security-relevant effect, is `ruled_out` (name the control) or `open_proof_gap` (name the missing proof). Run the `counterevidence` pass before reporting.

## False Positives

- Decode/normalization of `../` with no request sink downstream — the value never shapes a request.
- A sink whose redirected request has no security-relevant effect (static asset, idempotent read of already-authorized data, dead/404 path).
- Same-origin-only redirection to an equally-authorized endpoint — the principal could already call it directly.
- A framework that re-encodes or segment-normalizes before the sink, so the traversal does not survive into the final request.

## Pro Tips

1. The attacker-supplied string is not evidence; the browser-parsed final request path is. Always read the logged `origin` + `path`, never the raw input.
2. Query and hash values are usually decoded automatically; path segments vary by router and by execution context. Test each source separately.
3. Double-encoding (`%252f`) often survives one decode layer that strips single-encoded forms — probe it whenever a single `%2f` is removed.
4. A BFF/route-handler hop is the difference between a same-origin dead end and SSRF; trace whether the server fetch inherits the client-supplied segment.
5. No sink and no impact is `open_proof_gap`, never a finding. Name the missing proof instead of reporting the decode.
6. Prefer a one-line minimal PoC and a paired control over a payload catalog; the reusable unit is the source-to-sink pipeline, not the string.

## Cross-links

- `browser_security` — browser-state model, router-decoding notes, runtime instrumentation this skill adapts.
- `semantic_confusion` — decode/normalization differentials across router vs server when the two disagree on the same bytes.
- `open_redirect`, `csrf`, `xss`, `ssrf` — the escalation sinks; use the matching skill once the impact class is known.
- `nextjs` — RSC/BFF route handlers that forward a client-supplied path into a server fetch.
