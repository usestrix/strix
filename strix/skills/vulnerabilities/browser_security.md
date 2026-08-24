---
name: browser-security
description: Browser-internals security testing for browsing-context relationships, postMessage, client-side path traversal, XS-Leaks, service workers, Web Workers, navigation behavior, CSP interactions, caches, and cross-origin state machines
---

# Browser Security

Use this skill when exploitability depends on browser behavior beyond a basic HTML injection. Model origins, browsing contexts, navigation history, workers, caches, router decoding, request metadata, and user activation as explicit state.

Pair this skill with `xss`, `oauth`, `open_redirect`, `csrf`, or `semantic_confusion` when one of those is the primary vulnerability class. For an Electron renderer with a preload or IPC bridge, load `electron_desktop_apps` to analyze whether navigation and origin transitions reach native capability.

## Safety Boundary

- Use a controlled browser profile, synthetic account/data, explicit target allowlist, and a fresh assessment-specific proxy/CA when interception is required.
- Redact tokens, cookies, message contents, storage values, and personal data from console logs, captures, recordings, and reports.
- Treat oversized URLs/headers, cookie inflation, redirect loops, cache exhaustion, and high-rate timing trials as resource/denial-of-service tests; run them only with strict ceilings in a restartable lab.
- Do not attempt to set or spoof browser-generated `event.origin`. Vary the sender URL and record the serialized origin supplied by the browser.
- Restore monkey-patched browser APIs and unregister test workers/caches after validation.

## Browser State Model

For each relevant page or worker, record:

- origin and site, including transitions after navigation
- top-level window, opener, parent, child frames, named contexts, and retained references
- sandbox flags, CSP `frame-ancestors`, COOP, COEP, CORP, and X-Frame-Options
- service-worker controller and scope
- storage access: cookies, local/session storage, IndexedDB, Cache API
- navigation/history entries and redirect type: HTTP, JavaScript, form, meta refresh
- user-activation and interaction requirements
- browser family/version and enabled experimental features

Draw the context graph. Security checks on `event.origin`, `event.source`, or a popup reference are meaningful only when the lifetime and ownership of that context are understood.

## High-Value Surfaces

### postMessage and Window Relationships

- Enumerate listeners and senders; record message schema, origin check, source check, and reachable sinks/actions.
- Validate origins after URL parsing and canonicalization, not with raw-string regexes.
- Test numeric/alternate IP forms, userinfo, path masquerading as a host suffix, and redirects.
- Treat predictable `window.open()` target names and iframe names as potentially shared namespace entries. Confirm reuse within the same browsing-context group, opener chain, COOP state, and relevant navigation/message timing.
- Check whether a blocked intermediate frame leaves a useful browsing-context relationship intact.
- Use random per-flow names or `_blank` with `noopener` where an opener relationship is unnecessary.

### Client-Side Path Traversal

Trace the complete source-to-request pipeline:

```text
browser URL -> router parser -> route/query/hash accessor -> app interpolation -> fetch/XHR -> final normalized URL
```

- Test path parameters, query parameters, and hashes independently.
- Determine exactly where `%2F`, `%5C`, `%2E`, and double-encoded forms decode or re-encode.
- Instrument `fetch`, XHR, Axios, router navigation, and server-side fetch wrappers to capture the final URL.
- Escalate only after identifying the sink: state-changing API for CSRF-like impact, HTML/attachment response rendered in an unsafe sink for XSS, or server-side fetch for SSRF.
- Do not assume the same framework API behaves identically in client components, server components, and route handlers.

### XS-Leaks and Cross-Origin Oracles

Inventory observable signals that do not require reading the cross-origin response:

- load/error events for script, image, stylesheet, frame, media, and module elements
- timing, connection reuse, cache state, redirect count, and navigation success
- window/frame count, focus, history length, and resource dimensions
- browser-generated error pages and status-dependent behavior
- request headers such as `Sec-Fetch-Dest`, `Sec-Fetch-Mode`, and `Origin`

Test controls such as ORB, CORP, COEP, and MIME enforcement. A service worker or alternate fetch path can change request destination metadata and therefore change whether a blocked response becomes a network error or an empty response. Validate the oracle across authenticated and unauthenticated control cases.

### Service Workers and Caches

- Map service-worker registration scope, update lifecycle, controller acquisition, and fetch handlers.
- Inspect Cache API keys and responses; determine whether HTML or JavaScript is served directly from a writable cache.
- Test whether a constrained script context can poison app-managed cache entries later consumed by a normal page or service worker.
- Treat service-worker persistence as high impact, but prove registration/control scope and update survivability.
- Compare a direct subresource request with the same request proxied through `fetch(event.request)`; request destination and mode can differ.

### Web Workers and Constrained Script Execution

When script runs inside a worker, inventory capabilities instead of dismissing it as low impact:

- credentialed same-origin `fetch` for data access and state changes
- `postMessage` gadgets into the main page
- IndexedDB and Cache API shared with other same-origin contexts
- Blob construction and object URLs
- import mechanisms, WebSocket, and available browser-specific APIs

Prove the strongest reliable capability first. If escalation requires a user gesture, document the exact gesture, timing, browser, and visibility rather than calling it zero-click XSS.

### Navigation and Redirect Control

- Distinguish HTTP 30x, script navigation, form submission, meta refresh, and popup navigation.
- Test invalid or blocked URL schemes and WAF-generated error pages only when they support a real flow. Oversized URLs/headers, cookie-path-specific header inflation, redirect limits, and navigation throttling are restartable-lab-only tests with strict size/iteration limits and health checks.
- A sandbox inherited by a new top-level context can selectively block forms, scripts, popups, or navigation; enumerate the exact flag set.
- Preserve and inspect history when a built-in error page replaces the active document; do not assume the errored URL is lost.

### CSP and Browser Parsing

- Evaluate the delivered policy on the exact response, including redirects and error/API/static paths.
- Map nonces, hashes, `strict-dynamic`, allowed schemes, trusted script gadgets, `base-uri`, `frame-ancestors`, and Trusted Types.
- Test parser namespaces and repairs in HTML, SVG, and MathML. A protected attribute or sanitizer rule in the HTML namespace may behave differently after namespace transitions.
- Treat scriptless disclosure of a nonce or trusted URL as a primitive; prove a second controllable sink before claiming bypass.
- For response splitting, consider whether a same-origin endpoint can be turned into a script resource with a controlled body length or framing.

### JavaScript Gadget Discovery

- When direct calls are blocked, inspect implicit coercions (`toString`, `valueOf`, iterators, getters, proxies) and callbacks invoked by accessible library functions.
- Search for functions whose `this` object and arguments can be attacker-shaped.
- Build a bounded harness to enumerate reachable globals and observe property reads/calls; avoid assuming one library gadget is universal.
- Validate the complete call chain to a dangerous sink such as navigation, HTML insertion, `eval`, `Function`, or a privileged API.

## Reconnaissance

### Runtime Instrumentation

Instrument in a controlled browser session:

```javascript
const realFetch = window.fetch;
window.fetch = (...args) => {
  const input = args[0];
  const rawUrl = typeof input === 'string' ? input : input.url;
  const url = new URL(rawUrl, location.href);
  const method = args[1]?.method || input?.method || 'GET';
  console.log('fetch', {method, origin: url.origin, path: url.pathname});
  return realFetch(...args);
};

window.addEventListener('message', e => {
  const keys = e.data && typeof e.data === 'object' ? Object.keys(e.data) : [];
  console.log('message', {origin: e.origin, sourceMatches: e.source === window.opener, keys});
}, true);
```

Use the wrapper only in the controlled profile and restore `window.fetch = realFetch` afterward. Do not log bodies, message values, credentials, or query strings.

Also inspect DevTools network initiators, service workers, storage, CSP violations, frame tree, and navigation history. Use raw browser behavior for validation; command-line HTTP clients cannot reproduce origin/window/worker semantics.

### Source Review

- Search for `postMessage`, message listeners, `window.open`, named targets, opener/parent access, frame creation, and sandbox attributes.
- Search for router parameter APIs flowing into `fetch`, Axios, navigation, or HTML rendering.
- Search for service-worker registration, Cache API writes, worker constructors, Blob URLs, and dynamic imports.
- Search for raw HTML sinks and trust escape hatches in every supported frontend framework.
- Compare CSP and framing headers across document, API, static, callback, redirect, and error routes.

## Testing Methodology

1. **Define the browser state** - Origin/site, context graph, policies, workers, storage, and activation.
2. **Identify a source and observable sink** - Message, URL component, cache entry, navigation, load/error event, or implicit call.
3. **Trace transformations** - URL parsing, framework decode, browser normalization, request destination, and document replacement.
4. **Build paired controls** - Same-origin/cross-origin, status success/error, worker/direct, unique/predictable window name, encoded/raw path.
5. **Prove the primitive** - Data transfer, path change, state oracle, cache modification, or context capture.
6. **Escalate deliberately** - Chain to a privileged action, sensitive disclosure, SSRF, or executable DOM sink.
7. **Cross-browser check** - At minimum record Chromium/Firefox/Safari applicability when the primitive is browser-specific.
8. **State interaction requirements** - Click, drag, popup permission, timing window, login state, and visual deception.

## Validation

1. Capture the context graph and relevant policies at exploit time.
2. Show the exact browser-parsed origin or final request URL, not just the attacker-supplied string.
3. For postMessage, prove both message origin and source/context ownership.
4. For XS-Leaks, repeat randomized success/failure trials and quantify separation and noise.
5. For workers/caches, show which later context consumes the modified data.
6. For client-side traversal, capture the final network request and the security-relevant response/action.
7. For interaction-dependent chains, provide a screen recording or deterministic event trace.

## False Positives

- A message reaches a listener but fails schema, origin, source, or state validation before any action
- A router decodes traversal characters but the value never reaches a URL/path sink
- Different load/error behavior caused by unstable network rather than protected state
- Worker script execution with no sensitive API, shared state, main-thread gadget, or meaningful action
- CSP nonce disclosure without a controllable way to reuse it in an executable sink
- Named-window collision blocked by origin scoping, randomized names, COOP, or `noopener`
- Browser-specific behavior reported without the required version, flag, or user interaction

## Pro Tips

1. Treat browsing-context names as attacker-contestable identifiers unless randomized.
2. Query parameters are usually decoded automatically; path parameters vary by router and execution context.
3. Compare request metadata, not just URLs. Service workers can alter destination/mode semantics.
4. A strict origin check does not compensate for attacker control of the supposedly trusted window reference.
5. Error pages, redirects, and blocked frames still mutate history and context relationships.
6. Keep browser-version claims narrow and retest; these behaviors change faster than server-side primitives.
7. Prefer a small state-machine explanation over a large payload catalog.

## Summary

Browser exploitation is state-machine exploitation. Map origins, context references, policies, workers, storage, navigation, and decoding as one system. Prove each state transition with browser evidence, then chain only the primitives that survive the target's browser and interaction constraints.
