---
name: client-side-path-traversal
description: Client-Side Path Traversal (CSPT) testing — attacker-controlled client input steering the victim's own authenticated browser requests to unintended same-origin endpoints
---

# Client-Side Path Traversal (CSPT)

Client-Side Path Traversal happens **in the victim's browser**, not on the
server. Front-end JavaScript takes an attacker-influenceable client-side value
and concatenates it into the path of a request the browser then sends with the
victim's ambient credentials (cookies, `Authorization` headers set by the app,
session). By injecting `../` (or encoded / normalizing variants) into that value,
an attacker redirects the request to a **different same-origin endpoint** than the
developer intended — turning the victim's own browser into the request forger.

The bug is a **path join in client code**, and the impact is realized entirely by
the browser's URL normalization (`new URL()`, the fetch/XHR URL parser) collapsing
`../` before the request leaves the page. Treat every client-readable input that
flows into a request URL as untrusted; validate the *resulting path*, not the raw
segment.

CSPT is frequently a **gadget**, not a standalone bug: it lets an attacker point
an authenticated request at an endpoint whose JSON/HTML response is then fed into
a sink. Chained with a reflected/DOM XSS sink, a permissive CORS reader, or a
state-changing endpoint that trusts a weak/absent CSRF defense, a "read-only"
CSPT becomes account takeover or a stored-XSS delivery path.

## Not CSPT (route these elsewhere)

Keep this class clean. The following are **server-side** file/path issues covered
by the `path-traversal-lfi-rfi` skill — report them as `dynamic` findings, never
as `client_side_path_traversal`:

- **Server-side path traversal** — server code joins a request parameter into a
  filesystem path and reads/returns a file (`/download?file=../../etc/passwd`).
  The traversal is resolved by the *server's* filesystem, not the browser.
- **LFI / RFI** — server includes/executes a file whose name/URL is user-controlled
  (`php://filter`, remote include). Server-side execution.
- **Zip Slip / archive extraction** — server writes files outside a target dir.
- **SSRF** — server (not the browser) fetches an attacker-controlled URL.
- **Open redirect** — the browser is navigated (Location / `window.location`) to
  an attacker origin. CSPT stays *same-origin* and targets a request **path**, not
  a top-level navigation. If the sink is a navigation, it's `open-redirect`.

The discriminator: **who resolves the `../` and who sends the final request?**
If it's the victim's browser building a same-origin `fetch`/XHR path → CSPT. If
it's the server touching its filesystem or making an outbound request →
server-side traversal / LFI / RFI / SSRF.

## Sources (attacker-influenceable client input)

Any of these reaching a request-URL sink is a candidate taint source:

- **URL query params** — `URLSearchParams`, `location.search`, router query
  (`?next=`, `?id=`, `?path=`, `?tab=`, `?redirect=`).
- **URL path segments** — SPA route params parsed from `location.pathname`
  (`/orders/:id`, `react-router` / `vue-router` params).
- **Fragment / hash** — `location.hash`, hash-router segments. Never sent to the
  server, so server-side WAFs don't see it — a favorite CSPT source.
- **`document.referrer`** — attacker controls it by hosting the referring page.
- **`postMessage` data** — `event.data` from another window/iframe without an
  `event.origin` check.
- **Browser storage** — `localStorage`, `sessionStorage`, `IndexedDB`, cookies —
  when an earlier, attacker-influenceable flow seeded the value.
- **`window.name`**, **BroadcastChannel**, **WebSocket message payloads** — cross
  -context channels that survive navigation.

## Sinks (client request builders whose path is tainted)

The tainted value must land in the **path** portion (not just a query value) of:

- `fetch(url)` / `fetch(new Request(url))`
- `XMLHttpRequest.open(method, url)`
- `axios.get/post/... (url)`, an axios instance with a `baseURL`
- jQuery `$.ajax({url})`, `$.get`, `$.getJSON`, `$.load`
- `navigator.sendBeacon(url)`
- `new EventSource(url)`, `new WebSocket(url)`
- framework data layers that build a request path: Angular `HttpClient`,
  `HttpClient.get(\`/api/${seg}\`)`, RTK Query / SWR / react-query key→URL builders,
  GraphQL client `uri`.

The dangerous pattern is **template/`+` concatenation of a source into a path**:

```js
fetch("/api/users/" + userId + "/avatar")        // userId from location.hash
fetch(`/api/${tab}/settings`)                     // tab from ?tab=
axios.get("/api/orders/" + params.id)             // id from route param
xhr.open("GET", baseApi + "/" + segment)          // segment from postMessage
```

If `userId` = `../../admin/keys#`, the browser normalizes
`/api/users/../../admin/keys` → `/api/admin/keys`, sent with the victim's session.

## Reconnaissance

### Surface map

- Grep client bundles for the sinks above joined with a source. In `agent_browser`:
  ```bash
  agent-browser open <target>
  # dump all script URLs, then fetch + grep them
  agent-browser eval "Array.from(document.scripts).map(s=>s.src).filter(Boolean)"
  ```
  Then pull each bundle and search for `fetch(`, `.open(`, `axios`, backtick URL
  templates, and `location.hash` / `URLSearchParams` / `postMessage` / referrer.
- Map every endpoint the SPA calls (record with the proxy, see Validation). Note
  which build their path from a client value vs. a constant.
- Identify **high-value sibling endpoints** reachable by traversal from a normal
  path (admin, other users' resources, token/key endpoints, state-changing POSTs).

### Capability probes

Inject into each candidate source and watch the **outbound request path** (via the
proxy), not the response body alone — the win condition is the browser sending a
path you didn't intend.

- **Direct**: `../`, `../../`, `..%2f` un-decoded, leading `/` (absolute-path
  override: `id=/admin/keys` → `/api//admin/keys` or an absolute join).
- **Encoded**: `%2e%2e%2f`, `%2e%2e/`, `..%2f`, double-encoded `%252e%252e%252f`
  when an app decodes before joining. The browser decodes `%2e`/`%2f` in the path
  during normalization — test both raw and encoded because framework routers may
  decode a layer first.
- **Normalized**: `....//` (folds to `../` after one collapse), `..././`,
  `.%2e/`, mixed `..\` on apps that rewrite backslashes, redundant `//` and `/./`
  segments that shift the base.
- **Base-relative vs root-relative**: confirm whether the app uses a relative
  base (`api/x`) or rooted (`/api/x`) — it changes how many `../` are needed and
  whether a leading `/` fully replaces the path.

## Validation (browser + Caido proxy)

Detection is dynamic: drive a real headless browser and read the **final outbound
request path** off the proxy. The `agent_browser` CLI auto-routes through the
Caido HTTP/HTTPS proxy (do **not** pass `--proxy`; it's wired via
`http_proxy`/`https_proxy`). See the `agent_browser` skill for the full CLI.

Runbook:

```bash
# 1. Load the page and (if needed) authenticate so requests carry a session.
agent-browser open <target>
agent-browser auth login <profile>          # or state load — see agent_browser skill

# 2. Start capturing traffic BEFORE triggering the sink.
agent-browser network har start

# 3. Drive the tainted source. Examples per source type:
#    - fragment:  navigate with a crafted hash
agent-browser open "<target>/#/orders/..%2f..%2fadmin%2fkeys"
#    - query:     open with a crafted param
agent-browser open "<target>/dashboard?tab=../../admin/config"
#    - postMessage: eval a crafted message into the vulnerable listener
cat <<'EOF' | agent-browser eval --stdin
window.postMessage({ path: "../../admin/keys" }, "*");
EOF

# 4. Let the request fire, then read what actually left the browser.
agent-browser wait --load networkidle
agent-browser network requests                 # inspect fired request URLs
agent-browser network har stop /workspace/.agent-browser-screenshots/cspt.har

# 5. Capture visual proof if the traversed response changes the page.
agent-browser screenshot
```

**Confirmation criteria** — you have a real CSPT when *all* hold:

1. The **outbound request path in the proxy/HAR** is the traversed target
   (`/api/admin/keys`), not the intended one (`/api/users/<id>/avatar`).
2. That request carried the **victim's credentials** (session cookie /
   `Authorization` header present on the request — read it from the HAR).
3. There is a **benign same-endpoint control**: the same flow with a normal
   value hits the intended path. Show both paths side by side.
4. The traversed endpoint returned data (or performed an action) the source
   value should not have been able to reach.

Record the request/response pair (method, full path, relevant headers, status)
from the HAR as evidence. Prefer reading a low-sensitivity sibling endpoint to
prove reach; do not exfiltrate real secrets — a status/length/shape delta is
enough proof.

## Reporting

File confirmed CSPT with `create_vulnerability_report` and:

- `finding_class="client_side_path_traversal"` — **required** so the finding is
  separated from server-side path traversal / LFI / RFI (which share the CWE but
  are a different class). Do not leave it `dynamic`.
- `cwe="CWE-22"` (Improper Limitation of a Pathname to a Restricted Directory).
- `title` prefixed **`Client-Side Path Traversal`** (e.g.
  `"Client-Side Path Traversal in order-detail fetch via URL fragment"`), so the
  class is obvious in the report/SARIF even to a human skimming titles.
- `evidence` — the two request paths (intended vs. traversed) from the proxy/HAR,
  with the credential header present, plus the benign control. Fenced code blocks.
- `poc_description` — steps to reproduce (navigate/craft source → observe path).
- `poc_script_code` — the crafted URL / `postMessage` / storage-seeding snippet.
- `impact` — name the concrete sibling endpoint reached and what it exposes or
  changes; if chained (XSS/CSRF/CORS), state the chain.
- CVSS — usually `AV:N`, `UI:R` (victim opens a link), `PR:N`; scope/impact
  depends on the reached endpoint.

## False positives

Not CSPT — do not report:

- The source is **validated to the resulting path**: an allowlist of endpoints,
  a strict `^[a-z0-9-]+$` segment check, or `encodeURIComponent` on a value used
  as a **single segment** *and* the app rejects/encodes `/` and `.` so traversal
  can't form. (`encodeURIComponent` alone is only safe when the value is one
  segment and `%2f`/`%2e` aren't decoded downstream — verify the outbound path.)
- **Safe path construction**: the endpoint path is a constant and the client
  value only ever becomes a **query parameter or request body field**, never part
  of the path. A tainted query value is not CSPT (it may be another bug).
- The browser **does not normalize** the value into a different path (confirm on
  the wire — no traversal actually occurred in the outbound request).
- The traversed request is **not** sent with ambient credentials (no session on
  that request), so there's no privilege to abuse — note it, don't over-rate it.
- Server rejects the traversed path (404/403) with no differential — no reach, no
  finding.

## Pro tips

1. Always judge on the **outbound request path in the proxy**, not the response —
   a 404 on the traversed path still proves the browser was steered, but a
   *successful* differential response is what makes it impactful.
2. The fragment (`location.hash`) is the strongest source: invisible to server
   WAFs/logs and fully attacker-controlled via a link.
3. Test both raw (`../`) and encoded (`%2e%2e%2f`) — SPA routers often decode one
   layer, so the effective payload differs by framework.
4. `....//` and other self-collapsing sequences bypass naive `replace("../","")`
   filters — a single non-recursive strip leaves a working `../`.
5. CSPT shines when chained. After proving reach, look for a reader sink (CORS,
   response rendered into DOM) or a state-changing target to escalate read-only
   traversal into real impact.
