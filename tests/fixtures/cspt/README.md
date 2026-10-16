# CSPT test fixtures

Self-contained HTML+JS apps exercising Client-Side Path Traversal (CSPT)
detection. Each file is a single static page with no server dependency — a
CSPT specialist can drive them with the `agent_browser` CLI (routed through the
Caido proxy) exactly as it would a real target, and the automated tests in
`tests/test_cspt_skill.py` assert their structural properties so they cannot
silently rot.

Every app builds a same-origin request URL by joining a **client-side source**
into a request **path** and sending it via a browser request sink (`fetch` /
`XMLHttpRequest` / `axios`-style). The distinction between positive and negative
is whether the resulting path is validated before it reaches the sink.

## Positive fixtures (a real CSPT — source flows unvalidated into the path)

| File | Source | Sink | Traversal style |
|------|--------|------|-----------------|
| `positive_direct.html` | URL fragment (`location.hash`) | `fetch` | direct `../` |
| `positive_encoded.html` | query param (`?resource=`) | `XMLHttpRequest` | URL-encoded `%2e%2e%2f` |
| `positive_normalized.html` | route segment (`location.pathname`) | `fetch` | self-collapsing `....//` |
| `positive_postmessage.html` | `postMessage` `event.data` (no origin check) | `fetch` | direct `../` |
| `positive_storage.html` | `localStorage` value | `axios`-style wrapper | direct `../` |

## Negative fixtures (safe — not CSPT)

| File | Why it's safe |
|------|---------------|
| `negative_validated.html` | Segment matched against a strict allowlist / `^[a-z0-9-]+$` before use; traversal rejected. |
| `negative_safe_construction.html` | Endpoint path is a constant; the client value only becomes a **query parameter**, never part of the path. |

## How to drive one manually (evidence runbook)

See `docs/cspt-evidence-runbook.md` for the full browser + Caido proxy procedure
that produces the request-path evidence a confirmed finding requires.
