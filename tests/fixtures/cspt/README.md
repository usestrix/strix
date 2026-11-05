# CSPT fixtures

Minimal HTML pages exercising client-side path traversal (CSPT) source to sink
flows, used by `tests/test_cspt_fixtures.py` as a deterministic, browser-free
regression for what CSPT looks like in client code. Unlike a Playwright
capture test, these run in ordinary CI with no Chromium.

Naming: `positive_*` has the CSPT **primitive** — an attacker-controlled client
source (URL query, fragment, referrer, postMessage, storage) reaches a request
sink's path unguarded. That is the source-to-sink reachability only; whether the
redirected request is *exploitable* (a state change, a rendered response, an
internal fetch, an authz bypass) is a separate step, per the exploitability bar
in the `client_side_path_traversal` skill. `negative_*` is a control — the flow
is validated, or the user value never reaches the request path.

Convention the test relies on: the attacker-controlled value that reaches a
sink is named `userPath`, so a sink-call line containing `userPath` marks a
tainted flow. The sources, sinks, and mitigation markers the matcher keys on
are listed at the top of `tests/test_cspt_fixtures.py`.
