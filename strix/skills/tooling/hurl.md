---
name: hurl
description: Reproducible, reviewable HTTP request chains and response assertions with Hurl for authorized multi-step security validation, vulnerable-versus-fixed regression cases, captured values, and low-rate semantic oracles
---

# Hurl Security Regression Playbook

Use [Hurl](https://hurl.dev/) when a security proof requires an ordered HTTP session whose requests, captured values, and assertions should be code-reviewed and replayed. It is well suited to authentication flows, redirects, cookies, CSRF tokens, upload lifecycles, patch regression, and paired semantic-differential cases.

Hurl sends exactly what the file describes. It does not make state-changing requests safe. Review scope, methods, targets, and captured secrets before every run.

## Install

Prefer an official release binary or package. On macOS:

```bash
brew install hurl
hurl --version
```

Official alternatives include release packages and `cargo install --locked hurl`; see [installation](https://hurl.dev/docs/installation.html). Record the tool version with results.

## Minimal Chain

```hurl
# lab-regression.hurl
GET {{base_url}}/session
HTTP 200
[Captures]
csrf: xpath "string(//input[@name='csrf']/@value)"
[Asserts]
header "Content-Type" startsWith "text/html"

POST {{base_url}}/action
Content-Type: application/x-www-form-urlencoded
[FormParams]
csrf: {{csrf}}
operation: noop
HTTP 204
```

Hurl keeps cookies across requests in the same file, so an explicit `Cookie` header is unnecessary here.

Run one reviewed case against one authorized target first:

```bash
hurl --test --jobs 1 --connect-timeout 5s --max-time 15s \
  --variable base_url=https://lab.example lab-regression.hurl
```

When credentials are required, pass them with `--secrets-file local-secrets.env`, keep that file outside version control, and avoid verbose/debug output that could expose headers or bodies. Use `--variables-file` only for non-secret environment values.

## Designing a Security Regression

- Assert the security invariant, not only a status code: denied identity, final normalized location, absence/presence of a structural field, unchanged object state, or exact benign result.
- Capture only values needed by later requests. Do not write tokens, personal data, or response bodies into committed reports.
- Encode a malformed but non-triggering control alongside the suspected case.
- Run the same file against vulnerable and fixed builds through `base_url` or other explicit variables.
- Keep state-changing methods in a clearly labeled lab/staging file; prefer no-op actions, inert markers, and cleanup requests.
- Check every redirect step when the vulnerability crosses routing, origin, or authentication boundaries. Blindly following redirects can hide the relevant transition.
- Use unique canaries so cached or pre-existing state cannot create a false positive.

## Chain Structure

Organize longer files around capability transitions:

```text
fingerprint -> establish session -> reach boundary -> prove primitive -> verify state -> cleanup
```

At each response, assert the condition required by the next request. A final success assertion cannot explain which earlier assumption failed.

Useful Hurl features include:

- captures from headers, cookies, JSONPath, XPath, and regex queries
- assertions over status, headers, body, JSON/XML, redirects, and timing
- request-local options and variables
- `--test` plus JSON, JUnit, TAP, or HTML reports

Consult the [Hurl manual](https://hurl.dev/docs/manual.html) for version-specific syntax instead of guessing an option.

## Safety Rules

- Use an explicit `base_url`; never derive the destination from untrusted response data without validating scheme, host, and port.
- Review POST/PUT/PATCH/DELETE requests and server-side side effects before replay.
- Set bounded timeouts and retries for the target; do not use polling as an unbounded brute-force loop.
- Do not use Hurl for raw HTTP parser/smuggling cases when its HTTP stack normalizes the bytes being tested; use an appropriate raw harness in an isolated lab.
- Use `--path-as-is` when literal `/../` or `/./` path segments are the behavior under test; otherwise Hurl's underlying URL handling can normalize them.
- Redact reports. HTML/JSON/JUnit artifacts may contain request URLs, headers, captured variables, and response snippets.
- Keep authentication material in local secret storage and use dedicated test accounts with minimum privilege.

## Validation Deliverable

1. reviewed `.hurl` file with variableized target and no embedded secrets
2. vulnerable, fixed, and negative-control environment descriptions
3. assertion at every capability transition
4. deterministic results with tool version and timestamps
5. side effects, cleanup, and residual-state check
6. redacted report appropriate for sharing
