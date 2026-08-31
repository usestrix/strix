---
name: api-security-testing
description: Security-test a REST, GraphQL, or gRPC API with Strix — autonomous agents that enumerate endpoints from an OpenAPI/GraphQL schema (or by crawling), then actually exploit the API-specific vulnerability classes in the OWASP API Security Top 10 (2023) — broken object-level authorization (BOLA/IDOR), broken object property level authorization (excessive data exposure and mass assignment), broken function-level authorization, unrestricted resource consumption, SSRF, injection, and auth/token flaws. Every finding comes with a working proof-of-concept request. Use when the user asks to pentest, security-test, audit, or find vulnerabilities in an API, endpoint, or backend service.
license: Apache-2.0
metadata:
  author: usestrix
  homepage: https://docs.strix.ai
---

# Security-test an API

APIs fail differently from web UIs: there is no rendered surface to crawl, the interesting bugs are authorization-shaped rather than injection-shaped, and the same endpoint behaves differently per token. This workflow targets those specifics with Strix's autonomous agents, using the current [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) as the coverage checklist. For the web-app equivalent, the current edition is the OWASP Top 10:2025 — see **owasp-top-10-testing**.

Install, LLM setup, full CLI flags, and the managed-cloud path are in the **penetration-testing-with-strix** skill. Read it if `strix --version` fails or the target is not an API.

## 1. Gather what the agents need

APIs are near-impossible to test blind, so collect first:

| Input | Why it matters |
|---|---|
| **Schema** — OpenAPI/Swagger file, Postman collection, GraphQL endpoint (introspection), or a gRPC `.proto` | Turns guesswork into full endpoint enumeration. Biggest single win in coverage. An OpenAPI/Swagger or Postman spec (`.json`/`.yaml`/`.yml`) is a target Strix takes directly; a `.proto` is not, so pass it with `--workspace-file`. |
| **Two sets of credentials/tokens**, ideally in different tenants | BOLA/IDOR — API1:2023, still the #1 API risk — can only be *proven* by accessing tenant A's objects with tenant B's token. |
| **A low-privilege and a high-privilege token** | Required to prove broken function-level authorization (API5:2023 — a `user` calling admin-only routes). |
| **Example object IDs** | Lets agents test ID tampering immediately instead of hunting for valid identifiers. |
| **Out-of-scope routes** | Payments, mass notification, destructive admin endpoints. |
| **Rate limits / WAF** in front of the API | Avoids agents burning budget on throttled requests; mention them so testing adapts. |

Ask the user for anything missing — do not fabricate tokens or scan an API they do not own.

## 2. Run the scan

Pass the spec as a **target**, not as prose in the instruction — Strix parses OpenAPI/Swagger (`.json`/`.yaml`) and Postman collection exports directly, so the agents start from the real endpoint list:

```bash
strix -n -t ./openapi.yaml -t https://api.staging.example.com --max-budget 20 \
  --instruction "Tenant A token: <tokenA> (org 1111, user id 11, order id 501).
Tenant B token: <tokenB> (org 2222, user id 22).
Admin token: <tokenAdmin>.
Focus: BOLA across orgs (API1), function-level authz on /admin/* (API5), object property level authz on PATCH /users/{id} — both mass assignment and over-exposed fields in list responses (API3), unrestricted resource consumption (API4).
Out of scope: POST /billing/*, POST /notifications/broadcast."
```

- **Postman instead of OpenAPI:** a collection export works as a target (`-t ./collection.postman_collection.json`), or pull one live with `-t postman://<collection-uuid>` (optionally `"postman://<collection-uuid>?env=<environment-uuid>"`), which needs `POSTMAN_API_KEY` in the environment.
- **Many services at once:** put one target per line in a file and pass `--target-list ./targets.txt`, repeatable and combinable with `-t`.
- **Add the backend source for depth:** `-t ./services/api -t https://api.staging.example.com`. With code access the agents can reason about authorization checks and object ownership rather than inferring them from responses.
- **gRPC:** target the endpoint and pass the definition as a workspace file, `-t https://grpc.staging.example.com --workspace-file ./service.proto`. Only `.json`, `.yaml`, and `.yml` specs are recognized as targets, so `-t ./service.proto` fails with "Path exists but is not a directory".
- **GraphQL:** point at the GraphQL endpoint and say whether introspection is enabled; call out that you want batching/aliasing abuse, depth/complexity limits, and per-field authorization tested.
- **Internal/private APIs** unreachable from your machine: use the managed platform's network connector — see **managed-pentesting-with-strix**.
- Use `--instruction-file` when the credential/context block gets long, and keep tokens out of shell history and out of committed files.
- **Supporting files** the agents should read but not test, such as an endpoint wordlist or handwritten notes about the tenancy model: pass `--workspace-file ./notes.md`. The file lands read-only in `/workspace`. Add `:DEST` to choose the path, for example `--workspace-file ./wordlist.txt:lists/wordlist.txt`.

## 3. Verify findings

`strix_runs/<run>/penetration_test_report.md` first, then `vulnerabilities/*.md` — each contains the exact request that proved the issue. Replay it (for example, with `curl`) before reporting; for authorization findings, confirm the response really contains the other tenant's data rather than an empty 200.

`findings.sarif` uploads to GitHub code scanning; `vulnerabilities.json` is the structured index for ticketing.

## 4. Fix, re-test, and keep it tested

Remediate with **fix-security-vulnerabilities-with-strix** (fix the authorization check, not the single endpoint), then re-run against the same target to prove the exploit is dead. Wire it into pull-request CI with **ci-security-scanning-with-strix** so new endpoints get tested as they ship.
