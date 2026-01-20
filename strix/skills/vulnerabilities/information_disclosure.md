# INFORMATION DISCLOSURE

## Critical

Information leaks accelerate exploitation by revealing code, configuration, identifiers, and trust boundaries. Treat every response byte, artifact, and header as potential intelligence. Minimize, normalize, and scope disclosure across all channels.

## Scope

- Errors and exception pages: stack traces, file paths, SQL, framework versions
- Debug/dev tooling reachable in prod: debuggers, profilers, feature flags
- DVCS/build artifacts and temp/backup files: .git, .svn, .hg, .bak, .swp, archives
- Configuration and secrets: .env, phpinfo, appsettings.json, Docker/K8s manifests
- API schemas and introspection: OpenAPI/Swagger, GraphQL introspection, gRPC reflection
- Client bundles and source maps: webpack/Vite maps, embedded env, __NEXT_DATA__, static JSON
- Headers and response metadata: Server/X-Powered-By, tracing, ETag, Accept-Ranges, Server-Timing
- Storage/export surfaces: public buckets, signed URLs, export/download endpoints
- Observability/admin: /metrics, /actuator, /health, tracing UIs (Jaeger, Zipkin), Kibana, Admin UIs
- Directory listings and indexing: autoindex, sitemap/robots revealing hidden routes
- Cross-origin signals: CORS misconfig, Referrer-Policy leakage, Expose-Headers
- File/document metadata: EXIF, PDF/Office properties

## Methodology

1. Build a channel map: Web, API, GraphQL, WebSocket, gRPC, mobile, background jobs, exports, CDN.
2. Establish a diff harness: compare owner vs non-owner vs anonymous across transports; normalize on status/body length/ETag/headers.
3. Trigger controlled failures: send malformed types, boundary values, missing params, and alternate content-types to elicit error detail and stack traces.
4. Enumerate artifacts: DVCS folders, backups, config endpoints, source maps, client bundles, API docs, observability routes.
5. Correlate disclosures to impact: versions→CVE, paths→LFI/RCE, keys→cloud access, schemas→auth bypass, IDs→IDOR.

## Surfaces

### Errors And Exceptions

- SQL/ORM errors: reveal table/column names, DBMS, query fragments
- Stack traces: absolute paths, class/method names, framework versions, developer emails
- Template engine probes: `{{7*7}}, ${7*7}` identify templating stack and code paths
- JSON/XML parsers: type mismatches and coercion logs leak internal model names

### Debug And Env Modes

- Debug pages and flags: Django DEBUG, Laravel Telescope, Rails error pages, Flask/Werkzeug debugger, ASP.NET customErrors Off
- Profiler endpoints: /debug/pprof, /actuator, /_profiler, custom /debug APIs
- Feature/config toggles exposed in JS or headers; admin/staff banners in HTML

### Dvcs And Backups

- DVCS: /.git/ (HEAD, config, index, objects), .svn/entries, .hg/store → reconstruct source and secrets
- Backups/temp: .bak/.old/~/.swp/.swo/.tmp/.orig, db dumps, zipped deployments under /backup/, /old/, /archive/
- Build artifacts: dist artifacts containing .map, env prints, internal URLs

### Configs And Secrets

- Classic: web.config, appsettings.json, settings.py, config.php, phpinfo.php
- Containers/cloud: Dockerfile, docker-compose.yml, Kubernetes manifests, service account tokens, cloud credentials files
- Credentials and connection strings; internal hosts and ports; JWT secrets

### Api Schemas And Introspection

- OpenAPI/Swagger: /swagger, /api-docs, /openapi.json — enumerate hidden/privileged operations
- GraphQL: introspection enabled; field suggestions; error disclosure via invalid fields; persisted queries catalogs
- gRPC: server reflection exposing services/messages; proto download via reflection

### Client Bundles And Maps

- Source maps (.map) reveal original sources, comments, and internal logic
- Client env leakage: NEXT_PUBLIC_/VITE_/REACT_APP_ variables; runtime config; embedded secrets accidentally shipped
- Next.js data: __NEXT_DATA__ and pre-fetched JSON under /_next/data can include internal IDs, flags, or PII
- Static JSON/CSV feeds used by the UI that bypass server-side auth filtering

### Headers And Response Metadata

- Fingerprinting: Server, X-Powered-By, X-AspNet-Version
- Tracing: X-Request-Id, traceparent, Server-Timing, debug headers
- Caching oracles: ETag/If-None-Match, Last-Modified/If-Modified-Since, Accept-Ranges/Range (partial content reveals)
- Content sniffing and MIME metadata that implies backend components

### Storage And Exports

- Public object storage: S3/GCS/Azure blobs with world-readable ACLs or guessable keys
- Signed URLs: long-lived, weakly scoped, re-usable across tenants; metadata leaks in headers
- Export/report endpoints returning foreign data sets or unfiltered fields

### Observability And Admin

- Metrics: Prometheus /metrics exposing internal hostnames, process args, SQL, credentials by mistake
- Health/config: /actuator/health, /actuator/env, Spring Boot info endpoints
- Tracing UIs and dashboards: Jaeger/Zipkin/Kibana/Grafana exposed without auth

### Directory And Indexing

- Autoindex on /uploads/, /files/, /logs/, /tmp/, /assets/
- Robots/sitemap reveal hidden paths, admin panels, export feeds

### Cross Origin Signals

- Referrer leakage: missing/referrer policy leading to path/query/token leaks to third parties
- CORS: overly permissive Access-Control-Allow-Origin/Expose-Headers revealing data cross-origin; preflight error shapes

### File Metadata

- EXIF, PDF/Office properties: authors, paths, software versions, timestamps, embedded objects

## Advanced Techniques

### Differential Oracles

- Compare owner vs non-owner vs anonymous for the same resource and track: status, length, ETag, Last-Modified, Cache-Control
- HEAD vs GET: header-only differences can confirm existence or type without content
- Conditional requests: 304 vs 200 behaviors leak existence/state; binary search content size via Range requests

### Cdn And Cache Keys

- Identity-agnostic caches: CDN/proxy keys missing Authorization/tenant headers → cross-user cached responses
- Vary misconfiguration: user-agent/language vary without auth vary leaks alternate content
- 206 partial content + stale caches leak object fragments

### Cross Channel Mirroring

- Inconsistent hardening between REST, GraphQL, WebSocket, and gRPC; one channel leaks schema or fields hidden in others
- SSR vs CSR: server-rendered pages omit fields while JSON API includes them; compare responses

### Introspection And Reflection

- GraphQL: disabled introspection still leaks via errors, fragment suggestions, and client bundles containing schema
- gRPC reflection: list services/messages and infer internal resource names and flows

### Cloud Specific

- S3/GCS/Azure: anonymous listing disabled but object reads allowed; metadata headers leak owner/project identifiers
- Pre-signed URLs: audience not bound; observe key scope and lifetime in URL params

## Usefulness Assessment

- Actionable signals:
  - Secrets/keys/tokens that grant new access (DB creds, cloud keys, JWT signing/refresh, signed URL secrets)
  - Versions with a reachable, unpatched CVE on an exposed path
  - Cross-tenant identifiers/data or per-user fields that differ by principal
  - File paths, service hosts, or internal URLs that enable LFI/SSRF/RCE pivots
  - Cache/CDN differentials (Vary/ETag/Range) that expose other users' content
  - Schema/introspection revealing hidden operations or fields that return sensitive data
- Likely benign or intended:
  - Public docs or non-sensitive metadata explicitly documented as public
  - Generic server names without precise versions or exploit path
  - Redacted/sanitized fields with stable length/ETag across principals
  - Per-user data visible only to the owner and consistent with privacy policy

## Triage Rubric

- Critical: Credentials/keys; signed URL secrets; config dumps; unrestricted admin/observability panels
- High: Versions with reachable CVEs; cross-tenant data; caches serving cross-user content; schema enabling auth bypass
- Medium: Internal paths/hosts enabling LFI/SSRF pivots; source maps revealing hidden endpoints/IDs
- Low: Generic headers, marketing versions, intended documentation without exploit path
- Guidance: Always attempt a minimal, reversible proof for Critical/High; if no safe chain exists, document precise blocker and downgrade

## Escalation Playbook

- If DVCS/backups/configs → extract secrets; test least-privileged read; rotate after coordinated disclosure
- If versions → map to CVE; verify exposure; execute minimal PoC under strict scope
- If schema/introspection → call hidden/privileged fields with non-owner tokens; confirm auth gaps
- If source maps/client JSON → mine endpoints/IDs/flags; pivot to IDOR/listing; validate filtering
- If cache/CDN keys → demonstrate cross-user cache leak via Vary/ETag/Range; escalate to broken access control
- If paths/hosts → target LFI/SSRF with harmless reads (e.g., /etc/hostname, metadata headers); avoid destructive actions
- If observability/admin → enumerate read-only info first; prove data scope breach; avoid write/exec operations

## Exploitation Chains

### Credential Extraction

- DVCS/config dumps exposing secrets (DB, SMTP, JWT, cloud)
- Keys → cloud control plane access; rotate and verify scope

### Version To Cve

1. Derive precise component versions from headers/errors/bundles.
2. Map to known CVEs and confirm reachability.
3. Execute minimal proof targeting disclosed component.

### Path Disclosure To Lfi

1. Paths from stack traces/templates reveal filesystem layout.
2. Use LFI/traversal to fetch config/keys.
3. Prove controlled access without altering state.

### Schema To Auth Bypass

1. Schema reveals hidden fields/endpoints.
2. Attempt requests with those fields; confirm missing authorization or field filtering.

## Validation

1. Provide raw evidence (headers/body/artifact) and explain exact data revealed.
2. Determine intent: cross-check docs/UX; classify per triage rubric (Critical/High/Medium/Low).
3. Attempt minimal, reversible exploitation or present a concrete step-by-step chain (what to try next and why).
4. Show reproducibility and minimal request set; include cross-channel confirmation where applicable.
5. Bound scope (user, tenant, environment) and data sensitivity classification.

## False Positives

- Intentional public docs or non-sensitive metadata with no exploit path
- Generic errors with no actionable details
- Redacted fields that do not change differential oracles (length/ETag stable)
- Version banners with no exposed vulnerable surface and no chain
- Owner-visible-only details that do not cross identity/tenant boundaries

## Impact

- Accelerated exploitation of RCE/LFI/SSRF via precise versions and paths
- Credential/secret exposure leading to persistent external compromise
- Cross-tenant data disclosure through exports, caches, or mis-scoped signed URLs
- Privacy/regulatory violations and business intelligence leakage

## Pro Tips

1. Start with artifacts (DVCS, backups, maps) before payloads; artifacts yield the fastest wins.
2. Normalize responses and diff by digest to reduce noise when comparing roles.
3. Hunt source maps and client data JSON; they often carry internal IDs and flags.
4. Probe caches/CDNs for identity-unaware keys; verify Vary includes Authorization/tenant.
5. Treat introspection and reflection as configuration findings across GraphQL/gRPC; validate per environment.
6. Mine observability endpoints last; they are noisy but high-yield in misconfigured setups.
7. Chain quickly to a concrete risk and stop—proof should be minimal and reversible.

## Remember

Information disclosure is an amplifier. Convert leaks into precise, minimal exploits or clear architectural risks.
