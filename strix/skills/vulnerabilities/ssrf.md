# SERVER-SIDE REQUEST FORGERY (SSRF)

## Critical

SSRF enables the server to reach networks and services the attacker cannot. Focus on cloud metadata endpoints, service meshes, Kubernetes, and protocol abuse to turn a single fetch into credentials, lateral movement, and sometimes RCE.

## Scope

- Outbound HTTP/HTTPS fetchers (proxies, previewers, importers, webhook testers)
- Non-HTTP protocols via URL handlers (gopher, dict, file, ftp, smb wrappers)
- Service-to-service hops through gateways and sidecars (envoy/nginx)
- Cloud and platform metadata endpoints, instance services, and control planes

## Methodology

1. Identify every user-influenced URL/host/path across web/mobile/API and background jobs. Include headers that trigger server-side fetches (link previews, analytics, crawler hooks).
2. Establish a quiet oracle first (OAST DNS/HTTP callbacks). Then pivot to internal addressing (loopback, RFC1918, link-local, IPv6, hostnames) and protocol variations.
3. Enumerate redirect behavior, header propagation, and method control (GET-only vs arbitrary). Test parser differentials across frameworks, CDNs, and language libraries.
4. Target high-value services (metadata, kubelet, Redis, FastCGI, Docker, Vault, internal admin panels). Chain to write/exec primitives if possible.

## Injection Surfaces

- Direct URL params: url=, link=, fetch=, src=, webhook=, avatar=, image=
- Indirect sources: Open Graph/link previews, PDF/image renderers, server-side analytics (Referer trackers), import/export jobs, webhooks/callback verifiers
- Protocol-translating services: PDF via wkhtmltopdf/Chrome headless, image pipelines, document parsers, SSO validators, archive expanders
- Less obvious: GraphQL resolvers that fetch by URL, background crawlers, repository/package managers (git, npm, pip), calendar (ICS) fetchers

## Cloud And Platforms

### Aws

- IMDSv1: http://169.254.169.254/latest/meta-data/ → `/iam/security-credentials/{role}`, `/user-data`
- IMDSv2: requires token via PUT `/latest/api/token` with header `X-aws-ec2-metadata-token-ttl-seconds`, then include `X-aws-ec2-metadata-token` on subsequent GETs. If the sink cannot set headers or methods, fallback to other targets or seek intermediaries that can
- ECS/EKS task credentials: `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`

### Gcp

- Endpoint: http://metadata.google.internal/computeMetadata/v1/
- Required header: `Metadata-Flavor: Google`
- Target: `/instance/service-accounts/default/token`

### Azure

- Endpoint: http://169.254.169.254/metadata/instance?api-version=2021-02-01
- Required header: `Metadata: true`
- MSI OAuth: `/metadata/identity/oauth2/token`

### Kubernetes

- Kubelet: 10250 (authenticated) and 10255 (deprecated read-only). Probe `/pods`, `/metrics`, exec/attach endpoints
- API server: https://kubernetes.default.svc/. Authorization often needs the service account token; SSRF that propagates headers/cookies may reuse them
- Service discovery: attempt cluster DNS names (svc.cluster.local) and default services (kube-dns, metrics-server)

## Internal Targets

- Docker API: http://localhost:2375/v1.24/containers/json (no TLS variants often internal-only)
- Redis/Memcached: dict://localhost:11211/stat, gopher payloads to Redis on 6379
- Elasticsearch/OpenSearch: http://localhost:9200/_cat/indices
- Message brokers/admin UIs: RabbitMQ, Kafka REST, Celery/Flower, Jenkins crumb APIs
- FastCGI/PHP-FPM: gopher://localhost:9000/ (craft records for file write/exec when app routes to FPM)

## Protocol Exploitation

### Gopher

- Speak raw text protocols (Redis/SMTP/IMAP/HTTP/FCGI). Use to craft multi-line payloads, schedule cron via Redis, or build FastCGI requests

### File And Wrappers

- file:///etc/passwd, file:///proc/self/environ when libraries allow file handlers
- jar:, netdoc:, smb:// and language-specific wrappers (php://, expect://) where enabled

### Parser And Filter Bypasses

#### Address Variants

- Loopback: 127.0.0.1, 127.1, 2130706433, 0x7f000001, ::1, [::ffff:127.0.0.1]
- RFC1918/link-local: 10/8, 172.16/12, 192.168/16, 169.254/16; test IPv6-mapped and mixed-notation forms

#### Url Confusion

- Userinfo and fragments: http://internal@attacker/ or http://attacker#@internal/
- Scheme-less/relative forms the server might complete internally: //169.254.169.254/
- Trailing dots and mixed case: internal. vs INTERNAL, Unicode dot lookalikes

#### Redirect Behavior

- Allowlist only applied pre-redirect: 302 from attacker → internal host. Test multi-hop and protocol switches (http→file/gopher via custom clients)

#### Header And Method Control

- Some sinks reflect or allow CRLF-injection into the request line/headers; if arbitrary headers/methods are possible, IMDSv2, GCP, and Azure become reachable

#### Blind And Mapping

- Use OAST (DNS/HTTP) to confirm egress. Derive internal reachability from timing, response size, TLS errors, and ETag differences
- Build a port map by binary searching timeouts (short connect/read timeouts yield cleaner diffs)

#### Chaining

- SSRF → Metadata creds → cloud API access (list buckets, read secrets)
- SSRF → Redis/FCGI/Docker → file write/command execution → shell
- SSRF → Kubelet/API → pod list/logs → token/secret discovery → lateral

#### Validation

1. Prove an outbound server-initiated request occurred (OAST interaction or internal-only response differences).
2. Show access to non-public resources (metadata, internal admin, service ports) from the vulnerable service.
3. Where possible, demonstrate minimal-impact credential access (short-lived token) or a harmless internal data read.
4. Confirm reproducibility and document request parameters that control scheme/host/headers/method and redirect behavior.

#### False Positives

- Client-side fetches only (no server request)
- Strict allowlists with DNS pinning and no redirect following
- SSRF simulators/mocks returning canned responses without real egress
- Blocked egress confirmed by uniform errors across all targets and protocols

#### Impact

- Cloud credential disclosure with subsequent control-plane/API access
- Access to internal control panels and data stores not exposed publicly
- Lateral movement into Kubernetes, service meshes, and CI/CD
- RCE via protocol abuse (FCGI, Redis), Docker daemon access, or scriptable admin interfaces

#### Pro Tips

1. Prefer OAST callbacks first; then iterate on internal addressing and protocols.
2. Test IPv6 and mixed-notation addresses; filters often ignore them.
3. Observe library/client differences (curl, Java HttpClient, Node, Go); behavior changes across services and jobs.
4. Redirects are leverage: control both the initial allowlisted host and the next hop.
5. Metadata endpoints require headers/methods; verify if your sink can set them or if intermediaries add them for you.
6. Use tiny payloads and tight timeouts to map ports with minimal noise.
7. When responses are masked, diff length/ETag/status and TLS error classes to infer reachability.
8. Chain quickly to durable impact (short-lived tokens, harmless internal reads) and stop there.

#### Remember

Any feature that fetches remote content on behalf of a user is a potential tunnel to internal networks and control planes. Bind scheme/host/port/headers explicitly or expect an attacker to route through them.
