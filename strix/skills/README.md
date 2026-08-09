# Strix Skills

## Overview

Skills are specialized knowledge packages that enhance Strix agents with deep expertise in specific vulnerability types, technologies, and testing methodologies. Each skill provides advanced techniques, practical examples, and validation methods that go beyond baseline security knowledge.

---

## Architecture

### How Skills Work

When an agent is created, it can load up to 5 specialized skills relevant to the specific subtask and context at hand:

```python
# Agent creation with specialized skills
create_agent(
    task="Test authentication mechanisms in API",
    name="Auth Specialist",
    skills="authentication_jwt,business_logic"
)
```

The skills are dynamically injected into the agent's system prompt, allowing it to operate with deep expertise tailored to the specific vulnerability types or technologies required for the task at hand. Every agent also receives its scan-mode skill, `tooling/agent_browser`, and `tooling/python` automatically (see `strix/agents/prompt.py`).

### Skill File Format

Every skill is a single Markdown file at `strix/skills/<category>/<name>.md` with YAML frontmatter:

```markdown
---
name: ssrf
description: SSRF testing for cloud metadata access, internal service discovery, and protocol smuggling
---

# SSRF

...
```

The frontmatter `description` is what agents see when choosing skills, so make it specific and searchable. The body should follow the sections used across the collection: Attack Surface, Reconnaissance, Key Vulnerabilities, Advanced Techniques, Testing Methodology, Validation, False Positives, Impact, Pro Tips, Tooling, and Summary.

---

## Skill Index

### `/vulnerabilities`

Advanced testing techniques for core vulnerability classes.

| Skill | Coverage |
|-------|----------|
| `authentication_jwt` | JWT/OIDC token forgery, algorithm confusion, claim manipulation |
| `broken_function_level_authorization` | BFLA, action-level authorization failures |
| `business_logic` | Workflow bypass, state manipulation, domain invariants |
| `command_injection` | OS command injection: in-band/blind detection, shell payloads, filter bypass, OAST |
| `cors_misconfiguration` | Origin reflection, null origin, credentialed reads, preflight gaps, missing Vary |
| `csrf` | Token bypass, SameSite cookies, state-changing request abuse |
| `header_injection` | CRLF/response splitting, cache poisoning, Host-header confusion |
| `http_request_smuggling` | CL.TE, TE.CL, H2 desync and smuggling techniques |
| `idor` | IDOR/BOLA object-level authorization failures |
| `information_disclosure` | Error messages, debug endpoints, metadata leakage |
| `insecure_deserialization` | Gadget chains across Java, Python, PHP, .NET, Ruby, Node |
| `insecure_file_uploads` | Extension bypass, content-type manipulation, traversal |
| `llm_prompt_injection` | Prompt injection, jailbreaks, tool/agent abuse |
| `mass_assignment` | Unauthorized field binding and privilege escalation |
| `nosql_injection` | MongoDB operators, auth bypass, blind extraction |
| `open_redirect` | Phishing pivots, OAuth token theft, allowlist bypass |
| `path_traversal_lfi_rfi` | Local/remote file inclusion and code execution |
| `prototype_pollution` | Object merge bugs, Node RCE chains, filter bypasses |
| `race_conditions` | TOCTOU, double-spend, concurrent state manipulation |
| `rce` | RCE umbrella: command injection, deserialization, template injection |
| `sql_injection` | Union, blind, error-based, ORM bypass |
| `ssrf` | Cloud metadata, internal discovery, protocol smuggling |
| `ssti` | Jinja/Mako/Velocity/Freemarker/Thymeleaf/Twig/EJS/ERB escapes |
| `subdomain_takeover` | Dangling DNS and unclaimed cloud resources |
| `weak_password_detection` | Credential stuffing, brute force, default credentials |
| `web_cache_poisoning` | Cache-key probing, unkeyed headers, parameter cloaking, cache deception |
| `xss` | Reflected, stored, DOM-based, CSP bypass |
| `xxe` | External entity injection, file disclosure, SSRF via XML |

### `/frameworks`

Specific testing methods for popular frameworks.

| Skill | Framework |
|-------|-----------|
| `django` | Django ORM injection, middleware gaps, auth/session flaws |
| `express` | Express/Node: prototype pollution, template injection, middleware order |
| `fastapi` | FastAPI: ASGI, dependency injection, API vulnerabilities |
| `flask` | Flask/Werkzeug: debug PIN RCE, session forgery, SSTI |
| `laravel` | Laravel/PHP: APP_KEY abuse, debug-mode RCE, mass assignment, .env exposure |
| `nestjs` | NestJS guards/pipes, module boundaries, multi-transport auth |
| `nextjs` | Next.js App Router, Server Actions, RSC, Edge runtime |
| `rails` | Rails: mass assignment, params parsing, signed-cookie forgery, known CVEs |
| `spring` | Spring Boot: actuators, SpEL injection, Spring4Shell, heapdump secrets |

### `/protocols`

Protocol-specific testing patterns.

| Skill | Protocol |
|-------|----------|
| `graphql` | Introspection, resolver injection, batching, authz bypass |
| `grpc` | Reflection, grpcurl workflows, authz gaps, protobuf field abuse |
| `oauth` | OAuth 2.0/OIDC flows, redirect manipulation, PKCE, token leakage |
| `saml` | Assertion tampering, XML signature wrapping, replay, audience gaps |
| `websocket` | Handshake auth, CSWSH, message injection, race conditions |

### `/technologies`

Specialized techniques for third-party services and platforms.

| Skill | Technology |
|-------|------------|
| `active_directory` | Kerberos roasting, delegation, AD CS (ESC1-17), relay, DACL abuse |
| `auth0` | Rules/actions, scope escalation, MFA bypass, token confusion |
| `ci_cd` | Jenkins/GitLab/GitHub Actions: consoles, pipeline injection, runners |
| `exposed_databases` | Redis/Mongo/Elasticsearch/Postgres/MySQL/Cassandra/CouchDB/Memcached |
| `firebase` | Firestore, Storage rules, Realtime DB, Functions |
| `grafana_prometheus` | Exposed observability -> SSRF, creds, RCE |
| `keycloak` | Realm/client misconfig, redirect abuse, broker SSRF, token handling |
| `payment_gateways` | Webhook signatures, amount/currency abuse, idempotency, refunds |
| `supabase` | Row Level Security, PostgREST, Edge Functions, service keys |
| `wordpress` | wpscan, user enum, xmlrpc, plugin/theme CVEs, REST gaps |

### `/cloud`

Cloud provider and container security testing.

| Skill | Platform |
|-------|----------|
| `aws` | IAM misconfig, S3 exposure, metadata abuse, privesc |
| `azure` | Entra ID, managed identity/IMDS, anonymous storage, Key Vault |
| `docker` | Exposed daemons, registry API, image secrets, escape misconfigs |
| `gcp` | IAM, public buckets, metadata abuse, service account privesc |
| `kubernetes` | RBAC, API exposure, container escapes, network policies |

### `/reconnaissance`

Information gathering and attack-surface mapping.

| Skill | Coverage |
|-------|----------|
| `asset_discovery` | CT logs, TLS SAN pivoting, passive DNS, ASN/IP enumeration |
| `content_discovery` | Directory brute force, backup/.git/.env hunting, JS mining, parameter discovery |
| `technology_fingerprinting` | Headers, cookies, error pages, favicon hashes, WAF/CDN detection |

### `/tooling`

Command-line playbooks for sandbox tools.

| Skill | Tool |
|-------|------|
| `agent_browser` | Headless Chrome CLI (pre-installed) |
| `dirsearch` | HTTP content discovery scanner (pre-installed) |
| `ffuf` | Web fuzzing |
| `httpx` | HTTP probing |
| `interactsh` | OAST out-of-band callbacks (pre-installed) |
| `katana` | Crawling |
| `naabu` | Port scanning |
| `nmap` | Network scanning |
| `nuclei` | Template-based scanning |
| `python` | Sandbox scripting + caido_api automation |
| `semgrep` | Static analysis |
| `sqlmap` | SQL injection automation |
| `subfinder` | Passive subdomain enumeration |

### `/custom`

Community-contributed skills for specialized scenarios.

| Skill | Coverage |
|-------|----------|
| `api_spec_testing` | Spec-driven API pentesting from OpenAPI/Swagger/Postman inventories |
| `dependency_cve_scanning` | SCA/trivy workflow for known dependency CVEs |
| `source_aware_sast` | Semgrep/AST/gitleaks/trufflehog/trivy static triage |

### Internal categories (not user-selectable)

| Category | Purpose |
|----------|---------|
| `/scan_modes` | `quick`, `standard`, `deep` - per-mode methodology injected into every agent |
| `/coordination` | `root_agent` orchestration and `source_aware_whitebox` white-box coordination |

---

## Creating New Skills

### What Should a Skill Contain?

A good skill is a structured knowledge package that typically includes:

- **Advanced techniques** - Non-obvious methods specific to the task and domain
- **Practical examples** - Working payloads, commands, or test cases with variations
- **Validation methods** - How to confirm findings and avoid false positives
- **Context-specific insights** - Environment and version nuances, configuration-dependent behavior, and edge cases
- **YAML frontmatter** - `name` and `description` fields for skill metadata

Skills focus on deep, specialized knowledge to significantly enhance agent capabilities. They are dynamically injected into agent context when needed.

### Conventions

- File name matches `name` in the frontmatter (`ssrf.md` -> `name: ssrf`)
- Descriptions are short, specific, and searchable; agents see them when selecting skills
- Reference other skills by their bare names (e.g. "see `ssrf`") so agents can `load_skill` them
- Tooling sections must reflect what the sandbox ships (see `containers/Dockerfile`) and mark anything that needs installing
- Keep the body ASCII-safe to avoid encoding issues in the rendered prompt

---

## Contributing

Community contributions are welcome - contribute new skills via [pull requests](https://github.com/usestrix/strix/pulls) or [GitHub issues](https://github.com/usestrix/strix/issues) to help expand the collection and improve extensibility for Strix agents.

---

> [!NOTE]
> The collection is actively expanding with specialized techniques and new categories.
