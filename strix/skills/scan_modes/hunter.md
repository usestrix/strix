---
name: hunter
description: Aggressive security penetration testing with recursive deepening, automated persistence, and comprehensive vulnerability coverage
---

# Hunter Scan Mode

Aggressive penetration testing methodology. Maximum surface coverage, recursive vulnerability deepening, zero-tolerance for false positives. Every finding becomes a weapon for subsequent rounds.

## Target Classification

| Target Type | Signal | Mode |
|---|---|---|
| **Focused** | User specifies scope or vulnerability class | Test ONLY the requested scope or vuln class with full recon depth. |
| **Open** | Production domain, no scope limit | All phases, all vulnerabilities. Maximum depth and persistence. |

## Core Principles

- **Think Before Acting**: Classify the target, identify intent, and deploy appropriate testing power.
- **Autonomous Deepening**: Every finding is a pivot point for subsequent rounds. Finish only when coverage is complete.
- **Zero-Tolerance for False Positives**: Every finding must be validated with concrete evidence (HTTP requests, screenshots, or PoC).
- **Total Surface Coverage**: A scan is invalid if any endpoint, feature, or parameter remains untested.
- **Recursive Evolution**: Use every leak, error, and reflection to pivot into deeper vulnerabilities.
- **Aggressive Persistence**: If automated tools find nothing, that is when the real work begins.

## Phase 1: Authentication & Reconnaissance

**Authentication First**

Authenticate immediately before any testing. Pick the fastest method (Curl first, Browser if needed). Nothing happens before login.

**Surface Mapping**

- Extract ALL endpoints from HTML, JavaScript, API docs, sitemaps, and robots.txt
- Extract all JavaScript URLs and save JS files locally for source code review
- Write the complete attack surface (endpoints + parameters + JS files) to `attack_surface.md`
- Map all user roles with different account types
- Document rate limiting, WAF rules, and security controls

**Subdomain Enumeration**

- Enumerate subdomains with multiple sources and tools
- Collect URLs from multiple aggregators (URLFinder, AlienVault OTX, crt.sh, CertSpotter)
- Use VirusTotal domain reports for historical URL discovery
- Merge and deduplicate all URL sources

**Credential & Secret Discovery**

Filter collected URLs and JavaScript files for authentication artifacts and secrets:

- URLs containing tokens, API keys, passwords, or embedded credentials
- JavaScript files containing hardcoded secrets (SendGrid keys, AWS keys, Stripe keys, GitHub PATs, Slack webhooks, private keys, Sentry DSNs)
- Private file leaks (PDFs, documents, images) from non-public directories
- Filter out common false positives: variable names without values, Base64-encoded binary data, React internal strings, empty/null values

## Phase 2: Passive Vulnerability Discovery

**Email Security Assessment**

- Check SPF, DMARC, and DKIM records for the target domain
- Report missing or weak email security configurations
- DMARC `p=none` with otherwise strong SPF is HIGH severity for organizations where customers trust email communications

**Form Discovery & Analysis**

- Search for HTML forms on all discovered subdomains
- Check for chat widget integrations (Intercom, HubSpot, Zendesk, Crisp, Drift)
- For JavaScript-heavy SPAs, use browser tools for DOM-based form extraction
- Test email-based fields for XSS with polyglot payloads at registration, login, password reset, newsletter signup, contact forms, and account settings

**Widget Misconfiguration Testing**

- Test Intercom boot-time injection for unauthorized access
- Test chat widget configurations for data leakage
- Flag Salesforce sandbox URLs leaking into production chat widgets

**Paywall & Access Control Bypass**

- Test origin IP access to bypass CDN-restricted paywalls
- Test common paywall bypass paths with direct origin IP requests
- Check for accessible private content without authentication

## Phase 3: Active Vulnerability Testing

**Race Condition Testing**

Test authenticated endpoints for race conditions on state-changing operations:

- Coupon/promo code redemption
- Gift card balance transfers
- Payment/checkout flows
- Referral bonus claiming
- Voting/liking systems
- Limited-quantity item purchases

Send multiple simultaneous requests with identical parameters and check if all succeeded when only one should have.

**Social Media & Link Hijacking**

- Extract all social media links from the target site
- Check each profile for 404s, abandoned accounts, or available usernames
- Test Discord invites for expiration

**Email Reservation Lockout**

Test email change flows for lockout vulnerabilities where an attacker can deny a user from creating an account by reserving their email during an unverified email change flow.

## Phase 4: Injection Testing

Apply recursive vulnerability classes across all discovered endpoints and parameters.

**SQL Injection**

- Error-based, boolean-based, time-based, and UNION-based techniques
- Out-of-band DNS exfiltration via `xp_dirtree` or similar
- Test all parameter types: path, query, body, headers, cookies

**Cross-Site Scripting**

- Reflected, stored, and blind XSS payloads
- Out-of-band exfiltration via fetch callbacks
- Store payloads in all fields and check for callbacks from admin panels

**Server-Side Template Injection**

- Test multiple template engines: Jinja2, ERB, Twig, Freemarker
- Escalate from arithmetic evaluation to remote code execution

**SSRF & Local File Inclusion**

- Cloud metadata endpoints (AWS, GCP, Azure)
- Local file access via `file://` and path traversal
- Internal service discovery (Redis, Postgres, internal APIs)
- Out-of-band SSRF via DNS and HTTP callbacks

**Prototype Pollution**

- Server-side prototype pollution via `__proto__` and `constructor.prototype`
- Test for status code manipulation, authentication bypass, and remote code execution

**Blind Deserialization**

- Java, PHP, Python, and .NET deserialization attack vectors
- Out-of-band exfiltration via URLDNS and similar gadgets

## Phase 5: Out-of-Band Exfiltration

Establish and use out-of-band channels for blind vulnerability confirmation:

- **DNS**: Subdomain-based exfiltration for command output
- **HTTP**: Callback-based exfiltration for large data
- **Timing**: Sleep-based detection when outbound is blocked
- **Error-based**: Local data leakage via error messages

## Phase 6: Reporting & Recursive Re-Recon

**Reporting**

For each confirmed finding, create a report with:

- **Title**: [Severity] Finding Name
- **CWE**: CWE identifier, bug type, scope, endpoint, vulnerable part, payload, technical environment
- **Description**: Technical root cause and vulnerability details
- **Steps to Reproduce**: Detailed, numbered steps
- **PoC**: Exact command or script that proves the vulnerability
- **Impact**: Business and security consequence
- **Remediation**: Specific, actionable fix

**Re-Recon After Privilege Elevation**

After every privilege elevation, restart reconnaissance from the new access level. Elevated sessions reveal new attack surfaces that were previously inaccessible.

## Agent Strategy

After initial reconnaissance, decompose the application:

1. **Component level** - Auth System, Payment Gateway, Admin Panel
2. **Feature level** - Login Form, Registration API, Password Reset
3. **Vulnerability level** - SQLi Agent, XSS Agent, Auth Bypass Agent

Spawn specialized agents at each level. Scale horizontally to maximum parallelization:

- Do NOT overload a single agent with multiple vulnerability types
- Each agent focuses on one specific area or vulnerability type
- Creates a parallel swarm covering every angle

**JS Analysis Agent (mandatory, runs first)**

Before spawning vulnerability agents, spawn a single `JS Analysis Agent` with `skills=["js-analysis"]`. Its job is to harvest every JS file (including lazy/dynamic chunks via the browser tool), extract API endpoints, parameters, secrets, dangerous sinks, and auth/session touchpoints into a single `js_analysis.md` artifact. Every downstream specialist agent (IDOR, SSRF, XSS, Auth) reads that artifact as input. Do not start vulnerability hunting until this artifact exists — it is the surface map.

## Rules

- Always confirm with a PoC before reporting
- Test every parameter (path, query, body, headers, cookies)
- Stay in the authenticated session for authenticated flows
- Never report theoretical findings
- Never test targets not explicitly authorized
- Never stop mid-scan without a summary of findings
- Zero hallucination: never write a response you didn't receive
- **Test memory is mandatory**: call `query_tests` before testing any endpoint and `record_test` after every attempt. On `--resume`, this lets agents skip ground already covered.
