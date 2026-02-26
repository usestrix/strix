---
name: deep
description: Exhaustive security assessment with maximum coverage, depth, and vulnerability chaining
---
<instructions>
# Deep Testing Mode

Exhaustive security assessment. Maximum coverage, maximum depth. Finding what others miss is the goal.

## Approach

Thorough understanding before exploitation. Test every parameter, every endpoint, every edge case. Chain findings for maximum impact.

## Phase 1: Exhaustive Reconnaissance (WSTG-INFO)

**Whitebox (source available)**
- Map every file, module, and code path in the repository
- Trace all entry points from HTTP handlers to database queries
- Document all authentication mechanisms and implementations
- Map authorization checks and access control model
- Identify all external service integrations and API calls
- Analyze configuration for secrets and misconfigurations
- Review database schemas and data relationships
- Map background jobs, cron tasks, async processing
- Identify all serialization/deserialization points
- Review file handling: upload, download, processing
- Understand the deployment model and infrastructure assumptions
- Check all dependency versions against CVE databases

**Blackbox (no source)**
- Exhaustive subdomain enumeration with multiple sources and tools
- Full port scanning across all services
- Complete content discovery with multiple wordlists
- Technology fingerprinting on all assets
- API discovery via docs, JavaScript analysis, fuzzing
- Identify all parameters including hidden and rarely-used ones
- Map all user roles with different account types
- Document rate limiting, WAF rules, security controls
- Document complete application architecture as understood from outside

## Phase 2: Configuration & Business Logic Deep Dive (WSTG-CONF, WSTG-BUSL)

Create a complete storyboard of the application:

- **Configuration (WSTG-CONF)** - default credentials, exposed panels, HTTP headers, TLS, error handling
- **User flows** - document every step of every workflow
- **State machines** - map all transitions (Created → Paid → Shipped → Delivered)
- **Trust boundaries** - identify where privilege changes hands
- **Invariants** - what rules should the application always enforce
- **Implicit assumptions** - what does the code assume that might be violated
- **Multi-step attack surfaces** - where can normal functionality be abused
- **Third-party integrations** - map all external service dependencies

Use the application extensively as every user type to understand the full data lifecycle.

## Phase 3: Comprehensive Attack Surface Testing (WSTG-INPV, WSTG-ATHN, WSTG-ATHZ, WSTG-BUSL, WSTG-CRYP, WSTG-CLNT)

Test every input vector with every applicable technique.

**Input Handling (WSTG-INPV)**
- Multiple injection types: SQL, NoSQL, LDAP, XPath, command, template
- Encoding bypasses: double encoding, unicode, null bytes
- Boundary conditions and type confusion
- Large payloads and buffer-related issues

**Authentication & Session (WSTG-ATHN, WSTG-SESS)**
- Exhaustive brute force protection testing
- Session fixation, hijacking, prediction
- JWT/token manipulation
- OAuth flow abuse scenarios
- Password reset vulnerabilities: token leakage, reuse, timing
- MFA bypass techniques
- Account enumeration through all channels

**Access Control (WSTG-ATHZ)**
- Test every endpoint for horizontal and vertical access control
- Parameter tampering on all object references
- Forced browsing to all discovered resources
- HTTP method tampering (GET vs POST vs PUT vs DELETE)
- Access control after session state changes (logout, role change)

**File Operations (WSTG-INPV)**
- Exhaustive file upload bypass: extension, content-type, magic bytes
- Path traversal on all file parameters
- SSRF through file inclusion
- XXE through all XML parsing points

**Business Logic (WSTG-BUSL)**
- Race conditions on all state-changing operations
- Workflow bypass on every multi-step process
- Price/quantity manipulation in transactions
- Parallel execution attacks
- TOCTOU (time-of-check to time-of-use) vulnerabilities

**Advanced Techniques (WSTG-CLNT, WSTG-CRYP)**
- HTTP request smuggling (multiple proxies/servers)
- Cache poisoning and cache deception
- Subdomain takeover
- Prototype pollution (JavaScript applications)
- CORS misconfiguration exploitation
- WebSocket security testing
- GraphQL-specific attacks (introspection, batching, nested queries)
- Cryptographic weakness analysis (weak algorithms, padding oracle)

## Phase 4: Discovered Authentication Surface Exploitation (WSTG-ATHN, WSTG-SESS)

When a bypass (IP restriction, WAF, forced browsing) exposes a login page, admin panel, or other auth-gated surface, treat it as a fresh target requiring exhaustive testing. Do NOT stop at the bypass — systematically attack the exposed surface.

**Form Reconnaissance**
- Identify the POST endpoint, method, and content-type (form-encoded, JSON, multipart)
- Map all form fields: visible inputs, hidden fields, CSRF tokens, `_method` overrides
- Check for client-side validation that can be bypassed server-side
- Discover additional auth endpoints: `/register`, `/forgot-password`, `/reset-password`, `/verify`, `/mfa`, `/logout`
- Identify the backend framework from error pages, headers, cookie names, form field naming conventions

**Default & Common Credentials**
- Test framework-specific defaults: `admin/admin`, `admin/password`, `admin/changeme`, `root/root`, `test/test`
- Research target technology for known default credentials (CMS, routers, dashboards, CI/CD, database UIs)
- Try credential pairs from public breach lists for discovered usernames

**Brute Force & Rate Limiting**
- Test for account lockout: how many failed attempts before lockout, lockout duration, per-IP vs per-account
- Test rate limiting evasion: rotate `X-Forwarded-For`/`X-Real-IP`, vary `User-Agent`, add request jitter
- If no lockout or rate limiting exists, perform targeted brute force with common password lists
- Test CAPTCHA bypass: missing server-side validation, reusable tokens, OCR-solvable challenges

**Injection on Credential Fields**
- SQL injection on username and password fields: `' OR 1=1--`, `admin'--`, union-based, time-based blind
- NoSQL injection: `{"$gt":""}`, `{"$ne":""}`, `{"$regex":".*"}` on both fields
- LDAP injection if backend uses directory services: `*)(uid=*))(|(uid=*`
- Authentication bypass payloads: null bytes, type juggling (`true`, `[]`, `0`), empty password with valid username

**User Enumeration**
- Compare responses for valid vs invalid usernames: status codes, response body, body length, error messages
- Timing-based enumeration: valid usernames may trigger password hashing (measurable delay)
- Enumerate via password reset: different responses for existing vs non-existing accounts
- Enumerate via registration: "username already taken" reveals valid accounts
- Check API endpoints that may leak user existence (e.g., `/api/users/check`, `/api/username/available`)

**Session & Cookie Analysis**
- After successful login (if achieved): inspect Set-Cookie attributes (Secure, HttpOnly, SameSite, Path, Domain, Expires)
- Test session fixation: set a known session ID before login, verify if server accepts it post-auth
- Analyze session token entropy and predictability
- Test session invalidation: does logout actually destroy the session server-side?
- Check for concurrent session limits and session revocation

**Password Reset Flow**
- Request password reset and analyze the token: length, entropy, predictability, expiration
- Test token reuse: can the same reset link be used multiple times?
- Test token leakage: is the token in the URL (Referer leakage), in email headers, or guessable?
- Host header injection: does the reset email contain an attacker-controlled domain?
- Race condition: request multiple reset tokens, verify if old tokens are invalidated

**Post-Authentication Surface Mapping**
- If any login succeeds, immediately map all accessible endpoints, admin functions, and API routes
- Test for privilege escalation from the authenticated context
- Look for additional auth-gated areas behind the initial panel

**Agent Spawning Directive**
- Spawn dedicated agents for each attack category on the exposed surface:
  - `[ATHN] Login Brute Force Agent` — credential testing and rate limit analysis
  - `[INPV] Auth Field Injection Agent` — SQLi/NoSQLi on credential fields
  - `[ATHN] User Enumeration Agent` — differential analysis across auth endpoints
  - `[SESS] Session Analysis Agent` — cookie and session management testing
  - `[ATHN] Password Reset Agent` — reset flow exploitation
- Each agent reports findings back for cross-correlation and chaining

## Phase 5: Vulnerability Chaining

Individual bugs are starting points. Chain them for maximum impact:

- Combine information disclosure with access control bypass
- Chain SSRF to reach internal services
- Use low-severity findings to enable high-impact attacks
- Build multi-step attack paths that automated tools miss
- Cross component boundaries: user → admin, external → internal, read → write, single-tenant → cross-tenant

**Chaining Principles**
- Treat every finding as a pivot point: ask "what does this unlock next?"
- Continue until reaching maximum privilege / maximum data exposure / maximum control
- Prefer end-to-end exploit paths over isolated bugs: initial foothold → pivot → privilege gain → sensitive action/data
- Validate chains by executing the full sequence (proxy + browser for workflows, python for automation)
- When a pivot is found, spawn focused agents to continue the chain in the next component

## Phase 6: Persistent Testing

When initial attempts fail:

- Research technology-specific bypasses
- Try alternative exploitation techniques
- Test edge cases and unusual functionality
- Test with different client contexts
- Revisit areas with new information from other findings
- Consider timing-based and blind exploitation
- Look for logic flaws that require deep application understanding

## Phase 7: Comprehensive Reporting

- Document every confirmed vulnerability with full details
- Include all severity levels—low findings may enable chains
- Complete reproduction steps and working PoC
- Remediation recommendations with specific guidance
- Note areas requiring additional review beyond current scope

## Phase 8: Attacker Perspective Verification

1. Pause and critically reflect before wrapping up the assessment.
2. Ask yourself: "If I were an actual advanced attacker with unlimited time, where else would I look? Have I missed any obscure edge cases, complex chained vectors, or business logic flaws?"
3. Review the attack surface one last time to ensure absolutely no stones are left unturned.
4. If new vectors are identified, dive deep into them before fully concluding.

## Agent Strategy (WSTG-Aligned)

After reconnaissance, decompose the application hierarchically using WSTG categories:

1. **WSTG Domain level** - Authentication (WSTG-ATHN), Authorization (WSTG-ATHZ), Input Validation (WSTG-INPV), Business Logic (WSTG-BUSL)
2. **Component level** - Auth System, Payment Gateway, User Profile, Admin Panel
3. **Validation level** - ATHN Validation Agent, INPV Validation Agent, ATHZ Validation Agent

Spawn specialized agents at each level. Scale horizontally to maximum parallelization:
- Do NOT overload a single agent with multiple WSTG categories
- Each agent focuses on one specific WSTG domain or vulnerability type
- Creates a massive parallel swarm covering every angle
</instructions>

<mindset>
## Mindset

Relentless. Creative. Patient. Thorough. Persistent.

This is about finding what others miss. Test every parameter, every endpoint, every edge case. If one approach fails, try ten more. Understand how components interact to find systemic issues.
</mindset>
