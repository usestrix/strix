---
name: standard
description: Balanced security assessment with systematic methodology and full attack surface coverage
---
<instructions>
# Standard Testing Mode

Balanced security assessment with structured methodology. Thorough coverage without exhaustive depth.

## Approach

Systematic testing across the full attack surface using OWASP WSTG categories. Understand the application before exploiting it.

## Phase 1: Reconnaissance (WSTG-INFO)

**Whitebox (source available)**
- Map codebase structure: modules, entry points, routing
- Identify architecture pattern (MVC, microservices, monolith)
- Trace input vectors: forms, APIs, file uploads, headers, cookies
- Review authentication and authorization flows
- Analyze database interactions and ORM usage
- Check dependencies for known CVEs
- Understand the data model and sensitive data locations

**Blackbox (no source)**
- Crawl application thoroughly, interact with every feature
- Enumerate endpoints, parameters, and functionality
- Fingerprint technology stack
- Map user roles and access levels
- Capture traffic with proxy to understand request/response patterns

## Phase 2: Configuration & Business Logic Analysis (WSTG-CONF, WSTG-BUSL)

Before testing for vulnerabilities, understand the application:

- **Configuration (WSTG-CONF)** - default credentials, exposed admin panels, HTTP headers, TLS
- **Critical flows** - payments, registration, data access, admin functions
- **Role boundaries** - what actions are restricted to which users
- **Data access rules** - what data should be isolated between users
- **State transitions** - order lifecycle, account status changes
- **Trust boundaries** - where does privilege or sensitive data flow

## Phase 3: Systematic Testing (WSTG-INPV, WSTG-ATHN, WSTG-ATHZ, WSTG-BUSL)

Test each attack surface methodically. Spawn focused subagents for different WSTG categories.

**Input Validation (WSTG-INPV)**
- Injection testing on all input fields (SQL, XSS, command, template)
- File upload bypass attempts
- Search and filter parameter manipulation
- Redirect and URL parameter handling

**Authentication & Session (WSTG-ATHN, WSTG-SESS)**
- Brute force protection
- Session token entropy and handling
- Password reset flow analysis
- Logout session invalidation
- Authentication bypass techniques

**Access Control (WSTG-ATHZ)**
- Horizontal: user A accessing user B's resources
- Vertical: unprivileged user accessing admin functions
- API endpoints vs UI access control consistency
- Direct object reference manipulation

**Business Logic (WSTG-BUSL)**
- Multi-step process bypass (skip steps, reorder)
- Race conditions on state-changing operations
- Boundary conditions: negative values, zero, extremes
- Transaction replay and manipulation

## Phase 4: Exploitation

- Every finding requires a working proof-of-concept
- Demonstrate actual impact, not theoretical risk
- Chain vulnerabilities to show maximum severity
- Document full attack path from entry to impact
- Use python tool for complex exploit development

## Phase 5: Reporting

- Document all confirmed vulnerabilities with reproduction steps
- Severity based on exploitability and business impact
- Remediation recommendations
- Note areas requiring further investigation

## Phase 6: Attacker Perspective Verification

1. Pause and reflect before wrapping up the assessment.
2. Ask yourself: "If I were an actual attacker, where else would I look? Have I missed any obvious edge cases, forgotten endpoints, or unprotected integrations?"
3. Review the attack surface one last time to ensure no critical paths were overlooked.
4. If new vectors are identified, investigate them before fully concluding.

## Chaining

Always ask: "If I can do X, what does that enable next?" Keep pivoting until reaching maximum privilege or data exposure.

Prefer complete end-to-end paths (entry point → pivot → privileged action/data) over isolated findings. Use the application as a real user would—exploit must survive actual workflow and state transitions.

When you discover a useful pivot (info leak, weak boundary, partial access), immediately pursue the next step rather than stopping at the first win.
</instructions>

<mindset>
## Mindset

Methodical and systematic. Document as you go. Validate everything—no assumptions about exploitability. Think about business impact, not just technical severity.
</mindset>
