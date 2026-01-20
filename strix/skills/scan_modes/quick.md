---
name: quick
description: Time-boxed rapid assessment targeting high-impact vulnerabilities
---

# Quick Testing Mode

Time-boxed assessment focused on high-impact vulnerabilities. Prioritize breadth over depth.

## Approach

Optimize for fast feedback on critical security issues. Skip exhaustive enumeration in favor of targeted testing on high-value attack surfaces.

## Phase 1: Rapid Orientation

**Whitebox (source available)**
- Focus on recent changes: git diffs, new commits, modified files—these are most likely to contain fresh bugs
- Identify security-sensitive patterns in changed code: auth checks, input handling, database queries, file operations
- Trace user input through modified code paths
- Check if security controls were modified or bypassed

**Blackbox (no source)**
- Map authentication and critical user flows
- Identify exposed endpoints and entry points
- Skip deep content discovery—test what's immediately accessible

## Phase 2: High-Impact Targets

Test in priority order:

1. **Authentication bypass** - login flaws, session issues, token weaknesses
2. **Broken access control** - IDOR, privilege escalation, missing authorization
3. **Remote code execution** - command injection, deserialization, SSTI
4. **SQL injection** - authentication endpoints, search, filters
5. **SSRF** - URL parameters, webhooks, integrations
6. **Exposed secrets** - hardcoded credentials, API keys, config files

Skip for quick scans:
- Exhaustive subdomain enumeration
- Full directory bruteforcing
- Low-severity information disclosure
- Theoretical issues without working PoC

## Phase 3: Validation

- Confirm exploitability with minimal proof-of-concept
- Demonstrate real impact, not theoretical risk
- Report findings immediately as discovered

## Chaining

When a strong primitive is found (auth weakness, injection point, internal access), immediately attempt one high-impact pivot to demonstrate maximum severity. Don't stop at a low-context "maybe"—turn it into a concrete exploit sequence that reaches privileged action or sensitive data.

## Operational Guidelines

- Use browser tool for quick manual testing of critical flows
- Use terminal for targeted scans with fast presets (e.g., nuclei with critical/high templates only)
- Use proxy to inspect traffic on key endpoints
- Skip extensive fuzzing—use targeted payloads only
- Create subagents only for parallel high-priority tasks

## Mindset

Think like a time-boxed bug bounty hunter going for quick wins. Prioritize breadth over depth on critical areas. If something looks exploitable, validate quickly and move on. Don't get stuck—if an attack vector isn't yielding results quickly, pivot.
