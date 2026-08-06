---
name: validation-methods
description: Systematic validation doctrine for confirming security findings — canary, heuristic, headless, and out-of-band strategies to eliminate false positives and produce provable evidence
---

# Validation Methods

A vulnerability finding without runtime validation is a hypothesis, not a result. This skill codifies four validation strategies and provides guidance on matching each strategy to the right class of finding. The goal: every reported vulnerability includes evidence that it is exploitable, not just theoretically possible.

## Why This Matters

Autonomous agents excel at generating candidate findings — but without validation, the signal-to-noise ratio degrades rapidly. A scan that reports 50 "possible SQLi" findings with no confirmation wastes more operator time than it saves. The industry benchmark is clear: **source analysis informs, runtime validation proves.**

False positives damage credibility. A single false positive in a penetration test report undermines confidence in every other finding. Validation is not optional — it is what separates a useful report from a noisy one.

## The Four Strategies

### 1. Canary Validation

**Concept:** Plant a unique, identifiable marker and check whether it surfaces where it shouldn't. The canary proves the vulnerability by demonstrating that attacker-controlled data crosses a trust boundary.

**When to Use**
- Injection vulnerabilities (XSS, SSTI, header injection)
- Prototype pollution
- Stored input reflected in unexpected contexts
- Any finding where attacker input should not appear in a specific output

**How It Works**
1. Generate a unique canary value: `strix_canary_<random_hex>` — must be unique per test to avoid false correlation
2. Inject the canary through the suspected input vector
3. Observe whether the canary appears in the response, DOM, logs, headers, or other output channels
4. The canary's presence in an unexpected context confirms the data flow

**Example: XSS Canary**
```
Input:  <img src=x onerror="fetch('//canary.strix_7f3a2b')">
Check:  Does the payload appear unencoded in the response HTML?
Proof:  DOM snapshot showing the <img> tag rendered with onerror intact
```

**Example: Prototype Pollution Canary**
```json
{"__proto__": {"strix_canary_a1b2c3": "polluted"}}
```
Follow-up: create a new object and check if `obj.strix_canary_a1b2c3 === "polluted"`.

**Strength:** Deterministic. If the canary appears, the finding is confirmed.
**Weakness:** Only works for injection/reflection classes where you control input and observe output.

### 2. Heuristic / Differential Validation

**Concept:** Send two requests that differ only in the test payload and compare responses. A meaningful difference (status code, response time, content length, error message) that correlates with the payload confirms the vulnerability.

**When to Use**
- Blind injection (SQL, NoSQL, command injection, LDAP)
- Authentication/authorization bypass (IDOR, privilege escalation)
- Business logic flaws (price manipulation, rate limit bypass)
- Any finding where the effect is not directly visible in a single response

**How It Works**
1. **Baseline request:** normal, expected input
2. **Test request:** same input with a payload variant
3. **Compare:** status code, response body length, timing, headers, error messages
4. **Control:** repeat to confirm the difference is consistent, not random

**Example: Blind SQLi (Boolean)**
```
Baseline: GET /search?id=1 AND 1=1  → 200, 4521 bytes
Test:     GET /search?id=1 AND 1=2  → 200, 2103 bytes
Control:  Repeat 3x — difference is consistent
```

**Example: IDOR (Differential)**
```
Own:     GET /api/users/42/profile  (with user 42's token) → 200
Foreign: GET /api/users/43/profile  (with user 42's token) → 200 (IDOR confirmed)
Control: GET /api/users/43/profile  (no token) → 401 (auth works, authz doesn't)
```

**Example: Time-Based**
```
Baseline: GET /search?id=1                        → 120ms
Test:     GET /search?id=1; WAITFOR DELAY '0:0:3' → 3150ms
Control:  Repeat — consistent 3s delta
```

**Strength:** Works for blind/indirect vulnerabilities where output is not directly observable.
**Weakness:** Requires careful control experiments to rule out network jitter, caching, and load variation. Always repeat.

### 3. Headless / Browser-Confirmed Validation

**Concept:** Use a real browser (headless or instrumented) to confirm client-side impact that cannot be verified through HTTP responses alone. The browser's DOM, JavaScript execution, and rendering engine are the proof environment.

**When to Use**
- DOM-based XSS (payload must execute in browser context)
- Clickjacking (frame rendering behavior)
- CSRF (form submission with victim's session)
- Client-side path traversal (browser path normalization)
- CSP bypass (browser enforces CSP, not the server)
- UI redressing and phishing overlays

**How It Works**
1. Load the target page in a headless browser (Playwright, Puppeteer)
2. Inject the payload via the identified vector (URL parameter, postMessage, etc.)
3. Observe client-side effects: DOM changes, JavaScript execution, network requests, console output
4. Capture evidence: screenshots, DOM snapshots, network logs, console output

**Example: DOM XSS**
```javascript
// Navigate to URL with payload
await page.goto('https://target.com/search?q=<img src=x onerror=window.__xss=1>');
// Check if payload executed
const xssTriggered = await page.evaluate(() => window.__xss === 1);
// Capture DOM evidence
const dom = await page.content();
```

**Example: Clickjacking**
```html
<iframe src="https://target.com/settings" style="opacity:0.01"></iframe>
```
Headless browser confirms: does the iframe render? Are `X-Frame-Options` and `frame-ancestors` CSP absent or misconfigured?

**Strength:** Proves client-side impact that HTTP-level testing cannot — the browser is the ground truth for client-side vulnerabilities.
**Weakness:** Slower than HTTP-only testing. Requires browser infrastructure. Some client-side effects are timing-sensitive.

### 4. Out-of-Band (OOB) / Collaborator Validation

**Concept:** Use an external callback service to confirm that the target made an outbound connection triggered by the payload. Proves code execution, SSRF, or data exfiltration in scenarios where in-band response observation is impossible.

**When to Use**
- Blind SSRF (no in-band response)
- Blind RCE / command injection (no output returned)
- Blind XXE (external entity fetched but content not reflected)
- DNS rebinding confirmation
- Email/webhook trigger verification
- Any asynchronous or blind vulnerability class

**How It Works**
1. Set up a callback listener with a unique identifier (DNS, HTTP, or SMTP)
2. Inject a payload that causes the target to contact the listener
3. Check the listener for incoming requests matching the unique ID
4. The request's existence confirms the vulnerability; its content may reveal additional data

**Example: Blind SSRF**
```
Payload:  POST /webhook {"url": "https://UNIQUE_ID.oob.listener.com/ssrf"}
Check:    Did the OOB listener receive an HTTP request from the target's IP?
Evidence: Listener log showing request with timestamp, source IP, headers
```

**Example: Blind XXE**
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://UNIQUE_ID.oob.listener.com/xxe">]>
<root>&xxe;</root>
```

**Example: Blind Command Injection**
```
Payload:  ; curl https://UNIQUE_ID.oob.listener.com/rce
Check:    HTTP request received at listener
Evidence: Source IP matches target, timing correlates with payload submission
```

**Strength:** Confirms vulnerabilities that produce zero in-band signal. The only way to validate many blind/async classes.
**Weakness:** Requires an externally reachable callback service. Network egress restrictions may block it (which is itself a useful finding to document).

## Strategy Selection Matrix

| Finding Class | Primary Strategy | Fallback Strategy |
|---|---|---|
| Reflected XSS | Canary | Headless |
| Stored XSS | Canary | Headless |
| DOM XSS | Headless | Canary (if reflected in DOM) |
| Blind SQLi | Heuristic (boolean/time) | OOB (DNS exfil) |
| Error-based SQLi | Canary (error message) | Heuristic |
| IDOR | Heuristic (differential) | — |
| SSRF (in-band) | Canary (response content) | OOB |
| SSRF (blind) | OOB | Heuristic (timing) |
| Command injection (blind) | OOB | Heuristic (timing) |
| XXE (blind) | OOB | Heuristic (timing) |
| Prototype pollution | Canary | Headless (for DOM impact) |
| CSRF | Headless | Heuristic (state change) |
| Clickjacking | Headless | — |
| SSTI | Canary (math expression) | OOB |
| Path traversal | Canary (known file content) | Heuristic (response diff) |
| CSPT | Headless | Heuristic (request path diff) |
| Business logic | Heuristic (differential) | — |
| Auth bypass | Heuristic (response comparison) | — |
| Race conditions | Heuristic (outcome observation) | — |

## Validation Quality Checklist

Every validated finding should include:

- [ ] **Strategy used** — Which of the four strategies confirmed this finding
- [ ] **Unique identifier** — Canary value, OOB ID, or differential request pair
- [ ] **Baseline vs test** — What the normal behavior is vs what the payload produced
- [ ] **Repeatability** — Confirmed across multiple attempts (minimum 2, ideally 3)
- [ ] **Evidence artifacts** — HTTP request/response pairs, DOM snapshots, OOB listener logs, timing data
- [ ] **Impact demonstration** — What an attacker achieves, not just that a payload was accepted
- [ ] **False positive exclusion** — Why this is not a false positive (control experiment or negative test)

## Integration with Other Skills

- **Prototype pollution** — Uses canary validation (unique key on Object.prototype)
- **SQL injection** — Uses heuristic (boolean/time differential) and OOB (DNS exfil)
- **XSS** — Uses canary (reflected payload) and headless (DOM execution)
- **SSRF** — Uses OOB (callback confirmation) with canary fallback for in-band
- **IDOR** — Uses heuristic (own vs foreign resource comparison)
- **Business logic** — Uses heuristic (expected vs actual state transitions)
- **Safe-mode crawling** — Validation methods should prefer read-only strategies; escalate to write/execute only with operator approval

## Pro Tips

1. Always use unique identifiers per test — reusing canary values across tests creates false correlations
2. For heuristic validation, run at least 3 repetitions to rule out noise (network jitter, caching, load balancing)
3. Combine strategies when possible: canary + headless for XSS gives both injection proof and execution proof
4. Document negative results too — "OOB callback was NOT received, indicating egress filtering is in place" is valuable information
5. Time-based heuristics should use delays long enough to exceed normal variance (3-5 seconds, not milliseconds)
6. If OOB testing is blocked by network egress rules, note this as a positive security control in the report
7. Validation is what makes a finding actionable — an unvalidated finding should be clearly marked as "candidate" or "unconfirmed"

## Summary

Every finding needs proof. Canary for injection, heuristic for blind/differential, headless for client-side, OOB for async/blind-with-no-output. Match the strategy to the vulnerability class, use unique identifiers, repeat for confidence, and include evidence artifacts. A validated finding is worth ten unvalidated candidates.
