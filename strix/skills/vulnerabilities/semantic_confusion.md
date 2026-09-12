---
name: semantic-confusion
description: Cross-component semantic confusion testing for parser differentials, normalization mismatches, overloaded fields, lifecycle state drift, internal redirects, protocol translation, and validator-to-sink inconsistencies
---

# Semantic Confusion

Use this skill when two or more components consume the same attacker-influenced value. The central question is not merely whether input is validated, but whether every consumer assigns the same meaning to the value at the moment it makes a security decision.

Typical chains cross a validator, router, proxy, framework, parser, filesystem, interpreter, cache, or browser. A value can be safe in one representation and dangerous after a later decode, normalization, fallback, or field mutation.

## Authorization and Safety Boundary

- Run active differentials only against explicit authorized targets. Preserve destination allowlists and set request, rate, body, response, timeout, and retry ceilings.
- Perform malformed framing, delayed-body, oversized-input, crash, or resource-exhaustion cases only in a restartable isolated lab with health monitoring.
- Use synthetic canaries, reversible actions, non-secret protected resources, or a constant per-test callback identifier. Never place target-derived secrets in an OAST label/body.
- Change one representation axis at a time so the security-relevant disagreement remains attributable to a specific boundary.
- Pair `browser_security` when the final consumer is a browser context, worker, cache, or navigation state machine.
- Do not load this skill for pure ownership drift where every component resolves and interprets the name consistently; use `infrastructure_lifecycle` unless a representation, alias, identity, or resolution-result mismatch is present.

## Core Model

Build a transformation graph before spraying payloads:

```text
raw bytes
  -> transport parser
  -> proxy / middleware representation
  -> authorization or validation decision
  -> rewrite / decode / normalization
  -> internal redirect or dispatch
  -> final sink interpretation
```

For every edge, record:

- exact input representation: bytes, string, URL, path, header list, object, or structured field
- owning component and implementation/version
- transformation performed, including error and fallback behavior
- security decision made before or after the transformation
- whether the original and transformed values remain available simultaneously
- whether a field changes semantic type, such as filename to URL or MIME type to handler

The highest-signal condition is `security_check(value_A)` followed by `sink(transform(value_A))` where the checked and consumed representations are not equivalent.

## High-Value Confusion Classes

### Parser Differentials

- Compare browser, framework, proxy, library, and backend parsing of the exact same bytes.
- Test duplicate and comma-joined fields, first-match vs last-match behavior, invalid-token recovery, comments, quoting, and empty members.
- Include structured formats and metadata: URL, MIME, JSON, multipart, XML, cookies, forwarded headers, and serialized objects.
- Treat leniency as a security feature only when every downstream consumer is equally lenient in the same way.

### Normalization and Canonicalization Drift

- Map percent-decoding count, Unicode conversion, slash/backslash handling, dot-segment removal, case folding, IDNA, numeric IP conversion, and filesystem cleanup.
- Compare string-prefix checks with segment-aware or origin-aware comparisons.
- Test malformed Unicode and replacement behavior; a rejected code point may become an allowed delimiter or wildcard later.
- Test path, query, and fragment separately. Browsers and routers commonly transform each source differently.

### Field and Type Overloading

- Identify shared fields reused for different concepts: path vs URL, content type vs handler, display name vs executable name, route vs filesystem location.
- Trace every writer and reader of the field across the complete lifecycle.
- Look for implicit fallback: when the intended field is empty, another field becomes authoritative.
- Exercise fields after errors, rewrites, subrequests, retries, internal redirects, and protocol upgrades/downgrades.

### Lifecycle and State Drift

- Trigger error paths that should terminate processing and verify that later phases actually stop.
- Look for stale metadata copied into a new request, subrequest, background job, cache entry, or retry.
- Compare direct external access with internal dispatch. Edge controls may inspect the public URL while an internal resolver opens a different path or invokes a different handler.
- Test order-dependent behavior: validation before rewrite, auth before route normalization, or content classification before processing.

### Boundary Translation

- Map HTTP/2 to HTTP/1 translation, proxy to application rewriting, URL to filesystem resolution, upload detector to content consumer, and client router to API request construction.
- In a restartable lab and only when supported by evidence, vary framing, bounded delays/body sizes, content type, pseudo-headers, and method conversion. Check target health after resource-sensitive cases.
- Do not assume a WAF or authorization sidecar sees the full body or final normalized request.

### Namespace and Resolution Fallback

- Identify names resolved across multiple scopes: local path, environment `PATH`, cache, private registry, public registry, plugin directory, template search path, or autoloader.
- Record lookup order and what happens when the intended entry is missing.
- Compare protected package/module names with exposed command, binary, handler, or alias names. For npm, a scoped package can expose an unscoped `bin` name, so the protected package name and invoked executable may differ.
- Treat automatic remote fallback or search-path fallback as an execution boundary.
- Load `npx_confusion` when `npx` or `npm exec` may reinterpret a missing executable as a public package spec.

## Reconnaissance

### Black-Box Mapping

1. Capture a clean baseline with raw request and response bytes.
2. Change one representation axis at a time: encoding depth, delimiter, duplicate, separator, method, protocol, body framing, or Unicode form.
3. Diff status, headers, body digest/length, timing, redirects, cache state, and out-of-band callbacks.
4. Replay through different paths: direct origin vs CDN, HTTP/1.1 vs HTTP/2, public route vs alternate host, synchronous vs background processing.
5. Cluster responses by behavior before escalating. Small differentials reveal component boundaries.

### Source-Aware Mapping

- Find every read and write of shared request/context fields, not just the obvious sink.
- Trace route matching, auth middleware, rewrites, internal redirects, handler selection, and response generation in execution order.
- Inventory decode/parse/normalize calls and note whether return values or errors are ignored.
- Search for compatibility fallbacks, legacy aliases, permissive recovery, default handlers, and search-path iteration.
- Inspect packaging and deployment defaults; distro configuration, enabled modules, plugins, and symlinks often determine reachability.

## Differential Test Matrix

Build a bounded matrix from relevant axes instead of blindly combining everything:

| Axis | Representative variants |
|---|---|
| Encoding | raw, once encoded, twice encoded, mixed case, malformed Unicode |
| Structure | duplicate, comma-joined, empty member, quoted, comment-like suffix |
| Path | `/`, `\\`, `//`, dot segments, absolute, sibling-prefix collision |
| URL | userinfo, numeric IP, alternate IP radix, trailing dot, fragment/query split |
| Transport | HTTP/1.1, HTTP/2, chunked/fixed body, delayed DATA, oversized body |
| Lifecycle | normal, error, retry, internal redirect, cache hit, background worker |
| Consumer | edge, application, library, filesystem, interpreter, browser |

Select axes supported by evidence from the target. Record which component saw which representation.

### Repeatable Harnesses

- For two local parsers, canonicalizers, or validator/consumer functions, load `hypothesis` and express the expected relationship as a property. Bound sizes/examples and keep the minimized disagreement as a regression test.
- For an ordered HTTP flow with cookies, redirects, captured values, and assertions, load `hurl` and encode vulnerable, fixed, and negative-control environments using the same request chain.
- Use raw-byte or protocol-specific harnesses when a high-level HTTP client would normalize the ambiguity away.
- Separate input generation from transport. Generators that are safe against pure local functions become active fuzzers when connected to a live target.

## Chaining Strategy

Treat the first differential as a primitive, then ask what authority the later consumer has:

- auth or ACL bypass -> protected route or file
- path/URL confusion -> source disclosure, SSRF, local socket, or unintended handler
- detector/consumer mismatch -> active upload processing or inline browser execution
- internal redirect state carryover -> handler selection or policy bypass
- search-path or namespace fallback -> attacker-controlled code resolution
- browser/router decode -> client-side path traversal, CSRF-like action, SSRF, or XSS sink

Enumerate existing local gadgets only after the primitive is proven. Prefer generic classes such as interpreters, template engines, debug tools, package scripts, local sockets, and autoload paths over a vendor-specific file list.

## Testing Methodology

1. **Define the invariant** - State what all components are expected to agree on: origin, path, type, handler, identity, length, or package name.
2. **Draw the graph** - List consumers and transformations in real execution order.
3. **Locate early decisions** - Mark validation, auth, WAF, cache, and routing checks.
4. **Locate late meaning changes** - Mark decodes, rewrites, fallback, internal dispatch, and sink parsing.
5. **Build a focused matrix** - Exercise only transformations supported by the stack.
6. **Isolate the disagreement** - Produce paired inputs that differ at one boundary and explain both interpretations.
7. **Prove the primitive safely** - Use a synthetic protected canary, reversible marker, constant callback identifier, or no-op handler whose behavior and side effects are understood.
8. **Escalate by capability** - Track Read -> influence -> write -> dispatch -> execute transitions with evidence and prerequisites for every edge.
9. **Cross-check versions/configurations** - Reproduce on a fixed version or hardened configuration when possible.

## Validation

A valid confusion finding should include:

1. the exact bytes or structured input supplied
2. the representation observed by the security control
3. the different representation observed by the final consumer
4. the transformation or lifecycle event that created the difference
5. paired control and exploit results across repeat runs
6. version, protocol, configuration, and interaction prerequisites
7. a minimal impact proof that does not depend on unrelated undefined behavior

## False Positives

- Different error messages with identical final authorization and sink behavior
- A parser accepts odd syntax but downstream consumers preserve the same safe meaning
- A normalization difference visible only in logs, with no security decision between representations
- WAF bypass where the application itself rejects the request identically
- Version-specific behavior claimed as universal without testing the relevant deployment
- A search-path candidate that is attacker-named but cannot be created, claimed, loaded, or executed

## Pro Tips

1. Begin with relationships and shared state, not endpoint payload lists.
2. Preserve raw traffic; high-level clients often normalize away the exploit before sending it.
3. Error paths are alternate lifecycles. Verify which fields survive and which phases still execute.
4. Compare direct and internal access separately; ingress policy rarely governs framework file IO or handler dispatch.
5. When a prefix allowlist is used, test a sibling sharing the prefix and verify with a segment-aware comparison.
6. Distinguish presence, reachability, and impact. Each needs separate evidence.
7. Generalize a finding by naming the disagreement class, not by copying its final payload.

## Summary

Semantic confusion exists when a security decision and a privileged consumer disagree about the meaning of the same attacker-influenced data. Model the entire transformation lifecycle, isolate one disagreement at a time, and prove both interpretations. The reusable unit is the boundary and its invariant—not a CVE-specific string.
