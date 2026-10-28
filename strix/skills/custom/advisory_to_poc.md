---
name: advisory-to-poc
description: Vulnerability research workflow for turning advisories, patches, release artifacts, public PoCs, and incident clues into root-cause analysis, safe reproducers, reliable detectors, patch-bypass review, and adjacent-bug hypotheses
---

# Advisory to PoC

Use this skill for authorized product-security and n-day research where the starting point is an advisory, fixed release, patch, public PoC, or incident evidence rather than a known vulnerable endpoint.

The goal is a version-bounded root-cause explanation and reliable, reproducible validation. Do not equate a changed function, crash, scanner hit, or advisory claim with exploitability.

## Evidence Ledger

Keep facts, inferences, and experiments separate:

| Type | Examples |
|---|---|
| Published fact | affected versions, CWE, exposed feature, vendor mitigation |
| Artifact fact | changed function, new validation, removed route, configuration delta |
| Inference | likely attacker-controlled field, suspected auth path, probable sink |
| Experiment | vulnerable response, fixed response, crash, OAST callback, file canary |

Record source URL, artifact hash, product edition/branch, build number, platform, configuration, and date. Re-check assumptions whenever the experimental result conflicts with the advisory narrative.

## Research Workflow

### 1. Scope the Claim

- Extract affected and fixed versions, branches, platforms, roles, protocols, and feature/configuration prerequisites.
- Note whether the vendor describes impact, root cause, mitigation, or only a CWE category.
- Treat bundled CVEs and large release rollups as multiple candidate changes until proven otherwise.
- Identify whether the issue is pre-auth, low-privilege, post-auth, local, or requires a victim/session bridge.

### 2. Acquire Comparable Artifacts

Prefer the closest vulnerable/fixed pair for the same edition and platform:

- source commits, tags, tests, pull requests, and dependency lockfiles
- packages, containers, installers, JAR/WAR/DLL/assemblies, Python bytecode, firmware, or VM images
- web-server/reverse-proxy configuration, service definitions, scripts, and bundled third-party components
- documentation and shipped examples that reveal routes, protocols, defaults, or extension points

Hash originals and work on copies. Preserve installation lineage: default credentials, generated keys, legacy files, and retained configs may matter even if a fresh fixed install does not contain them.

### 3. Reduce Diff Noise

Start with inventories before line-by-line analysis:

- added/removed/renamed files and dependencies
- changed routes, authorization annotations, allowlists/denylists, parser calls, command construction, length checks, and deserialization types
- edge configuration changes that block or rewrite a route without changing application code
- tests added, removed, or updated; these often encode a near-ready reproducer
- sibling call sites of the changed helper or validator

For binaries, combine string/import/symbol diffing with a decompiler and a second diffing method when possible. Large compiler or bundled-library changes create false clusters; anchor on advisory-relevant constants, protocol handlers, response strings, and call graphs.

### 4. Map External Reachability

Work from both directions:

```text
external listener -> edge config -> router -> authentication -> parser -> sink
known changed sink -> callers -> route/protocol -> authentication -> external listener
```

Inventory auxiliary listeners, management agents, sidecars, localhost APIs, custom RPC services, CGI/script dispatch, and framework direct-component routes. Do not assume the main web UI's authentication protects every product service.

Record branch-specific and configuration-specific exposure. A powerful sink behind a disabled feature or unreachable route is not a pre-auth vulnerability.

### 5. Explain the Patch Mechanism

State what security invariant the patch tries to restore:

- bounds, termination, initialization, or length/type consistency
- authentication/authorization before dispatch
- canonicalization before comparison
- allowlisted deserialization or reflection targets
- safe command/process APIs instead of shell construction
- file path confinement and extension/handler restrictions
- route removal or edge blocking
- session-field filtering or trustworthy state reconstruction

Then ask what the patch did not change: alternate callers, sibling parsers, secondary routes, nested gadgets, transitive deserialization, old aliases, different protocol handlers, and edge/application disagreement.

### 6. Build a Reproducer Ladder

Escalate one capability at a time:

1. **Presence** - product/version/protocol fingerprint with low noise
2. **Reachability** - expected route/parser/handler responds
3. **Security differential** - unauthorized behavior differs from a denied control
4. **Primitive** - safe read, controlled callback, canary write, harmless constructor, or deterministic crash in an isolated lab
5. **Impact** - demonstrate the requested authorized impact and preserve its prerequisites

Prefer distinctive non-secret response structure, benign errors, OAST DNS/HTTP callbacks, inert file markers, or no-op commands. For deserialization, use a non-executing network gadget before command execution. For memory corruption, establish the bug and mitigation constraints in a lab; a connection close or crash is not proof of RCE.

### 7. Calibrate on Controls

Run the same reproducer against:

- vulnerable version
- fixed version
- unaffected neighboring version where available
- feature disabled / hardened configuration
- malformed but non-triggering negative input
- authentication present vs absent, if the claim crosses an auth boundary

Repeat enough times to distinguish deterministic behavior from crashes, timing noise, worker restarts, load balancers, and transient network failures.

### 8. Hunt Adjacent and Partial Fixes

After reproducing the primary issue:

- enumerate every call site of the patched function/validator
- cluster nearby handlers using the same parser, session format, command wrapper, or file primitive
- replay the old PoC and structural variants against the first fixed version
- inspect whether the patch blocks the route while leaving the sink reachable elsewhere
- test nested/transitive objects rather than only top-level denylisted types
- check whether one advisory/CVE bundles multiple distinct vulnerable paths

Do not call a variant a bypass until the fixed version demonstrably remains vulnerable.

## Tool Routing

Use the lightest maintained tool that answers the current question. Pin versions in research notes and preserve generated outputs so another analyst can reproduce the diff.

### Artifact and Package Diff: diffoscope

[diffoscope](https://diffoscope.org/) is the default first pass for packages, directories, archives, and binaries. Use it to build a changed-file/config/package manifest before opening a decompiler. For hostile artifacts, keep inputs read-only, disable network, and run the helper-heavy comparison in an isolated environment.

### Firmware and Appliance Artifacts

When the starting point is firmware, a virtual appliance, or a nested image format, load `appliance_firmware`. That skill owns extraction, package/rootfs/runtime correlation, Ghidra/BinDiff routing, overlay/install-state analysis, and device-lifecycle caveats.

### Java/JVM: Vineflower

Use maintained [Vineflower](https://github.com/Vineflower/vineflower) for JAR/class decompilation. Diff archive inventories before decompiled text; compiler, obfuscator, and synthetic-code changes produce noise. Confirm suspicious control flow with bytecode (`javap -c`) rather than treating reconstructed Java as source truth.

### .NET: ILSpy / ilspycmd

Use [ILSpy](https://github.com/icsharpcode/ILSpy) for managed assemblies. Work offline, inspect IL/metadata when the C# reconstruction is ambiguous, and use only GitHub Releases or NuGet.

### Native Code: Ghidra and BinDiff

Use official [Ghidra](https://github.com/NationalSecurityAgency/ghidra) for cross-architecture disassembly/decompilation and [BinDiff](https://github.com/google/bindiff) only after the file/package diff has narrowed the relevant binaries. Keep the toolchain pinned, offline where practical, and non-executing. Decompiler output and similarity scores are triage aids, not proof.

## Source and Binary Techniques

### Source-Available Products

- Search route declarations, filters/interceptors, auth decorators, and direct framework component dispatch.
- Trace attacker-controlled fields through type coercion, validation, shell/process APIs, filesystem operations, reflection, template/XSLT evaluation, and deserialization.
- Compare callers, not just the patched callee. The same helper may be safe in one route and exposed in another.
- Read tests and examples for expected protocol syntax and serialized message shapes.

### Managed Artifacts

- Decompile JAR/WAR and .NET assemblies; diff namespaces/classes/method bodies and embedded configuration.
- Trace public setters, opaque identifiers, type metadata, and framework serialization hooks.
- Inspect bundled libraries and version changes, but prove application reachability before assigning impact.

### Native Binaries and Firmware

- Inventory architecture, mitigations, imports, strings, services, and exposed ports before deep reversing.
- Diff functions around new bounds checks, initialization, string termination, length casts, command builders, and protocol parsers.
- Reconstruct the smallest valid protocol state machine before mutating the suspected field.
- Use debuggers, sanitizers, traces, and process monitors inside an isolated lab when available.
- Separate bug existence from exploitability under ASLR, NX, stack canaries, allocator behavior, architecture, and restart model.

### Public PoC or Incident First

- First decompose and neutralize a public or captured PoC; reproduce its stages in an isolated lab while preserving the headers, ordering, sessions, and negotiation relevant to each stage.
- Decompose the PoC into stages and identify the oracle for each stage.
- Work backward from the final sink to root cause and forward from the entry point to confirm reachability.
- If no patch pair exists, controlled honeypot/instrumentation can reveal in-the-wild request structure; never expose a live vulnerable system beyond an isolated, monitored environment.

Pair `protocol_reverse_engineering` when the external entry point is binary, TLS-wrapped, message-oriented, or stateful.

## Detector Design

A detector must distinguish the vulnerable behavior reliably from fixed and unaffected behavior:

- match a structural response or deterministic state change, not a secret value
- use a unique per-target canary and clean it up when the test writes data
- distinguish patched denial from generic 404/500, WAF blocking, authentication failure, and connection loss
- complete protocol/session prerequisites instead of relying on a single raw request
- rate-limit crash-prone or resource-intensive probes and keep them opt-in
- calibrate templates against vulnerable, fixed, and negative-control targets

When scaling, separate fingerprinting from exploitation. Presence can prioritize assets; it does not confirm the vulnerability.

## Exploitability Triage

Rate each condition explicitly:

- attacker position and credentials
- default vs optional feature/configuration
- internet-facing vs auxiliary/local listener
- data/byte/control precision
- restart, race, victim action, or environment requirements
- available mitigations and architecture
- reliable primitive vs crash-only or unstable behavior
- practical post-primitive chain in the product's default deployment

Down-rate unrealistic chains even when the underlying bug is real. Conversely, revisit “low” primitives such as SSRF, reflection, arbitrary write, cache control, or information disclosure in product context; native admin features may convert them into RCE.

## Validation Deliverable

Include:

1. exact affected/fixed artifacts and hashes
2. authoritative published claims and unresolved ambiguity
3. minimal relevant diff and restored invariant
4. external route/protocol and auth/config prerequisites
5. source-to-sink or packet-to-sink trace
6. safe reproducer plus positive and negative controls
7. vulnerable vs fixed results across repeat runs
8. exploitability constraints and why the demonstrated impact follows
9. adjacent paths reviewed and any partial-fix evidence

## Anti-Patterns

- Trusting the advisory CWE/title as the actual root cause
- Diffing only application code while ignoring edge/proxy/service configuration
- Treating any crash, close, 500, scanner alert, or changed function as exploitation
- Running a weaponized public PoC before isolating its stages and side effects
- Claiming pre-auth impact without tracing the complete auth and routing path
- Assuming one CVE maps to one code path or one patch fixes the whole vulnerability class
- Searching only for the published payload instead of the restored invariant
- Reporting a registry/download/callback signal without separating automated noise from authentic target execution
- Generalizing from one appliance/version/configuration without testing prerequisites

## Summary

Advisory-driven research is evidence-driven reverse engineering. Acquire comparable artifacts, reduce the diff to a security invariant, prove external reachability, climb a safe reproducer ladder, calibrate against fixed and negative controls, and then audit sibling paths and partial fixes. The reusable output is the method and invariant—not the vendor-specific exploit string.
