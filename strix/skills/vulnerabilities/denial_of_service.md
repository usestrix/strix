# Application-Level Denial of Service

Find small attacker-controlled inputs that cause disproportionate computation, allocation, blocking, fan-out, retained state, cost, or shared-feature failure. Discovery is recall-first; promotion to a finding is proof-first. This is not a volumetric DDoS playbook.

## Safety and Authorization Gate

- Default to source review, unit tests, benchmarks, and disposable local environments. Never perform packet floods, distributed traffic, reflection/amplification, spoofing, multi-origin rate-limit evasion, or bandwidth saturation.
- General target authorization is not DoS authorization. Shared-service tests require explicit approval for the exact target and test class, with hard request, concurrency, input-size, duration, error-rate, latency, and resource ceilings.
- Identify monitoring, abort conditions, a kill switch, recovery owner, and maintenance window. Stop on unexpected user impact, health-check failure, instability, resource pressure, or lost observability; do not retry automatically.
- Start with one request or isolated invocation, change one dimension at a time, and stop when bounded evidence is sufficient. Downtime is not required.
- Remove poison records, jobs, connections, files, and accounts; verify cleanup and recovery.

Without active-test authorization, keep source-backed candidates visible and prove them only through safe analysis or isolated harnesses.

## Availability Model

Availability requires these invariants:

- accepted inputs have bounded encoded/decoded size, depth, count, cardinality, expansion, and processing time;
- principals and tenants have bounded concurrency, queueing, retained state, fan-out, and cost;
- timeout, cancellation, disconnect, retry, and failure release all resources;
- one malformed stored object cannot break a shared collection or worker;
- expensive work is authorized, deduplicated, backpressured, and isolated.

A security finding requires attacker control, meaningful cost asymmetry or durable failure, insufficient controls, and impact on another user or shared resource.

## PR and White-Box Discovery

Trace the full path:

```text
input -> decode/expand -> loop/match/allocate/wait/fan-out
      -> retained/shared resource -> cleanup/error path
```

- Record attacker-controlled dimensions: bytes, claimed length, count, depth, unique keys, sparse offsets, regex, URL, retries, concurrency, and stored values.
- Record the resource: CPU, memory, disk, descriptors, workers, connections, locks, queues, downstream calls, logs, or provider cost.
- Verify that limits run before decode, allocation, fan-out, or enqueueing and apply per request, principal, tenant, worker, and service.
- Read PR lines with callers, callees, alternate implementations, background consumers, and error/cleanup paths. One guarded caller does not close siblings reaching the same sink.
- Flag new or widened regex, parsers, loops, recursion, batching, fan-out, allocations, retries, queues, concurrency, caches, logging, and stored-field schemas; also flag removed or delayed bounds, deadlines, cancellation, and isolation.
- Prioritize import/export/preview/conversion, search/sort/filter/graphs, unauthenticated cryptographic work, webhooks, notifications, pools, and shared chats, feeds, announcements, dashboards, indexes, and caches.
- When practical, run the same bounded harness on base and head. A regression strengthens evidence, but base behavior alone does not prove current impact.

Useful search terms include `length`, `size`, `limit`, `depth`, `timeout`, `cancel`, `retry`, `queue`, `pool`, `semaphore`, `Promise.all`, task gathering, recursion, nested loops, dynamic regex, decompression, and allocation from claimed sizes.

## Candidate Discipline

Keep candidates separate from findings:

```text
HYPOTHESIS / CHALLENGED INVARIANT:
SOURCE PATH / PREDICTED RESOURCE EFFECT:
SMALLEST BOUNDED EXPERIMENT / MATCHED CONTROL:
EXPECTED / OBSERVED RESULT:
STATUS: unresolved | verified | disproved | blocked | superseded | duplicate
STOPPING OR ENABLING LAYER / NEXT QUESTION:
```

- **Verified** requires the Validation gate. Static suspicion and scanner output are not findings.
- **Disproved** requires evidence that current supported code or the real enforcement boundary blocks the semantic effect. A safe sibling, input, caller, or platform closes only itself.
- **Blocked** means required authorization, environment, or observability is unavailable. Keep the candidate and missing experiment visible; blocked is neither safe nor reportable.
- Failed tests must identify the stopping layer and whether another representation, caller, lifecycle stage, error path, platform, or build mode reaches the resource.
- Validate instances independently, then group those sharing one failed assumption and centralized fix.

Before closing a family, name and run the strongest remaining authorized bounded experiment, or record why it is disproved, blocked, or redundant.

## Vulnerability Classes

### ReDoS and Parser Complexity

- Find nested quantifiers, overlapping alternatives, ambiguous repeated groups, backreferences, user-supplied patterns, repeated matching, ambiguous grammars, recursive parsing, globs, templates, and pathological queries/deserialization.
- Resolve the actual engine and flags. Compare a late-failing/near-match input with a same-length ordinary control, including compilation and repeated-use costs.
- Static warnings are candidates; confirm reachable growth in the deployed engine with a timeout-bounded harness.

### Allocation and Structural Cardinality

- Bound bytes, decoded size, items, unique keys, fragments, sparse gaps, streams, headers, multipart parts, depth, and per-item metadata independently. A byte cap does not bound object count.
- Validate claimed dimensions before allocation; stream transformed data while enforcing expansion ratio and final size.
- Include temporary files, caches, logs, traces, metric labels, and error objects in retained-state accounting.

### Algorithmic, Fan-Out, Queue, and Concurrency Amplification

- Find attacker-selected quadratic loops, scans, sorts, graph walks, wildcards, cache misses, batches, blocking event-loop work, unlimited task gathering, and missing semaphores.
- Count database/HTTP/DNS/model/tool calls, notifications, files, and jobs per input; trace queue admission, capacity, deduplication, priority, retries, dead letters, and backpressure.
- Verify disconnect/cancellation stops downstream work, retries share a budget and idempotency, slow work holds no broad lock, and high-cardinality cache keys cannot create unbounded misses or storage.

### Resource Leaks and Slow Consumption

- Follow descriptors, connections, temporary files, subprocesses, locks, transactions, buffers, and streams through success, error, early return, timeout, cancellation, and disconnect.
- Prefer repeated unit tests with resource counters. Test slow-read/write or partial-body behavior only on a local server with strict connection and duration caps.

### Persistent Poisoned-State DoS

- Trace stored fields into shared chat, feed, announcement, dashboard, search, notification, export, sync, and moderation readers.
- Find write/read validation drift and test web, mobile, API, admin, worker, search, and export paths, including replay after restart, reindex, cache rebuild, or sync.
- One invalid record must be rejected or quarantined, not make the collection unreadable.

Minimal proof: one bounded record breaks a shared feature for an unrelated reader in isolation, and correcting only that record restores it.

## Safe Experimental Workflow

1. State the bounded resource, affected population, and expected ceiling.
2. Prove reachability: entrypoint, transforms, costly sink, guard placement, isolation boundary, and cleanup.
3. Build an isolated harness with hard time, memory, process, and input caps.
4. Use matched controls: equal-size benign/adversarial input or equal-byte low/high-cardinality input.
5. Increase a few small sizes geometrically, one dimension at a time. Record CPU/wall time, memory, allocations, queue depth, downstream calls, errors, and cleanup; one slow sample proves nothing.
6. Reproduce from clean state, confirm isolation/recovery, minimize the case, and stop.

For explicitly authorized load testing, use fixed arrival rate, low ceilings, short duration, thresholds, and abort conditions. Save the script and limits; never improvise an open-ended request loop.

## Tooling

- **Semgrep / CodeQL / regex analyzers:** discover candidates; confirm dataflow and behavior in the actual runtime. Never submit private patterns to third-party analyzers.
- **Hypothesis or project-native property testing:** generate bounded size, depth, shape, Unicode, and failure-position cases with deadlines.
- **Native benchmarks and profilers:** measure the exact engine using JMH, BenchmarkDotNet, Go benchmarks, Criterion, `pytest-benchmark`, or project equivalents.
- **k6:** only for an explicitly authorized monitored lab/staging target; watch duration, failures, dropped iterations, and target resources.

Load the existing `semgrep`, `hypothesis`, or `python` tooling skill when needed. Tool output never replaces evidence.

## Validation

Promote only when all applicable conditions hold:

- current supported code/artifact is tested and controlled input reaches the costly operation through a realistic path;
- the missing/late bound, resource, affected population, and isolation boundary are identified;
- repeated bounded matched controls establish asymmetry or growth, or one deterministic input causes a shared failure in an isolated real environment;
- target-side resource, call-count, persistent-state, or error evidence rules out network/client noise and ordinary variance;
- rate limits, deadlines, admission, cancellation, cleanup, restart behavior, and alternate paths are checked at the final enforcement boundary;
- the minimal saved reproduction works from clean state and cleanup/recovery are independently verified.

For poisoned state, an accepted object must break another user's shared reader or worker, and correcting only that object must restore service.

## False Positives

- Scanner output, a code smell, theoretical complexity, or a single timing sample without reachable controlled flow and matched evidence
- Cost not controlled by the attacker, proportionate to input, or confined to the attacker's bounded isolated job
- An unreachable pattern, proven linear-time engine, or small bound enforced before parse/allocation
- Effective admission, concurrency, queue, cost, timeout, cancellation, cleanup, and isolation on every path
- Client-only freezing with no stored, cross-user, or shared-worker effect
- Atomic rejection/quarantine of invalid records, or graceful shedding that preserves critical and unrelated workloads

Lack of permission for live stress testing is not counterevidence: retain the candidate as `blocked` or `unresolved`, but do not report it as confirmed.

## Remediation

- Enforce encoded/decoded size, count, depth, cardinality, expansion, fan-out, concurrency, and cost before expensive work.
- Replace ambiguous backtracking with linear constructions, explicit parsing, atomic/possessive features where supported, or a non-backtracking engine.
- Stream bounded data and reject unsafe claimed dimensions/expansion before materialization.
- Apply scoped admission, bounded queues, backpressure, concurrency caps, retry budgets, deadlines, cancellation, and idempotency.
- Isolate expensive work with resource-limited workers, bulkheads, and circuit breakers.
- Validate on write, handle defensively on read, quarantine bad records, and guarantee cleanup on every exit path.

## Summary

Application-level DoS is usually a missing bound or isolation boundary, not massive traffic. Preserve candidates, experimentally disprove or verify them, and report only the smallest reproducible input causing demonstrated shared harm.