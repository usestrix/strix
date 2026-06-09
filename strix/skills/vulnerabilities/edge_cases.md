---
name: edge_cases
description: Boundary and distributed-systems edge cases — cache races/deception, partial failures, eventual consistency, boundary values, degraded-mode auth bypass
---

# Edge Cases (Caching Races, Partial Failures, Boundary Conditions)

The `race_conditions` skill covers single-process concurrency; this one covers the broader class of bugs that appear at system *boundaries* — caches, service-to-service calls, replication lag, numeric/limit edges, and failure handling. They are high-impact (cross-user exposure, financial loss, authz bypass) and rarely surface in standard testing because they need adversarial timing, failure injection, or boundary-value analysis. CWE-362 and friends.

## Attack Surface

- **Caching layers**: CDN, reverse proxy, framework cache, browser — anywhere a response is stored and replayed.
- **Multi-service transactions**: payment + order, user + profile, anything that writes to 2+ stores.
- **Replicated/eventually-consistent stores**: read replicas, search indexes, distributed counters, caches of permissions.
- **Numeric & limit fields**: quantity, price, balance, pagination cursors/offsets, quotas, time windows.
- **Failure/degradation paths**: dependency-down fallbacks, circuit breakers, retry logic.

## Reconnaissance

- Fingerprint caching: inspect `Cache-Control`, `Age`, `Vary`, `X-Cache`, `CF-Cache-Status`, `ETag`. Note what is cached and the cache key.
- Map every multi-step/transactional flow and where it can be interrupted (close the connection mid-request, kill the second leg).
- Find replication/consistency windows: revoke a permission, then immediately read via a different path (search, list, replica-backed endpoint).
- List numeric/cursor parameters and quota/time-window resets.

## Key Vulnerabilities

### Cache poisoning & deception
- **Unkeyed input**: a header/param that influences the response but is not in the cache key — poison a shared cached entry for all users (test with `param_miner`-style header fuzzing, or vary `X-Forwarded-Host`, `X-Forwarded-Scheme`, etc.).
- **`Vary` omission**: an authenticated, user-specific response cached without `Vary`/`Cache-Control: private` is served to other users — cross-user data exposure. Confirm: authenticate, fetch, then fetch the same URL unauthenticated/as another user and look for the first user's data.
- **Web cache deception**: request `/<sensitive>/nonexistent.css` (or `;.css`, `%0a.css`) — if the origin serves the sensitive page but the CDN caches it as a static asset, it becomes publicly retrievable.
- **Cache-key confusion**: path/normalization differences between proxy and origin (`//`, `/./`, case, `;`) that collide keys.

### Partial-failure exploitation
- Interrupt a multi-store write so one side commits and the other doesn't: payment captured but order not created (refund/duplicate-goods), credits deducted without delivery, or vice versa.
- **Retry amplification**: a non-idempotent endpoint retried by the client/gateway produces duplicate side effects (double charge, double credit). Replay the same request/idempotency key and diff effects.
- Orphaned resources left in a usable but unauthorized state after a half-rollback.

### Eventual consistency windows
- **Stale permission reads**: revoke access, then immediately read via a replica/cache/search endpoint that still returns the resource (TOCTOU across the consistency gap).
- **Index lag**: deleted/revoked items still returned by search/list while the index catches up.
- **Counter drift**: distributed counters (quota, rate limit, balance) that diverge under concurrency — overspend a quota by hammering during the window (overlaps `race_conditions`).

### Boundary conditions
- Integer overflow/underflow and sign flips in quantity/price/balance (`-1`, `0`, `2147483648`, `99999999999`, floats like `1e308`) — negative totals, free purchases, refunds-as-credit.
- **Pagination/cursor authz**: manipulate `offset`/`cursor`/`page` (and decode opaque cursors) to cross a tenant/authorization boundary or read past your own data.
- **Time boundaries**: quota/window resets at midnight/month-end/DST — fire at the boundary to double-spend a window.

### Degraded-mode auth bypass
- Force a dependency to appear down (slow it, block it, send malformed upstream input) and check whether the fallback path skips authentication/authorization, or whether an open circuit breaker routes around a security check.

## Testing Methodology

1. Fingerprint caching and identify shared vs per-user responses; test `Vary`/private omission and deception paths.
2. Hunt unkeyed inputs that influence cached responses.
3. For each transactional flow, inject a partial failure (drop the connection / kill the second leg) and inspect the resulting state.
4. Replay non-idempotent requests and idempotency keys; diff side effects.
5. Probe consistency windows: revoke/delete, then read via every alternate path immediately.
6. Boundary-value sweep numeric and cursor/pagination params (scripted).
7. Induce dependency failure and verify auth/authz still holds on the fallback path.

## Validation

1. Show the concrete impact: another user's data from a cached response, a negative/zero charge that completed, a resource accessed after revocation, or a quota exceeded.
2. Make it reproducible — capture the exact timing/sequence/payload; for races and consistency windows, script the trigger.
3. Use tester-owned accounts and harmless values; never move real funds or touch other tenants' real data.

## False Positives

- `X-Cache: MISS` everywhere / `Cache-Control: private` correctly set — no shared caching.
- A "stale" read that is actually within a documented, bounded, and harmless window.
- Numeric edges that are validated server-side (rejected with a clean error).
- Idempotent endpoints where replay is a safe no-op.
- Client-only cache effects with no server-side consequence.

## Chaining & Impact

Cross-user data exposure, financial manipulation (free/negative purchases, double credits), authorization bypass across tenants, and quota/limit evasion. Cache-poisoning a shared response can escalate a reflected issue into a stored, all-users one.

## Pro Tips

1. The fastest cross-user win is an authenticated response cached without `Vary`/`private` — always check it first.
2. Decode opaque pagination cursors; they frequently embed IDs that cross authorization boundaries.
3. To exploit partial failures, interrupt *between* the two writes — connection reset mid-request is your scalpel.
4. Test permission revocation by reading immediately through a *different* endpoint than the one you'd expect; the lagging path is the bug.
5. Script boundary and timing tests; these bugs live in windows too narrow for manual clicking.
